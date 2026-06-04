package ike

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// SKFPayload represents the Encrypted Fragment payload (RFC 7383 §2.5).
//
//	                     1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Next Payload  |C|  RESERVED   |         Payload Length        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|        Fragment Number        |        Total Fragments        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                     Initialization Vector                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	~                      Encrypted content                        ~
//	+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|               |             Padding (0-255 octets)            |
//	+-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
//	|                                               |  Pad Length   |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	~                    Integrity Checksum Data                     ~
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type SKFPayload struct {
	FragmentNumber uint16
	TotalFragments uint16
	EncryptedData  []byte // IV + ciphertext + ICV (same format as SK body)
}

func (p *SKFPayload) Type() PayloadType { return PayloadSKF }

func (p *SKFPayload) Marshal() ([]byte, error) {
	// Body = FragNum(2) + TotalFrags(2) + EncryptedData
	body := make([]byte, 4+len(p.EncryptedData))

	binary.BigEndian.PutUint16(body[0:2], p.FragmentNumber)
	binary.BigEndian.PutUint16(body[2:4], p.TotalFragments)

	copy(body[4:], p.EncryptedData)

	return marshalWithHeader(p.Type(), body), nil
}

// parseV2SKF parses an SKF payload body (after generic payload header).
func parseV2SKF(body []byte) (*SKFPayload, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("SKF payload too short: %d", len(body))
	}

	return &SKFPayload{
		FragmentNumber: binary.BigEndian.Uint16(body[0:2]),
		TotalFragments: binary.BigEndian.Uint16(body[2:4]),
		EncryptedData:  cloneBytes(body[4:]),
	}, nil
}

// ---- Fragment Reassembly Cache ----

// FragmentCache holds incoming SKF fragments for a specific message ID.
// RFC 7383 §2.5.3: fragments are keyed by message ID.
type FragmentCache struct {
	mu        sync.Mutex
	msgID     uint32
	total     uint16
	fragments map[uint16][]byte // fragment number → decrypted plaintext chunk
}

// NewFragmentCache creates cache for given message ID.
func NewFragmentCache(msgID uint32) *FragmentCache {
	return &FragmentCache{
		msgID:     msgID,
		fragments: make(map[uint16][]byte),
	}
}

// AddFragment inserts a decrypted fragment. Returns true when all fragments received.
// plaintext is the decrypted content of this single fragment (no IV/ICV).
func (fc *FragmentCache) AddFragment(fragNum, totalFrags uint16, plaintext []byte) (bool, error) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if fragNum == 0 || totalFrags == 0 {
		return false, fmt.Errorf("invalid fragment numbers: %d/%d", fragNum, totalFrags)
	}

	if fragNum > totalFrags {
		return false, fmt.Errorf("fragment number %d exceeds total %d", fragNum, totalFrags)
	}

	// RFC 7383 §2.5.3: if total changes mid-stream, discard.
	if fc.total != 0 && fc.total != totalFrags {
		return false, fmt.Errorf("total fragments changed from %d to %d", fc.total, totalFrags)
	}

	fc.total = totalFrags
	fc.fragments[fragNum] = plaintext

	return uint16(len(fc.fragments)) == fc.total, nil
}

// Reassemble concatenates all fragments in order. Call only after AddFragment returns true.
func (fc *FragmentCache) Reassemble() ([]byte, error) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if fc.total == 0 || uint16(len(fc.fragments)) != fc.total {
		return nil, fmt.Errorf("incomplete: have %d/%d fragments", len(fc.fragments), fc.total)
	}

	var totalLen int
	for i := uint16(1); i <= fc.total; i++ {
		chunk, ok := fc.fragments[i]
		if !ok {
			return nil, fmt.Errorf("missing fragment %d", i)
		}

		totalLen += len(chunk)
	}

	result := make([]byte, 0, totalLen)
	for i := uint16(1); i <= fc.total; i++ {
		result = append(result, fc.fragments[i]...)
	}

	return result, nil
}

// ---- Fragment Reassembly Manager ----

// FragmentManager tracks fragment caches per SPI pair + message ID.
type FragmentManager struct {
	mu     sync.Mutex
	caches map[fragmentKey]*FragmentCache
}

type fragmentKey struct {
	spiPair [16]byte
	msgID   uint32
}

// NewFragmentManager creates fragment reassembly manager.
func NewFragmentManager() *FragmentManager {
	return &FragmentManager{
		caches: make(map[fragmentKey]*FragmentCache),
	}
}

// GetOrCreate returns existing cache or creates new one for given SPI pair + message ID.
func (fm *FragmentManager) GetOrCreate(spiPair [16]byte, msgID uint32) *FragmentCache {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	key := fragmentKey{spiPair: spiPair, msgID: msgID}
	if cache, ok := fm.caches[key]; ok {
		return cache
	}

	cache := NewFragmentCache(msgID)
	fm.caches[key] = cache

	return cache
}

// Remove cleans up a completed or stale fragment cache.
func (fm *FragmentManager) Remove(spiPair [16]byte, msgID uint32) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	delete(fm.caches, fragmentKey{spiPair: spiPair, msgID: msgID})
}

// ---- Outbound Fragmentation ----

// DefaultFragmentMTU is the maximum size of each IKE fragment payload.
// RFC 7383 §2.5.1 recommends fitting within typical path MTU.
// 1280 (IPv6 min MTU) - 40 (IPv6) - 8 (UDP) - 28 (IKE header) - 4 (SKF frag header) = 1200 bytes
// For IPv4: 1500 - 20 (IP) - 8 (UDP) - 28 (IKE header) - 4 (SKF frag header) = 1440 bytes
// Use conservative 1200 to handle both.
const DefaultFragmentMTU = 1200

// FragmentSKPayload splits a large plaintext payload chain into multiple SKF payloads.
// Each fragment is independently encrypted.
// RFC 7383 §2.5: fragment number starts at 1, first fragment carries original NextPayload.
//
// Returns slice of complete IKE messages (each with its own header), ready to send.
func FragmentSKPayload(sess *IKEv2Session, exchangeType ExchangeType, isResponse bool, msgID uint32, innerPayloads []Payload, maxFragSize int) ([]*Message, error) {
	if maxFragSize <= 0 {
		maxFragSize = DefaultFragmentMTU
	}

	// Marshal inner payload chain to plaintext.
	plaintext, firstPT, err := MarshalPayloadChain(innerPayloads)
	if err != nil {
		return nil, fmt.Errorf("marshaling payloads for fragmentation: %w", err)
	}

	// Calculate overhead per fragment: IV + padding(1) + ICV.
	ivSize := sess.Encryptor.IVSize()
	var icvSize int
	if sess.Encryptor.IsAEAD() {
		icvSize = 16 // GCM tag
	} else if sess.Integrity != nil {
		icvSize = sess.Integrity.OutputSize()
	}

	// Max plaintext per fragment = maxFragSize - IV - ICV - padLenByte(1)
	maxPlainPerFrag := maxFragSize - ivSize - icvSize - 1
	if maxPlainPerFrag <= 0 {
		return nil, fmt.Errorf("fragment MTU too small: %d", maxFragSize)
	}

	// Split plaintext into chunks.
	var chunks [][]byte
	for offset := 0; offset < len(plaintext); offset += maxPlainPerFrag {
		end := offset + maxPlainPerFrag
		if end > len(plaintext) {
			end = len(plaintext)
		}

		chunks = append(chunks, plaintext[offset:end])
	}

	totalFrags := uint16(len(chunks))
	if len(chunks) > int(^uint16(0)) {
		return nil, fmt.Errorf("too many fragments: %d", len(chunks))
	}

	log.Debug("IKEv2 fragmenting message",
		"total_fragments", totalFrags,
		"plaintext_size", len(plaintext),
		"max_frag_size", maxFragSize,
	)

	// Determine encryption keys (responder direction).
	encKey := sess.Keys.SK_er
	integKey := sess.Keys.SK_ar

	var messages []*Message
	for i, chunk := range chunks {
		fragNum := uint16(i + 1)

		// Generate IV.
		iv := make([]byte, ivSize)
		if _, err := rand.Read(iv); err != nil {
			return nil, fmt.Errorf("generating fragment IV: %w", err)
		}

		// Add padding.
		padLen := 0
		if !sess.Encryptor.IsAEAD() {
			blockSize := sess.Encryptor.BlockSize()
			totalLen := len(chunk) + 1

			if totalLen%blockSize != 0 {
				padLen = blockSize - (totalLen % blockSize)
			}
		}
		padded := make([]byte, len(chunk)+padLen+1)

		copy(padded, chunk)
		padded[len(padded)-1] = byte(padLen)

		// Build temporary IKE header for AAD computation.
		flags := FlagResponse
		if !isResponse {
			flags = FlagInitiator
		}

		tempHdr := Header{
			InitiatorSPI: sess.InitiatorSPI,
			ResponderSPI: sess.ResponderSPI,
			NextPayload:  PayloadSKF,
			MajorVersion: IKEv2Major,
			ExchangeType: exchangeType,
			Flags:        flags,
			MessageID:    msgID,
		}

		hdrBuf := make([]byte, HeaderLen)
		if err := tempHdr.Marshal(hdrBuf); err != nil {
			return nil, fmt.Errorf("marshaling fragment header: %w", err)
		}

		// Encrypt.
		var encryptedBody []byte
		if sess.Encryptor.IsAEAD() {
			ciphertext, err := sess.Encryptor.Encrypt(encKey, iv, padded, hdrBuf)
			if err != nil {
				return nil, fmt.Errorf("AEAD encrypt fragment %d: %w", fragNum, err)
			}
			encryptedBody = make([]byte, len(iv)+len(ciphertext))

			copy(encryptedBody, iv)
			copy(encryptedBody[len(iv):], ciphertext)
		} else {
			ciphertext, err := sess.Encryptor.Encrypt(encKey, iv, padded, nil)
			if err != nil {
				return nil, fmt.Errorf("CBC encrypt fragment %d: %w", fragNum, err)
			}

			macInput := make([]byte, len(hdrBuf)+len(iv)+len(ciphertext))
			copy(macInput, hdrBuf)
			copy(macInput[len(hdrBuf):], iv)
			copy(macInput[len(hdrBuf)+len(iv):], ciphertext)

			icv := sess.Integrity.Compute(integKey, macInput)

			encryptedBody = make([]byte, len(iv)+len(ciphertext)+len(icv))
			copy(encryptedBody, iv)
			copy(encryptedBody[len(iv):], ciphertext)
			copy(encryptedBody[len(iv)+len(ciphertext):], icv)
		}

		// Build SKF payload.
		skf := &SKFPayload{
			FragmentNumber: fragNum,
			TotalFragments: totalFrags,
			EncryptedData:  encryptedBody,
		}

		// RFC 7383 §2.5: first fragment NextPayload = original first inner payload type.
		// Subsequent fragments NextPayload = 0 (None).
		nextPT := PayloadNone
		if fragNum == 1 {
			nextPT = firstPT
		}

		msg := &Message{
			Header: Header{
				InitiatorSPI: sess.InitiatorSPI,
				ResponderSPI: sess.ResponderSPI,
				NextPayload:  nextPT,
				MajorVersion: IKEv2Major,
				ExchangeType: exchangeType,
				Flags:        flags,
				MessageID:    msgID,
			},
			Payloads: PayloadChain{{Header: GenericPayloadHeader{NextPayload: PayloadNone}, Payload: skf}},
		}

		messages = append(messages, msg)
	}

	return messages, nil
}

// ReassembleFragment processes an incoming SKF payload.
// Decrypts the fragment, adds to cache, and returns reassembled plaintext
// when all fragments are received.
// Returns (plaintext, firstPayloadType, complete, error).
func ReassembleFragment(fm *FragmentManager, sess *IKEv2Session, msg *Message, skf *SKFPayload) ([]byte, PayloadType, bool, error) {
	spiPair := sess.SPIPair()

	// Decrypt this fragment's encrypted data.
	// Use initiator keys since we're the responder receiving from initiator.
	decKey := sess.Keys.SK_ei
	integKey := sess.Keys.SK_ai

	// Build AAD from the IKE header of this fragment message.
	hdrBuf := msg.Header.MarshalBinary()

	// Decrypt the encrypted data portion (same format as SK body).
	plainChunk, err := decryptSKBody(sess.Encryptor, sess.Integrity, decKey, integKey, hdrBuf, skf.EncryptedData)
	if err != nil {
		return nil, 0, false, fmt.Errorf("decrypting fragment %d/%d: %w",
			skf.FragmentNumber, skf.TotalFragments, err)
	}

	// Add to cache.
	cache := fm.GetOrCreate(spiPair, msg.Header.MessageID)
	complete, err := cache.AddFragment(skf.FragmentNumber, skf.TotalFragments, plainChunk)
	if err != nil {
		return nil, 0, false, fmt.Errorf("adding fragment %d/%d: %w",
			skf.FragmentNumber, skf.TotalFragments, err)
	}

	if !complete {
		log.Debug("IKEv2 fragment received, waiting for more",
			"fragment", skf.FragmentNumber,
			"total", skf.TotalFragments,
			"msg_id", msg.Header.MessageID,
		)

		return nil, 0, false, nil
	}

	// All fragments received — reassemble.
	reassembled, err := cache.Reassemble()
	if err != nil {
		fm.Remove(spiPair, msg.Header.MessageID)
		return nil, 0, false, fmt.Errorf("reassembly failed: %w", err)
	}

	// Clean up cache.
	fm.Remove(spiPair, msg.Header.MessageID)

	// First fragment's NextPayload tells us the first inner payload type.
	// This was stored in the IKE header's NextPayload of fragment 1.
	firstPT := msg.Header.NextPayload
	if skf.FragmentNumber != 1 {
		// This is the last fragment but we need firstPT from fragment 1.
		// The FragmentCache doesn't track this, so caller must handle it.
		// Per RFC 7383 §2.5: NextPayload in IKE header of non-first fragments is 0.
		// We return PayloadNone and let caller parse from reassembled data.
		firstPT = PayloadNone
	}

	log.Info("IKEv2 fragmented message reassembled",
		"total_fragments", skf.TotalFragments,
		"reassembled_size", len(reassembled),
		"msg_id", msg.Header.MessageID,
	)

	return reassembled, firstPT, true, nil
}

// decryptSKBody decrypts SK/SKF encrypted data (IV || ciphertext [|| ICV]).
func decryptSKBody(enc IKEEncryptor, integ IntegrityAlgorithm, encKey, integKey []byte, aad []byte, skBody []byte) ([]byte, error) {
	ivSize := enc.IVSize()
	if len(skBody) < ivSize+1 {
		return nil, fmt.Errorf("SK body too short: %d bytes", len(skBody))
	}

	iv := skBody[:ivSize]
	encrypted := skBody[ivSize:]

	if enc.IsAEAD() {
		plaintext, err := enc.Decrypt(encKey, iv, encrypted, aad)
		if err != nil {
			return nil, fmt.Errorf("AEAD decrypt: %w", err)
		}

		// Remove padding.
		if len(plaintext) == 0 {
			return nil, fmt.Errorf("empty plaintext after AEAD decrypt")
		}

		padLen := int(plaintext[len(plaintext)-1])
		contentEnd := len(plaintext) - 1 - padLen
		if contentEnd < 0 {
			return nil, fmt.Errorf("invalid pad length %d in %d byte plaintext", padLen, len(plaintext))
		}

		return plaintext[:contentEnd], nil
	}

	// Non-AEAD: encrypted = ciphertext || ICV
	if integ == nil {
		return nil, fmt.Errorf("non-AEAD requires integrity algorithm")
	}

	icvLen := integ.OutputSize()
	if len(encrypted) < icvLen+1 {
		return nil, fmt.Errorf("ciphertext too short for ICV")
	}

	ciphertext := encrypted[:len(encrypted)-icvLen]
	receivedICV := encrypted[len(encrypted)-icvLen:]

	// Verify integrity.
	macInput := make([]byte, len(aad)+ivSize+len(ciphertext))
	copy(macInput, aad)
	copy(macInput[len(aad):], iv)
	copy(macInput[len(aad)+ivSize:], ciphertext)
	expectedICV := integ.Compute(integKey, macInput)

	if len(receivedICV) != len(expectedICV) {
		return nil, fmt.Errorf("ICV length mismatch")
	}

	for i := range receivedICV {
		if receivedICV[i] != expectedICV[i] {
			return nil, fmt.Errorf("ICV verification failed")
		}
	}

	// Decrypt.
	plaintext, err := enc.Decrypt(encKey, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("CBC decrypt: %w", err)
	}

	// Remove padding.
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}

	padLen := int(plaintext[len(plaintext)-1])
	contentEnd := len(plaintext) - 1 - padLen
	if contentEnd < 0 {
		return nil, fmt.Errorf("invalid pad length %d", padLen)
	}

	return plaintext[:contentEnd], nil
}
