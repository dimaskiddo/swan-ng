package ike

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"math/big"
)

// ---- DH Group Interface & Implementations ----

// DHGroup represents a Diffie-Hellman group for IKE key exchange.
type DHGroup interface {
	ID() uint16
	GenerateKeypair() (privateKey, publicKey []byte, err error)
	ComputeSharedSecret(privateKey, peerPublic []byte) ([]byte, error)
	PublicKeySize() int
}

// NewDHGroup returns a DHGroup implementation for the given group ID.
func NewDHGroup(id uint16) (DHGroup, error) {
	switch id {
	case DHGroup2:
		return &modpGroup{id: DHGroup2, prime: modpPrime1024, generator: modpGenerator2}, nil

	case DHGroup5:
		return &modpGroup{id: DHGroup5, prime: modpPrime1536, generator: modpGenerator2}, nil

	case DHGroup14:
		return &modpGroup{id: DHGroup14, prime: modpPrime2048, generator: modpGenerator2}, nil

	case DHGroup19:
		return &ecpGroup{id: DHGroup19, curve: ecdh.P256()}, nil

	case DHGroup20:
		return &ecpGroup{id: DHGroup20, curve: ecdh.P384()}, nil

	case DHGroup21:
		return &ecpGroup{id: DHGroup21, curve: ecdh.P521()}, nil

	default:
		return nil, fmt.Errorf("unsupported DH group %d", id)
	}
}

// ---- MODP DH Groups (RFC 3526) ----

type modpGroup struct {
	id        uint16
	prime     *big.Int
	generator *big.Int
}

func (g *modpGroup) ID() uint16 {
	return g.id
}

func (g *modpGroup) PublicKeySize() int {
	return (g.prime.BitLen() + 7) / 8
}

func (g *modpGroup) GenerateKeypair() (privateKey, publicKey []byte, err error) {
	// Private key: random value in [2, p-2].
	pMinus2 := new(big.Int).Sub(g.prime, big.NewInt(2))

	privInt, err := rand.Int(rand.Reader, pMinus2)
	if err != nil {
		return nil, nil, fmt.Errorf("generating DH private key for group %d: %w", g.id, err)
	}

	privInt.Add(privInt, big.NewInt(2)) // Ensure >= 2

	// Public key: g^x mod p.
	pubInt := new(big.Int).Exp(g.generator, privInt, g.prime)

	privBytes := padToLen(privInt.Bytes(), g.PublicKeySize())
	pubBytes := padToLen(pubInt.Bytes(), g.PublicKeySize())

	return privBytes, pubBytes, nil
}

func (g *modpGroup) ComputeSharedSecret(privateKey, peerPublic []byte) ([]byte, error) {
	privInt := new(big.Int).SetBytes(privateKey)
	peerInt := new(big.Int).SetBytes(peerPublic)

	// Validate peer public value: must be in [2, p-2].
	if peerInt.Cmp(big.NewInt(2)) < 0 {
		return nil, fmt.Errorf("DH group %d: peer public key too small", g.id)
	}

	pMinus2 := new(big.Int).Sub(g.prime, big.NewInt(2))
	if peerInt.Cmp(pMinus2) > 0 {
		return nil, fmt.Errorf("DH group %d: peer public key too large", g.id)
	}

	// Shared secret: peer^x mod p.
	shared := new(big.Int).Exp(peerInt, privInt, g.prime)
	return padToLen(shared.Bytes(), g.PublicKeySize()), nil
}

// ---- ECP DH Groups (RFC 5903) ----

type ecpGroup struct {
	id    uint16
	curve ecdh.Curve
}

func (g *ecpGroup) ID() uint16 {
	return g.id
}

func (g *ecpGroup) PublicKeySize() int {
	// Uncompressed point: 1 (0x04) + 2*coordSize.
	switch g.id {
	case DHGroup19:
		return 64 // 2*32 (IKE sends raw x||y without 0x04 prefix)

	case DHGroup20:
		return 96 // 2*48

	case DHGroup21:
		return 132 // 2*66

	default:
		return 0
	}
}

func (g *ecpGroup) GenerateKeypair() (privateKey, publicKey []byte, err error) {
	privKey, err := g.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ECDH key for group %d: %w", g.id, err)
	}

	// IKE uses raw x||y format (no 0x04 prefix).
	ecdhPub := privKey.PublicKey().Bytes()

	// crypto/ecdh returns uncompressed format with 0x04 prefix — strip it.
	if len(ecdhPub) > 0 && ecdhPub[0] == 0x04 {
		ecdhPub = ecdhPub[1:]
	}

	return privKey.Bytes(), ecdhPub, nil
}

func (g *ecpGroup) ComputeSharedSecret(privateKey, peerPublic []byte) ([]byte, error) {
	privKey, err := g.curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing ECDH private key for group %d: %w", g.id, err)
	}

	// Add 0x04 prefix for crypto/ecdh uncompressed format.
	uncompressed := make([]byte, 1+len(peerPublic))
	uncompressed[0] = 0x04

	copy(uncompressed[1:], peerPublic)

	peerKey, err := g.curve.NewPublicKey(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("parsing ECDH peer public key for group %d: %w", g.id, err)
	}

	shared, err := privKey.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH shared secret for group %d: %w", g.id, err)
	}

	return shared, nil
}

// ---- PRF Interface & Implementations ----

// PRFAlgorithm represents a Pseudo-Random Function for IKE key derivation.
type PRFAlgorithm interface {
	ID() uint16
	KeySize() int
	OutputSize() int
	Compute(key, data []byte) []byte
	NewHash(key []byte) hash.Hash
}

// NewPRF returns a PRFAlgorithm implementation for the given ID.
func NewPRF(id uint16) (PRFAlgorithm, error) {
	switch id {
	case PRFHMAC_SHA1:
		return &hmacPRF{id: PRFHMAC_SHA1, hashFunc: sha1.New, keySize: 20, outSize: 20}, nil

	case PRFHMAC_SHA256:
		return &hmacPRF{id: PRFHMAC_SHA256, hashFunc: sha256.New, keySize: 32, outSize: 32}, nil

	case PRFHMAC_SHA384:
		return &hmacPRF{id: PRFHMAC_SHA384, hashFunc: sha512.New384, keySize: 48, outSize: 48}, nil

	case PRFHMAC_SHA512:
		return &hmacPRF{id: PRFHMAC_SHA512, hashFunc: sha512.New, keySize: 64, outSize: 64}, nil

	default:
		return nil, fmt.Errorf("unsupported PRF algorithm %d", id)
	}
}

type hmacPRF struct {
	id       uint16
	hashFunc func() hash.Hash
	keySize  int
	outSize  int
}

func (p *hmacPRF) ID() uint16      { return p.id }
func (p *hmacPRF) KeySize() int    { return p.keySize }
func (p *hmacPRF) OutputSize() int { return p.outSize }

func (p *hmacPRF) Compute(key, data []byte) []byte {
	h := hmac.New(p.hashFunc, key)
	h.Write(data)

	return h.Sum(nil)
}

func (p *hmacPRF) NewHash(key []byte) hash.Hash {
	return hmac.New(p.hashFunc, key)
}

// ---- Integrity Algorithm Interface ----

// IntegrityAlgorithm computes and verifies integrity check values for IKE SA protection.
type IntegrityAlgorithm interface {
	ID() uint16
	KeySize() int
	OutputSize() int // Truncated output size
	Compute(key, data []byte) []byte
	Verify(key, data, expected []byte) bool
}

// NewIntegrity returns an IntegrityAlgorithm implementation.
func NewIntegrity(id uint16) (IntegrityAlgorithm, error) {
	switch id {
	case AuthHMAC_SHA1_96:
		return &hmacIntegrity{id: AuthHMAC_SHA1_96, hashFunc: sha1.New, keySize: 20, truncLen: 12}, nil

	case AuthHMAC_SHA256_128:
		return &hmacIntegrity{id: AuthHMAC_SHA256_128, hashFunc: sha256.New, keySize: 32, truncLen: 16}, nil

	case AuthHMAC_SHA384_192:
		return &hmacIntegrity{id: AuthHMAC_SHA384_192, hashFunc: sha512.New384, keySize: 48, truncLen: 24}, nil

	case AuthHMAC_SHA512_256:
		return &hmacIntegrity{id: AuthHMAC_SHA512_256, hashFunc: sha512.New, keySize: 64, truncLen: 32}, nil

	default:
		return nil, fmt.Errorf("unsupported integrity algorithm %d", id)
	}
}

type hmacIntegrity struct {
	id       uint16
	hashFunc func() hash.Hash
	keySize  int
	truncLen int
}

func (i *hmacIntegrity) ID() uint16 {
	return i.id
}

func (i *hmacIntegrity) KeySize() int {
	return i.keySize
}

func (i *hmacIntegrity) OutputSize() int {
	return i.truncLen
}

func (i *hmacIntegrity) Compute(key, data []byte) []byte {
	h := hmac.New(i.hashFunc, key)

	h.Write(data)
	full := h.Sum(nil)

	return full[:i.truncLen]
}

func (i *hmacIntegrity) Verify(key, data, expected []byte) bool {
	computed := i.Compute(key, data)
	return hmac.Equal(computed, expected)
}

// ---- IKE Encryption (for SK payload) ----

// IKEEncryptor handles encryption/decryption of IKE SK payloads.
type IKEEncryptor interface {
	ID() uint16
	KeySize() int
	IVSize() int
	BlockSize() int
	IsAEAD() bool
	Encrypt(key, iv, plaintext, aad []byte) ([]byte, error)
	Decrypt(key, iv, ciphertext, aad []byte) ([]byte, error)
}

// NewIKEEncryptor returns an IKE encryption algorithm.
func NewIKEEncryptor(id uint16, keyLen uint16) (IKEEncryptor, error) {
	switch id {
	case EncrAES_CBC:
		ks := int(keyLen / 8)
		if ks == 0 {
			ks = 16 // Default AES-128
		}

		return &aesCBCEncryptor{encID: id, keySize: ks}, nil

	case EncrAES_GCM_16:
		ks := int(keyLen / 8)
		if ks == 0 {
			ks = 32 // Default AES-256
		}

		return &aesGCMEncryptor{encID: id, keySize: ks}, nil

	case Encr3DES:
		return &aesCBCEncryptor{encID: id, keySize: 24}, nil

	default:
		return nil, fmt.Errorf("unsupported IKE encryption algorithm %d", id)
	}
}

// ---- AES-CBC Encryptor ----

type aesCBCEncryptor struct {
	encID   uint16
	keySize int
}

func (e *aesCBCEncryptor) ID() uint16 {
	return e.encID
}

func (e *aesCBCEncryptor) KeySize() int {
	return e.keySize
}

func (e *aesCBCEncryptor) IVSize() int {
	return aes.BlockSize
}

func (e *aesCBCEncryptor) BlockSize() int {
	return aes.BlockSize
}

func (e *aesCBCEncryptor) IsAEAD() bool {
	return false
}

func (e *aesCBCEncryptor) Encrypt(key, iv, plaintext, _ []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES-CBC encrypt: %w", err)
	}

	// PKCS#7 padding.
	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padded := make([]byte, len(plaintext)+padLen)

	copy(padded, plaintext)

	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	ciphertext := make([]byte, len(padded))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	return ciphertext, nil
}

func (e *aesCBCEncryptor) Decrypt(key, iv, ciphertext, _ []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES-CBC decrypt: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("AES-CBC ciphertext not block-aligned: %d bytes", len(ciphertext))
	}

	plaintext := make([]byte, len(ciphertext))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Strip PKCS#7 padding.
	if len(plaintext) == 0 {
		return plaintext, nil
	}

	padLen := int(plaintext[len(plaintext)-1])
	if padLen < 1 || padLen > aes.BlockSize || padLen > len(plaintext) {
		return nil, fmt.Errorf("AES-CBC invalid padding: %d", padLen)
	}

	for i := len(plaintext) - padLen; i < len(plaintext); i++ {
		if plaintext[i] != byte(padLen) {
			return nil, fmt.Errorf("AES-CBC padding verification failed")
		}
	}

	return plaintext[:len(plaintext)-padLen], nil
}

// ---- AES-GCM Encryptor (combined mode AEAD) ----

type aesGCMEncryptor struct {
	encID   uint16
	keySize int
}

func (e *aesGCMEncryptor) ID() uint16 {
	return e.encID
}

func (e *aesGCMEncryptor) KeySize() int {
	return e.keySize
}

func (e *aesGCMEncryptor) IVSize() int {
	return 8
}

func (e *aesGCMEncryptor) BlockSize() int {
	return 1
}

func (e *aesGCMEncryptor) IsAEAD() bool {
	return true
}

func (e *aesGCMEncryptor) Encrypt(key, iv, plaintext, aad []byte) ([]byte, error) {
	// IKE AES-GCM key material: first keySize bytes are the key,
	// last 4 bytes are the salt. Total = keySize + 4.
	if len(key) < e.keySize+4 {
		return nil, fmt.Errorf("AES-GCM key too short: need %d, got %d", e.keySize+4, len(key))
	}

	aesKey := key[:e.keySize]
	salt := key[e.keySize : e.keySize+4]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encrypt: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM mode: %w", err)
	}

	// Nonce: salt(4) || IV(8) = 12 bytes.
	nonce := make([]byte, 12)

	copy(nonce[:4], salt)
	copy(nonce[4:], iv)

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nil
}

func (e *aesGCMEncryptor) Decrypt(key, iv, ciphertext, aad []byte) ([]byte, error) {
	if len(key) < e.keySize+4 {
		return nil, fmt.Errorf("AES-GCM key too short: need %d, got %d", e.keySize+4, len(key))
	}

	aesKey := key[:e.keySize]
	salt := key[e.keySize : e.keySize+4]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM mode: %w", err)
	}

	nonce := make([]byte, 12)

	copy(nonce[:4], salt)
	copy(nonce[4:], iv)

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM auth failed: %w", err)
	}

	return plaintext, nil
}

// ---- IKEv1 CBC Encryption (full payload encryption) ----

// EncryptIKEv1Payload encrypts IKEv1 payloads using SKEYID_e with CBC mode.
// The IV for the first message is hash(Ni || Nr). Subsequent IVs are the
// last ciphertext block of the previous message (RFC 2409 §5.3).
func EncryptIKEv1Payload(encryptor IKEEncryptor, key, iv, plaintext []byte) ([]byte, error) {
	return encryptor.Encrypt(key, iv, plaintext, nil)
}

// DecryptIKEv1Payload decrypts IKEv1 payloads.
func DecryptIKEv1Payload(encryptor IKEEncryptor, key, iv, ciphertext []byte) ([]byte, error) {
	return encryptor.Decrypt(key, iv, ciphertext, nil)
}

// ---- Utility ----

// padToLen pads b with leading zeros to reach length n.
func padToLen(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}

	padded := make([]byte, n)
	copy(padded[n-len(b):], b)

	return padded
}

// GenerateNonce generates a random nonce of the specified length.
// RFC 7296 §2.10: nonces must be at least 16 bytes and at most 256 bytes.
func GenerateNonce(length int) ([]byte, error) {
	if length < 16 || length > 256 {
		return nil, fmt.Errorf("nonce length %d out of range [16, 256]", length)
	}

	nonce := make([]byte, length)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	return nonce, nil
}

// GenerateSPI generates a random 8-byte IKE SPI.
// RFC 7296 §2.6: SPIs must be non-zero.
func GenerateIKESPI() ([8]byte, error) {
	var spi [8]byte
	for {
		if _, err := rand.Read(spi[:]); err != nil {
			return spi, fmt.Errorf("generating IKE SPI: %w", err)
		}

		// Ensure non-zero.
		nonZero := false
		for _, b := range spi {
			if b != 0 {
				nonZero = true
				break
			}
		}

		if nonZero {
			return spi, nil
		}
	}
}

// ---- MODP Group Primes (RFC 3526) ----

var modpGenerator2 = big.NewInt(2)

// Group 2: 1024-bit MODP (RFC 2409).
var modpPrime1024, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
		"FFFFFFFFFFFFFFFF", 16)

// Group 5: 1536-bit MODP (RFC 3526 §2).
var modpPrime1536, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)

// Group 14: 2048-bit MODP (RFC 3526 §3).
var modpPrime2048, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
