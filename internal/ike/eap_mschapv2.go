package ike

import (
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// ---- MS-CHAPv2 OpCode Values (RFC 2759 §4) ----

const (
	MSCHAPv2OpChallenge uint8 = 1
	MSCHAPv2OpResponse  uint8 = 2
	MSCHAPv2OpSuccess   uint8 = 3
	MSCHAPv2OpFailure   uint8 = 4
)

// MSCHAPv2State holds server-side state for an EAP-MSCHAPv2 exchange.
type MSCHAPv2State struct {
	ServerChallenge []byte // 16-byte server challenge
	ServerName      string // Server identity string
	PeerChallenge   []byte // 16-byte peer challenge (from response)
	NTResponse      []byte // 24-byte NT response (from response)
	Username        string // Authenticated username
	AuthResp        string // Authenticator response ("S=..." hex string)
}

// GenerateMSCHAPv2Challenge generates a random 16-byte MS-CHAPv2 challenge.
func GenerateMSCHAPv2Challenge() ([]byte, error) {
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generating MSCHAPv2 challenge: %w", err)
	}

	return challenge, nil
}

// NtPasswordHash computes MD4(UTF-16LE(password)).
// RFC 2759 §8.3.
func NtPasswordHash(password string) []byte {
	// Convert password to UTF-16LE.
	utf16Encoded := utf16.Encode([]rune(password))
	utf16LEBytes := make([]byte, len(utf16Encoded)*2)

	for i, c := range utf16Encoded {
		binary.LittleEndian.PutUint16(utf16LEBytes[i*2:], c)
	}

	h := md4.New()
	h.Write(utf16LEBytes)

	return h.Sum(nil)
}

// HashNtPasswordHash computes MD4(NtPasswordHash).
// RFC 2759 §8.4.
func HashNtPasswordHash(ntHash []byte) []byte {
	h := md4.New()
	h.Write(ntHash)

	return h.Sum(nil)
}

// ChallengeHash computes SHA1(PeerChallenge || AuthenticatorChallenge || UserName)[:8].
// RFC 2759 §8.2.
func ChallengeHash(peerChallenge, authChallenge []byte, username string) []byte {
	h := sha1.New()
	h.Write(peerChallenge)
	h.Write(authChallenge)
	h.Write([]byte(username))

	digest := h.Sum(nil)

	return digest[:8]
}

// desEncryptBlock encrypts a single 8-byte block with a 7-byte DES key.
// The 7-byte key is expanded to 8 bytes with parity bits per RFC 2759 §8.6.
func desEncryptBlock(key7 []byte, data []byte) ([]byte, error) {
	// Expand 7 bytes to 8 bytes with parity bits.
	key8 := make([]byte, 8)
	key8[0] = key7[0] >> 1
	key8[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2)
	key8[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3)
	key8[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4)
	key8[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5)
	key8[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6)
	key8[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7)
	key8[7] = key7[6] & 0x7F

	// Set parity bits (odd parity).
	for i := range key8 {
		key8[i] = (key8[i] << 1) & 0xFE
	}

	cipher, err := des.NewCipher(key8)
	if err != nil {
		return nil, fmt.Errorf("DES cipher: %w", err)
	}

	result := make([]byte, 8)
	cipher.Encrypt(result, data[:8])

	return result, nil
}

// ChallengeResponse computes the 24-byte response from 8-byte challenge and 16-byte NT hash.
// RFC 2759 §8.5: Three 7-byte DES keys derived from padded NT hash, each encrypts the challenge.
func ChallengeResponse(challenge, ntHash []byte) ([]byte, error) {
	// Pad NT hash to 21 bytes.
	paddedHash := make([]byte, 21)
	copy(paddedHash, ntHash)

	result := make([]byte, 24)

	// Encrypt challenge with three 7-byte keys.
	for i := 0; i < 3; i++ {
		block, err := desEncryptBlock(paddedHash[i*7:(i+1)*7], challenge)
		if err != nil {
			return nil, err
		}

		copy(result[i*8:], block)
	}

	return result, nil
}

// GenerateNTResponse computes the 24-byte NT-Response for MS-CHAPv2.
// RFC 2759 §8.1.
func GenerateNTResponse(authChallenge, peerChallenge []byte, username, password string) ([]byte, error) {
	challenge := ChallengeHash(peerChallenge, authChallenge, username)
	ntHash := NtPasswordHash(password)

	return ChallengeResponse(challenge, ntHash)
}

// GenerateAuthenticatorResponse computes the authenticator response string.
// RFC 2759 §8.7. Returns "S=<hex>" format.
func GenerateAuthenticatorResponse(password string, ntResponse, peerChallenge, authChallenge []byte, username string) string {
	ntHash := NtPasswordHash(password)
	ntHashHash := HashNtPasswordHash(ntHash)

	// SHA1(NtHashHash || NT-Response || Magic1)
	magic1 := []byte{
		0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65,
		0x72, 0x76, 0x65, 0x72, 0x20, 0x74, 0x6F, 0x20,
		0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x73,
		0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x63,
		0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74,
	}

	h := sha1.New()
	h.Write(ntHashHash)
	h.Write(ntResponse)
	h.Write(magic1)

	digest := h.Sum(nil)

	// SHA1(Digest || ChallengeHash || Magic2)
	magic2 := []byte{
		0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D,
		0x61, 0x6B, 0x65, 0x20, 0x69, 0x74, 0x20, 0x64,
		0x6F, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x20, 0x74,
		0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E, 0x65, 0x20,
		0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
		0x6E,
	}

	challengeHashVal := ChallengeHash(peerChallenge, authChallenge, username)

	h2 := sha1.New()
	h2.Write(digest)
	h2.Write(challengeHashVal)
	h2.Write(magic2)

	authResp := h2.Sum(nil)

	return "S=" + strings.ToUpper(hex.EncodeToString(authResp))
}

// BuildMSCHAPv2Challenge builds an EAP-MSCHAPv2 Challenge packet.
//
// EAP-MSCHAPv2 Challenge format (inside EAP Type-Data):
//
//	OpCode(1) | MS-CHAPv2-ID(1) | MS-Length(2) | Value-Size(1) | Challenge(16) | Name(var)
func BuildMSCHAPv2Challenge(eapID uint8, mschapID uint8, challenge []byte, serverName string) []byte {
	nameBytes := []byte(serverName)
	// MS-CHAPv2 packet: OpCode(1) + ID(1) + Length(2) + ValueSize(1) + Challenge(16) + Name
	msLen := uint16(5 + len(challenge) + len(nameBytes))

	mschapData := make([]byte, msLen)
	mschapData[0] = MSCHAPv2OpChallenge
	mschapData[1] = mschapID

	binary.BigEndian.PutUint16(mschapData[2:4], msLen)

	mschapData[4] = byte(len(challenge))

	copy(mschapData[5:], challenge)
	copy(mschapData[5+len(challenge):], nameBytes)

	pkt := &EAPPacket{
		Code:       EAPCodeRequest,
		Identifier: eapID,
		Type:       EAPTypeMSCHAPv2,
		Data:       mschapData,
	}

	return pkt.Marshal()
}

// VerifyMSCHAPv2Response verifies an MS-CHAPv2 response packet.
// Returns the authenticator response string and success status.
//
// MS-CHAPv2 Response format (inside EAP Type-Data):
//
//	OpCode(1) | MS-CHAPv2-ID(1) | MS-Length(2) | Value-Size(1) | Response(49) | Name(var)
//
// Response(49) = PeerChallenge(16) | Reserved(8) | NT-Response(24) | Flags(1)
func VerifyMSCHAPv2Response(eapData []byte, authChallenge []byte, username, password string) (string, bool) {
	// eapData is the EAP Type-Data (after EAP Type byte), which is the MS-CHAPv2 packet.
	if len(eapData) < 5 {
		return "", false
	}

	opcode := eapData[0]
	if opcode != MSCHAPv2OpResponse {
		return "", false
	}

	valueSize := eapData[4]
	if valueSize != 49 || len(eapData) < 5+49 {
		return "", false
	}

	responseValue := eapData[5 : 5+49]
	peerChallenge := responseValue[0:16]

	// reserved := responseValue[16:24]

	ntResponse := responseValue[24:48]

	// flags := responseValue[48]

	// Compute expected NT-Response.
	expectedNTResp, err := GenerateNTResponse(authChallenge, peerChallenge, username, password)
	if err != nil {
		return "", false
	}

	if !hashEqual(expectedNTResp, ntResponse) {
		return "", false
	}

	// Compute authenticator response for Success message.
	authResp := GenerateAuthenticatorResponse(password, ntResponse, peerChallenge, authChallenge, username)

	return authResp, true
}

// BuildMSCHAPv2Success builds an EAP-MSCHAPv2 Success Request packet.
//
// MS-CHAPv2 Success format:
//
//	OpCode(1=Success) | MS-CHAPv2-ID(1) | MS-Length(2) | Message(var)
//
// Message = "S=<40 hex chars>" authenticator response.
func BuildMSCHAPv2Success(eapID uint8, mschapID uint8, authResp string) []byte {
	msgBytes := []byte(authResp)
	msLen := uint16(4 + len(msgBytes))

	mschapData := make([]byte, msLen)
	mschapData[0] = MSCHAPv2OpSuccess
	mschapData[1] = mschapID

	binary.BigEndian.PutUint16(mschapData[2:4], msLen)
	copy(mschapData[4:], msgBytes)

	pkt := &EAPPacket{
		Code:       EAPCodeRequest,
		Identifier: eapID,
		Type:       EAPTypeMSCHAPv2,
		Data:       mschapData,
	}

	return pkt.Marshal()
}

// BuildMSCHAPv2Failure builds an EAP-MSCHAPv2 Failure Request packet.
func BuildMSCHAPv2Failure(eapID uint8, mschapID uint8, message string) []byte {
	msgBytes := []byte(message)
	msLen := uint16(4 + len(msgBytes))

	mschapData := make([]byte, msLen)
	mschapData[0] = MSCHAPv2OpFailure
	mschapData[1] = mschapID

	binary.BigEndian.PutUint16(mschapData[2:4], msLen)
	copy(mschapData[4:], msgBytes)

	pkt := &EAPPacket{
		Code:       EAPCodeRequest,
		Identifier: eapID,
		Type:       EAPTypeMSCHAPv2,
		Data:       mschapData,
	}

	return pkt.Marshal()
}

// GetMSCHAPv2MSK derives the Master Session Key from MSCHAPv2 authentication.
// This is used as the EAP MSK for the final IKEv2 AUTH computation.
// RFC 3079 §3.3 + draft-kamath-pppext-eap-mschapv2-02 §8.
//
// The MSK is 64 bytes derived from the NT password hash and NT response:
//
//	MasterKey = SHA1(NtHashHash || NT-Response || "This is the MPPE Master Key")[:16]
//	SendKey = SHA1(MasterKey || SHSpad1 || SHA1(MasterKey || SHSpad2 || "On the client side, this is the send key; on the server side, it is the receive key.") || SHSpad1)
//	RecvKey = SHA1(MasterKey || SHSpad1 || SHA1(MasterKey || SHSpad2 || "On the client side, this is the receive key; on the server side, it is the send key.") || SHSpad1)
//	MSK = RecvKey(32) || SendKey(32)
//
// For simplicity per draft-kamath, MSK = SHA1-based derivation producing 64 bytes.
func GetMSCHAPv2MSK(password string, ntResponse []byte) []byte {
	ntHash := NtPasswordHash(password)
	ntHashHash := HashNtPasswordHash(ntHash)

	// GetMasterKey (RFC 3079 §3.4)
	magic1 := []byte("This is the MPPE Master Key")

	h := sha1.New()
	h.Write(ntHashHash)
	h.Write(ntResponse)
	h.Write(magic1)

	masterKey := h.Sum(nil)[:16]

	// Derive send and receive keys using GetAsymmetricStartKey (RFC 3079 §3.4).
	sendMagic := []byte{
		0x4F, 0x6E, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63,
		0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x73, 0x69,
		0x64, 0x65, 0x2C, 0x20, 0x74, 0x68, 0x69, 0x73,
		0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
		0x73, 0x65, 0x6E, 0x64, 0x20, 0x6B, 0x65, 0x79,
		0x3B, 0x20, 0x6F, 0x6E, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
		0x73, 0x69, 0x64, 0x65, 0x2C, 0x20, 0x69, 0x74,
		0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
		0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
		0x6B, 0x65, 0x79, 0x2E,
	}

	recvMagic := []byte{
		0x4F, 0x6E, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63,
		0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x73, 0x69,
		0x64, 0x65, 0x2C, 0x20, 0x74, 0x68, 0x69, 0x73,
		0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
		0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
		0x6B, 0x65, 0x79, 0x3B, 0x20, 0x6F, 0x6E, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x72, 0x76,
		0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2C,
		0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74,
		0x68, 0x65, 0x20, 0x73, 0x65, 0x6E, 0x64, 0x20,
		0x6B, 0x65, 0x79, 0x2E,
	}

	shsPad1 := make([]byte, 40)
	for i := range shsPad1 {
		shsPad1[i] = 0x00
	}

	shsPad2 := make([]byte, 40)
	for i := range shsPad2 {
		shsPad2[i] = 0xF2
	}

	sendKey := getAsymmetricStartKey(masterKey, sendMagic, shsPad1, shsPad2, 32)
	recvKey := getAsymmetricStartKey(masterKey, recvMagic, shsPad1, shsPad2, 32)

	// MSK = RecvKey || SendKey (server perspective).
	msk := make([]byte, 64)

	copy(msk[:32], recvKey)
	copy(msk[32:], sendKey)

	return msk
}

// getAsymmetricStartKey derives a session key using RFC 3079 §3.4 algorithm.
func getAsymmetricStartKey(masterKey, magic, shsPad1, shsPad2 []byte, keyLen int) []byte {
	h := sha1.New()
	h.Write(masterKey)
	h.Write(shsPad1)
	h.Write(magic)
	h.Write(shsPad2)

	digest := h.Sum(nil)

	if keyLen > len(digest) {
		keyLen = len(digest)
	}

	return cloneSlice(digest[:keyLen])
}
