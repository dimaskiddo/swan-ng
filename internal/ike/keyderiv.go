package ike

import "fmt"

// IKEv2KeyMaterial holds the derived key material for an IKEv2 SA.
// RFC 7296 §2.14.
type IKEv2KeyMaterial struct {
	SK_d  []byte // Key for deriving Child SA keys
	SK_ai []byte // Integrity key for initiator→responder
	SK_ar []byte // Integrity key for responder→initiator
	SK_ei []byte // Encryption key for initiator→responder
	SK_er []byte // Encryption key for responder→initiator
	SK_pi []byte // PRF key for initiator AUTH computation
	SK_pr []byte // PRF key for responder AUTH computation
}

// PRFPlus implements the PRF+ function per RFC 7296 §2.13.
//
//	PRF+(K, S) = T1 | T2 | T3 | ...
//	T1 = PRF(K, S | 0x01)
//	T2 = PRF(K, T1 | S | 0x02)
//	T3 = PRF(K, T2 | S | 0x03)
//	...
//
// Returns exactly 'needed' bytes of keying material.
func PRFPlus(prf PRFAlgorithm, key, seed []byte, needed int) []byte {
	var result []byte
	var prev []byte

	counter := byte(1)

	for len(result) < needed {
		// Input = prev | seed | counter
		input := make([]byte, len(prev)+len(seed)+1)
		copy(input, prev)
		copy(input[len(prev):], seed)
		input[len(input)-1] = counter

		prev = prf.Compute(key, input)
		result = append(result, prev...)
		counter++

		if counter == 0 {
			break // Overflow protection (255 iterations max)
		}
	}

	return result[:needed]
}

// DeriveIKEv2Keys derives the full IKEv2 key material from a DH shared secret.
// RFC 7296 §2.14:
//
//	SKEYSEED = PRF(Ni | Nr, g^ir)
//	{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
//	    = PRF+(SKEYSEED, Ni | Nr | SPIi | SPIr)
func DeriveIKEv2Keys(prf PRFAlgorithm, sharedSecret []byte, ni, nr []byte, spiI, spiR [8]byte, encKeyLen, intKeyLen, prfKeyLen int) (*IKEv2KeyMaterial, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("DH shared secret is empty")
	}

	// SKEYSEED = PRF(Ni | Nr, g^ir)
	nonceConcat := make([]byte, len(ni)+len(nr))

	copy(nonceConcat, ni)
	copy(nonceConcat[len(ni):], nr)

	skeyseed := prf.Compute(nonceConcat, sharedSecret)

	// PRF+ seed = Ni | Nr | SPIi | SPIr
	seed := make([]byte, len(ni)+len(nr)+16)

	copy(seed, ni)
	copy(seed[len(ni):], nr)
	copy(seed[len(ni)+len(nr):], spiI[:])
	copy(seed[len(ni)+len(nr)+8:], spiR[:])

	// Total key material needed.
	totalNeeded := prfKeyLen + intKeyLen*2 + encKeyLen*2 + prfKeyLen*2
	keymat := PRFPlus(prf, skeyseed, seed, totalNeeded)

	km := &IKEv2KeyMaterial{}
	offset := 0

	km.SK_d = cloneSlice(keymat[offset : offset+prfKeyLen])
	offset += prfKeyLen

	km.SK_ai = cloneSlice(keymat[offset : offset+intKeyLen])
	offset += intKeyLen

	km.SK_ar = cloneSlice(keymat[offset : offset+intKeyLen])
	offset += intKeyLen

	km.SK_ei = cloneSlice(keymat[offset : offset+encKeyLen])
	offset += encKeyLen

	km.SK_er = cloneSlice(keymat[offset : offset+encKeyLen])
	offset += encKeyLen

	km.SK_pi = cloneSlice(keymat[offset : offset+prfKeyLen])
	offset += prfKeyLen

	km.SK_pr = cloneSlice(keymat[offset : offset+prfKeyLen])

	return km, nil
}

// DeriveIKEv2RekeyKeys derives new key material for IKE SA rekeying.
// RFC 7296 §2.18:
//
//	SKEYSEED = PRF(SK_d_old, g^ir_new | Ni | Nr)
func DeriveIKEv2RekeyKeys(prf PRFAlgorithm, oldSKd []byte, newSharedSecret []byte, ni, nr []byte, spiI, spiR [8]byte, encKeyLen, intKeyLen, prfKeyLen int) (*IKEv2KeyMaterial, error) {
	// SKEYSEED = PRF(SK_d_old, g^ir_new | Ni | Nr)
	prfInput := make([]byte, len(newSharedSecret)+len(ni)+len(nr))

	copy(prfInput, newSharedSecret)
	copy(prfInput[len(newSharedSecret):], ni)
	copy(prfInput[len(newSharedSecret)+len(ni):], nr)

	skeyseed := prf.Compute(oldSKd, prfInput)

	// Same PRF+ expansion as initial.
	seed := make([]byte, len(ni)+len(nr)+16)

	copy(seed, ni)
	copy(seed[len(ni):], nr)
	copy(seed[len(ni)+len(nr):], spiI[:])
	copy(seed[len(ni)+len(nr)+8:], spiR[:])

	totalNeeded := prfKeyLen + intKeyLen*2 + encKeyLen*2 + prfKeyLen*2
	keymat := PRFPlus(prf, skeyseed, seed, totalNeeded)

	km := &IKEv2KeyMaterial{}
	offset := 0

	km.SK_d = cloneSlice(keymat[offset : offset+prfKeyLen])
	offset += prfKeyLen

	km.SK_ai = cloneSlice(keymat[offset : offset+intKeyLen])
	offset += intKeyLen

	km.SK_ar = cloneSlice(keymat[offset : offset+intKeyLen])
	offset += intKeyLen

	km.SK_ei = cloneSlice(keymat[offset : offset+encKeyLen])
	offset += encKeyLen

	km.SK_er = cloneSlice(keymat[offset : offset+encKeyLen])
	offset += encKeyLen

	km.SK_pi = cloneSlice(keymat[offset : offset+prfKeyLen])
	offset += prfKeyLen

	km.SK_pr = cloneSlice(keymat[offset : offset+prfKeyLen])

	return km, nil
}

// IKEv1KeyMaterial holds the derived key material for an IKEv1 Phase 1 SA.
// RFC 2409 §5.
type IKEv1KeyMaterial struct {
	SKEYID   []byte // Base key
	SKEYID_d []byte // Key for deriving session keys (Phase 2)
	SKEYID_a []byte // Key for ISAKMP SA message authentication
	SKEYID_e []byte // Key for ISAKMP SA message encryption
}

// DeriveIKEv1Keys derives IKEv1 Phase 1 key material using PSK authentication.
// RFC 2409 §5:
//
//	SKEYID   = PRF(pre-shared-key, Ni_b | Nr_b)
//	SKEYID_d = PRF(SKEYID, g^xy | CKY-I | CKY-R | 0)
//	SKEYID_a = PRF(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
//	SKEYID_e = PRF(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)
func DeriveIKEv1Keys(prf PRFAlgorithm, psk []byte, sharedSecret []byte, ni, nr []byte, cookieI, cookieR [8]byte) (*IKEv1KeyMaterial, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("DH shared secret is empty")
	}

	// SKEYID = PRF(PSK, Ni_b | Nr_b)
	nonceConcat := make([]byte, len(ni)+len(nr))

	copy(nonceConcat, ni)
	copy(nonceConcat[len(ni):], nr)

	skeyid := prf.Compute(psk, nonceConcat)

	// Common suffix: g^xy | CKY-I | CKY-R
	suffix := make([]byte, len(sharedSecret)+16)

	copy(suffix, sharedSecret)
	copy(suffix[len(sharedSecret):], cookieI[:])
	copy(suffix[len(sharedSecret)+8:], cookieR[:])

	// SKEYID_d = PRF(SKEYID, g^xy | CKY-I | CKY-R | 0)
	inputD := append(suffix, 0)
	skeyidD := prf.Compute(skeyid, inputD)

	// SKEYID_a = PRF(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
	inputA := make([]byte, len(skeyidD)+len(suffix)+1)

	copy(inputA, skeyidD)
	copy(inputA[len(skeyidD):], suffix)

	inputA[len(inputA)-1] = 1
	skeyidA := prf.Compute(skeyid, inputA)

	// SKEYID_e = PRF(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)
	inputE := make([]byte, len(skeyidA)+len(suffix)+1)

	copy(inputE, skeyidA)
	copy(inputE[len(skeyidA):], suffix)

	inputE[len(inputE)-1] = 2
	skeyidE := prf.Compute(skeyid, inputE)

	return &IKEv1KeyMaterial{
		SKEYID:   skeyid,
		SKEYID_d: skeyidD,
		SKEYID_a: skeyidA,
		SKEYID_e: skeyidE,
	}, nil
}

// DeriveIKEv1QuickModeKeys derives Phase 2 (Quick Mode) keying material.
// RFC 2409 §5.5:
//
//	KEYMAT = PRF(SKEYID_d, protocol | SPI | Ni_b | Nr_b)          [without PFS]
//	KEYMAT = PRF(SKEYID_d, g^ir_new | protocol | SPI | Ni_b | Nr_b) [with PFS]
//
// If more key material is needed than one PRF output:
//
//	KEYMAT = K1 | K2 | K3 | ...
//	K1 = PRF(SKEYID_d, [ g^ir_new | ] protocol | SPI | Ni_b | Nr_b)
//	K2 = PRF(SKEYID_d, K1 | [ g^ir_new | ] protocol | SPI | Ni_b | Nr_b)
func DeriveIKEv1QuickModeKeys(prf PRFAlgorithm, skeyidD []byte, protocol uint8, spi, ni, nr, dhShared []byte, neededBytes int) []byte {
	// Build the base seed.
	var seed []byte

	if len(dhShared) > 0 {
		seed = append(seed, dhShared...)
	}

	seed = append(seed, protocol)
	seed = append(seed, spi...)
	seed = append(seed, ni...)
	seed = append(seed, nr...)

	// Generate enough keying material.
	var result []byte
	var prev []byte

	for len(result) < neededBytes {
		input := append(prev, seed...)
		prev = prf.Compute(skeyidD, input)
		result = append(result, prev...)
	}

	return result[:neededBytes]
}

// DeriveChildSAKeys derives keying material for an IKEv2 Child SA.
// RFC 7296 §2.17:
//
//	KEYMAT = PRF+(SK_d, Ni | Nr)              [without PFS]
//	KEYMAT = PRF+(SK_d, g^ir_new | Ni | Nr)   [with PFS]
func DeriveChildSAKeys(prf PRFAlgorithm, skD []byte, ni, nr, dhShared []byte, neededBytes int) []byte {
	var seed []byte

	if len(dhShared) > 0 {
		seed = append(seed, dhShared...)
	}

	seed = append(seed, ni...)
	seed = append(seed, nr...)

	return PRFPlus(prf, skD, seed, neededBytes)
}

// cloneSlice returns a copy of the byte slice.
func cloneSlice(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)

	return c
}
