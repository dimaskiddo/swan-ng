package ike

import (
	"bytes"
	"net"
	"testing"
)

func TestNATDetection(t *testing.T) {
	spiI := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	spiR := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	addr := net.ParseIP("192.168.1.1")
	port := uint16(500)

	hash1 := ComputeNATDetection(spiI, spiR, addr, port)
	hash2 := ComputeNATDetection(spiI, spiR, addr, port)

	if !bytes.Equal(hash1, hash2) {
		t.Error("NAT detection hashes not deterministic")
	}

	if !CheckNATDetection(hash1, spiI, spiR, addr, port) {
		t.Error("NAT detection check failed for matching params")
	}

	if CheckNATDetection(hash1, spiI, spiR, net.ParseIP("10.0.0.1"), port) {
		t.Error("NAT detection check should fail for different IP")
	}
}

func TestEncryptDecryptSKPayload(t *testing.T) {
	// Setup AES-GCM encryptor.
	enc, err := NewIKEEncryptor(EncrAES_GCM_16, 128)
	if err != nil {
		t.Fatalf("NewIKEEncryptor: %v", err)
	}

	// Key = 16 bytes AES key + 4 bytes salt = 20 bytes.
	key := make([]byte, 20)
	for i := range key {
		key[i] = byte(i + 1)
	}

	header := make([]byte, HeaderLen)

	// Build test payloads.
	payloads := []Payload{
		&NoncePayload{NonceData: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
	}

	firstPT, skBody, err := EncryptSKPayload(enc, nil, key, nil, header, payloads)
	if err != nil {
		t.Fatalf("EncryptSKPayload: %v", err)
	}

	if firstPT != PayloadNonce {
		t.Errorf("Expected first payload type %d, got %d", PayloadNonce, firstPT)
	}

	// Decrypt.
	chain, err := DecryptSKPayload(enc, nil, key, nil, header, skBody, firstPT)
	if err != nil {
		t.Fatalf("DecryptSKPayload: %v", err)
	}

	if len(chain) != 1 {
		t.Fatalf("Expected 1 payload, got %d", len(chain))
	}

	nonce, ok := chain[0].Payload.(*NoncePayload)
	if !ok {
		t.Fatalf("Expected NoncePayload, got %T", chain[0].Payload)
	}
	if !bytes.Equal(nonce.NonceData, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Error("Nonce data mismatch after decrypt")
	}
}

func TestIKEv2HandleSAInit(t *testing.T) {
	handler := NewIKEv2Handler(
		func(peerAddr *net.UDPAddr, peerID []byte) ([]byte, string, error) {
			return []byte("test_psk"), "test_conn", nil
		},
		[]byte("responder.example.com"),
		IDFQDN,
		CookieModeUnlimited,
	)

	// Build SA_INIT request.
	dh, err := NewDHGroup(DHGroup14)
	if err != nil {
		t.Fatalf("NewDHGroup: %v", err)
	}
	_, dhPub, err := dh.GenerateKeypair()
	if err != nil {
		t.Fatalf("DH keygen: %v", err)
	}

	nonce, err := GenerateNonce(32)
	if err != nil {
		t.Fatalf("Nonce gen: %v", err)
	}

	spiI, err := GenerateIKESPI()
	if err != nil {
		t.Fatalf("SPI gen: %v", err)
	}

	// Use proposal that matches default (AES-CBC-256 + SHA256 + DH14).
	saPayload := &SAPayload{
		Proposals: []Proposal{
			{
				Number:     1,
				ProtocolID: ProtocolIKE,
				Transforms: []Transform{
					{Type: TransformTypeENCR, ID: EncrAES_CBC, KeyLength: 256},
					{Type: TransformTypePRF, ID: PRFHMAC_SHA256},
					{Type: TransformTypeINTG, ID: AuthHMAC_SHA256_128},
					{Type: TransformTypeDH, ID: DHGroup14},
					{Type: TransformTypeESN, ID: ESNNone},
				},
			},
		},
	}

	msg := &Message{
		Header: Header{
			InitiatorSPI: spiI,
			ExchangeType: ExchangeIKESAInit,
		},
		Payloads: PayloadChain{
			{Payload: saPayload},
			{Payload: &KEPayload{DHGroup: DHGroup14, Data: dhPub}},
			{Payload: &NoncePayload{NonceData: nonce}},
		},
	}
	msg.Header.SetIKEv2()
	msg.Header.SetRequestFlags(true)

	peerAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 500}

	resp, sess, err := handler.HandleSAInit(msg, peerAddr)
	if err != nil {
		t.Fatalf("HandleSAInit failed: %v", err)
	}

	if sess == nil {
		t.Fatal("Expected session to be created")
	}
	if sess.State != StateV2InitRecv {
		t.Errorf("Expected state InitRecv, got %s", sess.State)
	}
	if resp == nil {
		t.Fatal("Expected response message")
	}
	if resp.Header.ExchangeType != ExchangeIKESAInit {
		t.Errorf("Wrong exchange type: %v", resp.Header.ExchangeType)
	}
	if sess.Keys == nil {
		t.Error("Expected keys to be derived")
	}
	if len(sess.InitReqBytes) == 0 || len(sess.InitRespBytes) == 0 {
		t.Error("Expected init bytes to be saved for AUTH")
	}
}

func TestParseCookieMode(t *testing.T) {
	if ParseCookieMode("busy") != CookieModeBusy {
		t.Error("Expected CookieModeBusy")
	}
	if ParseCookieMode("unlimited") != CookieModeUnlimited {
		t.Error("Expected CookieModeUnlimited")
	}
	if ParseCookieMode("auto") != CookieModeAuto {
		t.Error("Expected CookieModeAuto")
	}
	if ParseCookieMode("") != CookieModeAuto {
		t.Error("Expected CookieModeAuto for empty string")
	}
}
