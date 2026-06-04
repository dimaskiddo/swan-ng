package ike

import (
	"net"
	"testing"
)

func TestIKEv1HandleMainMode1(t *testing.T) {
	// Dummy handler
	handler := NewIKEv1Handler(
		func(peerAddr *net.UDPAddr) ([]byte, string, error) {
			return []byte("test_psk"), "test_conn", nil
		},
		nil, // getXAUTHCredentials
		[]byte("local_id"),
		IDIPv4Addr,
	)

	// Build a valid Main Mode 1 message
	saPayload := &SAv1Payload{
		Proposals: []ProposalV1Payload{
			{
				Number:     1,
				ProtocolID: ProtocolIKE,
				Transforms: []TransformV1Payload{
					{
						TransformID: uint8(V1EncrAES_CBC),
						Attributes: []ISAKMPAttribute{
							{Type: V1AttrKeyLength, Value: []byte{1, 0}},
							{Type: V1AttrHashAlg, Value: []byte{0, byte(V1HashSHA256)}},
							{Type: V1AttrAuthMethod, Value: []byte{0, byte(V1AuthPreSharedKey)}},
							{Type: V1AttrGroupDesc, Value: []byte{0, byte(DHGroup14)}},
						},
					},
				},
			},
		},
	}

	msg := &Message{
		Header: Header{
			InitiatorSPI: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
			ExchangeType: ExchangeIdentityProtect,
		},
		Payloads: PayloadChain{{Payload: saPayload}},
	}
	msg.Header.SetIKEv1()

	peerAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 500}

	respMsg, sess, err := handler.HandleMainMode1(msg, peerAddr)
	if err != nil {
		t.Fatalf("HandleMainMode1 failed: %v", err)
	}

	if sess == nil {
		t.Fatal("Expected session to be created")
	}

	if sess.State != StateV1MainSARecv {
		t.Errorf("Expected session state %v, got %v", StateV1MainSARecv, sess.State)
	}

	if respMsg == nil {
		t.Fatal("Expected response message")
	}

	if respMsg.Header.ExchangeType != ExchangeIdentityProtect {
		t.Errorf("Expected response exchange type %v, got %v", ExchangeIdentityProtect, respMsg.Header.ExchangeType)
	}

	if len(respMsg.Payloads) != 1 {
		t.Fatalf("Expected 1 payload in response, got %d", len(respMsg.Payloads))
	}

	_, ok := respMsg.Payloads[0].Payload.(*SAv1Payload)
	if !ok {
		t.Errorf("Expected response payload to be SAv1Payload, got %T", respMsg.Payloads[0].Payload)
	}
}
