package ike

import (
	"testing"
)

func TestSelectV1Proposal(t *testing.T) {
	// Create a sample SA payload representing client's proposals
	saPayload := &SAv1Payload{
		Proposals: []ProposalV1Payload{
			{
				Number:     1,
				ProtocolID: ProtocolIKE,
				Transforms: []TransformV1Payload{
					{
						TransformID: uint8(V1EncrAES_CBC),
						Attributes: []ISAKMPAttribute{
							{Type: V1AttrKeyLength, Value: []byte{1, 0}}, // 256 bit AES
							{Type: V1AttrHashAlg, Value: []byte{0, byte(V1HashSHA256)}},
							{Type: V1AttrAuthMethod, Value: []byte{0, byte(V1AuthPreSharedKey)}},
							{Type: V1AttrGroupDesc, Value: []byte{0, byte(DHGroup14)}},
						},
					},
					{
						TransformID: uint8(V1EncrAES_CBC),
						Attributes: []ISAKMPAttribute{
							{Type: V1AttrKeyLength, Value: []byte{0, 128}}, // 128 bit AES
							{Type: V1AttrHashAlg, Value: []byte{0, byte(V1HashSHA1)}},
							{Type: V1AttrAuthMethod, Value: []byte{0, byte(V1AuthPreSharedKey)}},
							{Type: V1AttrGroupDesc, Value: []byte{0, byte(DHGroup2)}},
						},
					},
				},
			},
		},
	}

	// Supported config 
	supported := []V1Phase1Config{
		{
			EncAlg:     V1EncrAES_CBC,
			HashAlg:    V1HashSHA256,
			AuthMethod: V1AuthPreSharedKey,
			DHGroup:    DHGroup14,
			KeyLength:  256,
		},
	}

	matchedCfg, matchedProp, matchedXf, err := SelectV1Proposal(saPayload, supported)
	if err != nil {
		t.Fatalf("Failed to select proposal: %v", err)
	}

	if matchedProp.Number != 1 {
		t.Errorf("Expected proposal number 1, got %d", matchedProp.Number)
	}

	if matchedXf.TransformID != uint8(V1EncrAES_CBC) {
		t.Errorf("Expected AES CBC transform, got %d", matchedXf.TransformID)
	}

	if matchedCfg.HashAlg != V1HashSHA256 {
		t.Errorf("Expected Hash SHA256, got %d", matchedCfg.HashAlg)
	}

	if matchedCfg.KeyLength != 256 {
		t.Errorf("Expected KeyLength 256, got %d", matchedCfg.KeyLength)
	}
}
