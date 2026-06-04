package ike

import (
	"fmt"
	"strings"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// ---- IKEv2 Proposal Defaults & Negotiation ----

// DefaultIKEProposals returns sensible default IKE SA proposals.
// Ordered by preference: strongest first.
func DefaultIKEProposals() *SAPayload {
	return &SAPayload{
		Proposals: []Proposal{
			{
				Number:     1,
				ProtocolID: ProtocolIKE,
				Transforms: []Transform{
					{Type: TransformTypeENCR, ID: EncrAES_GCM_16, KeyLength: 256},
					{Type: TransformTypePRF, ID: PRFHMAC_SHA256},
					{Type: TransformTypeDH, ID: DHGroup20},
					{Type: TransformTypeESN, ID: ESNNone},
				},
			},
			{
				Number:     2,
				ProtocolID: ProtocolIKE,
				Transforms: []Transform{
					{Type: TransformTypeENCR, ID: EncrAES_GCM_16, KeyLength: 128},
					{Type: TransformTypePRF, ID: PRFHMAC_SHA256},
					{Type: TransformTypeDH, ID: DHGroup14},
					{Type: TransformTypeESN, ID: ESNNone},
				},
			},
			{
				Number:     3,
				ProtocolID: ProtocolIKE,
				Transforms: []Transform{
					{Type: TransformTypeENCR, ID: EncrAES_CBC, KeyLength: 256},
					{Type: TransformTypePRF, ID: PRFHMAC_SHA256},
					{Type: TransformTypeINTG, ID: AuthHMAC_SHA256_128},
					{Type: TransformTypeDH, ID: DHGroup14},
					{Type: TransformTypeESN, ID: ESNNone},
				},
			},
			{
				Number:     4,
				ProtocolID: ProtocolIKE,
				Transforms: []Transform{
					{Type: TransformTypeENCR, ID: EncrAES_CBC, KeyLength: 128},
					{Type: TransformTypePRF, ID: PRFHMAC_SHA1},
					{Type: TransformTypeINTG, ID: AuthHMAC_SHA1_96},
					{Type: TransformTypeDH, ID: DHGroup14},
					{Type: TransformTypeESN, ID: ESNNone},
				},
			},
		},
	}
}

// DefaultESPProposals returns default Child SA (ESP) proposals.
func DefaultESPProposals() *SAPayload {
	return &SAPayload{
		Proposals: []Proposal{
			{
				Number:     1,
				ProtocolID: ProtocolESP,
				Transforms: []Transform{
					{Type: TransformTypeENCR, ID: EncrAES_GCM_16, KeyLength: 256},
					{Type: TransformTypeESN, ID: ESNNone},
				},
			},
			{
				Number:     2,
				ProtocolID: ProtocolESP,
				Transforms: []Transform{
					{Type: TransformTypeENCR, ID: EncrAES_GCM_16, KeyLength: 128},
					{Type: TransformTypeESN, ID: ESNNone},
				},
			},
			{
				Number:     3,
				ProtocolID: ProtocolESP,
				Transforms: []Transform{
					{Type: TransformTypeENCR, ID: EncrAES_CBC, KeyLength: 256},
					{Type: TransformTypeINTG, ID: AuthHMAC_SHA256_128},
					{Type: TransformTypeESN, ID: ESNNone},
				},
			},
			{
				Number:     4,
				ProtocolID: ProtocolESP,
				Transforms: []Transform{
					{Type: TransformTypeENCR, ID: EncrAES_CBC, KeyLength: 128},
					{Type: TransformTypeINTG, ID: AuthHMAC_SHA1_96},
					{Type: TransformTypeESN, ID: ESNNone},
				},
			},
		},
	}
}

// SelectedProposal holds the result of proposal negotiation.
type SelectedProposal struct {
	ProposalNum uint8
	ProtocolID  ProtocolID
	SPI         []byte
	EncrID      uint16
	EncrKeyLen  uint16
	PRFID       uint16 // 0 for ESP proposals
	IntegID     uint16 // 0 for AEAD
	DHID        uint16 // 0 if no DH
	ESN         uint16
}

// SelectProposal selects the best matching proposal from peer's offer
// against our local proposals. Returns the first match (responder chooses).
// RFC 7296 §2.7: responder picks one complete proposal from the initiator's list.
func SelectProposal(ours, theirs *SAPayload) (*SelectedProposal, *Proposal, error) {
	if theirs == nil || len(theirs.Proposals) == 0 {
		return nil, nil, fmt.Errorf("no proposals offered by peer")
	}

	if ours == nil || len(ours.Proposals) == 0 {
		return nil, nil, fmt.Errorf("no local proposals configured")
	}

	// For each of OUR proposals (priority order), check if peer offers a match.
	for _, ourProp := range ours.Proposals {
		for _, theirProp := range theirs.Proposals {
			if ourProp.ProtocolID != theirProp.ProtocolID {
				continue
			}

			if proposalMatch(&ourProp, &theirProp) {
				selected := extractSelected(&ourProp, &theirProp)
				selectedProp := buildSelectedProposal(&theirProp, &ourProp)

				log.Debug("proposal selected",
					"proposal_num", theirProp.Number,
					"protocol", theirProp.ProtocolID,
					"encr", selected.EncrID,
					"key_len", selected.EncrKeyLen,
				)

				return selected, selectedProp, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("no proposal chosen: no matching proposal found")
}

// proposalMatch checks if two proposals have compatible transforms.
func proposalMatch(ours, theirs *Proposal) bool {
	// Group transforms by type.
	ourByType := groupTransforms(ours.Transforms)
	theirByType := groupTransforms(theirs.Transforms)

	// Check that for each required transform type in our proposal,
	// the peer offers at least one matching transform.
	for xfType, ourXfs := range ourByType {
		theirXfs, ok := theirByType[xfType]
		if !ok {
			// Peer doesn't offer this transform type.
			// INTEG is optional for AEAD ciphers.
			if xfType == TransformTypeINTG {
				continue
			}

			return false
		}

		if !hasMatchingTransform(ourXfs, theirXfs) {
			return false
		}
	}

	return true
}

// groupTransforms groups transforms by their type.
func groupTransforms(xfs []Transform) map[TransformType][]Transform {
	grouped := make(map[TransformType][]Transform)
	for _, xf := range xfs {
		grouped[xf.Type] = append(grouped[xf.Type], xf)
	}

	return grouped
}

// hasMatchingTransform checks if any transform in ours matches any in theirs.
func hasMatchingTransform(ours, theirs []Transform) bool {
	for _, o := range ours {
		for _, t := range theirs {
			if transformMatch(&o, &t) {
				return true
			}
		}
	}

	return false
}

// transformMatch checks if two individual transforms are compatible.
func transformMatch(ours, theirs *Transform) bool {
	if ours.Type != theirs.Type {
		return false
	}

	if ours.ID != theirs.ID {
		return false
	}

	// For variable-key ciphers, key length must match.
	if ours.KeyLength != 0 && theirs.KeyLength != 0 && ours.KeyLength != theirs.KeyLength {
		return false
	}

	return true
}

// extractSelected extracts the selected algorithm IDs from matching proposals.
func extractSelected(ours, theirs *Proposal) *SelectedProposal {
	sel := &SelectedProposal{
		ProposalNum: theirs.Number,
		ProtocolID:  theirs.ProtocolID,
		SPI:         theirs.SPI,
	}

	ourByType := groupTransforms(ours.Transforms)
	theirByType := groupTransforms(theirs.Transforms)

	for xfType, ourXfs := range ourByType {
		theirXfs := theirByType[xfType]
		for _, o := range ourXfs {
			for _, t := range theirXfs {
				if transformMatch(&o, &t) {
					switch xfType {
					case TransformTypeENCR:
						sel.EncrID = o.ID
						sel.EncrKeyLen = o.KeyLength

						if sel.EncrKeyLen == 0 {
							sel.EncrKeyLen = t.KeyLength
						}

					case TransformTypePRF:
						sel.PRFID = o.ID

					case TransformTypeINTG:
						sel.IntegID = o.ID

					case TransformTypeDH:
						sel.DHID = o.ID

					case TransformTypeESN:
						sel.ESN = o.ID
					}

					break
				}
			}
		}
	}

	return sel
}

// buildSelectedProposal creates a single-proposal SA with only the matched transforms.
func buildSelectedProposal(theirProp, ourProp *Proposal) *Proposal {
	result := &Proposal{
		Number:     theirProp.Number,
		ProtocolID: theirProp.ProtocolID,
		SPI:        theirProp.SPI,
		IsLast:     true,
	}

	ourByType := groupTransforms(ourProp.Transforms)
	theirByType := groupTransforms(theirProp.Transforms)

	// For each transform type, pick the matched transform.
	for xfType, ourXfs := range ourByType {
		theirXfs := theirByType[xfType]
		for _, o := range ourXfs {
			for _, t := range theirXfs {
				if transformMatch(&o, &t) {
					xf := Transform{
						Type:      xfType,
						ID:        o.ID,
						KeyLength: o.KeyLength,
					}

					if xf.KeyLength == 0 {
						xf.KeyLength = t.KeyLength
					}

					result.Transforms = append(result.Transforms, xf)
					goto nextType
				}
			}
		}
	nextType:
	}

	return result
}

// ---- IKEv1 Proposal Selection ----

// SelectV1Proposal selects matching IKEv1 Phase 1 proposal.
// Returns the matched proposal and the transform attributes.
func SelectV1Proposal(sa *SAv1Payload, supported []V1Phase1Config) (*V1Phase1Config, *ProposalV1Payload, *TransformV1Payload, error) {
	if sa == nil || len(sa.Proposals) == 0 {
		return nil, nil, nil, fmt.Errorf("no IKEv1 proposals offered")
	}

	for _, prop := range sa.Proposals {
		for _, xf := range prop.Transforms {
			parsed := parseV1TransformAttrs(xf.Attributes)
			parsed.EncAlg = uint16(xf.TransformID)

			for _, sup := range supported {
				if v1ConfigMatch(&sup, &parsed) {
					matched := sup
					return &matched, &prop, &xf, nil
				}
			}
		}
	}

	return nil, nil, nil, fmt.Errorf("no IKEv1 proposal chosen: no matching transform")
}

// V1Phase1Config represents parsed IKEv1 Phase 1 transform attributes.
type V1Phase1Config struct {
	EncAlg     uint16
	HashAlg    uint16
	AuthMethod uint16
	DHGroup    uint16
	KeyLength  uint16 // For variable-key ciphers
	LifeType   uint16
	LifeDur    uint32
}

// DefaultV1Phase1Configs returns supported IKEv1 Phase 1 configurations.
func DefaultV1Phase1Configs() []V1Phase1Config {
	return []V1Phase1Config{
		// XAUTH+PSK variants (highest priority for XAUTH clients).
		{EncAlg: V1EncrAES_CBC, HashAlg: V1HashSHA256, AuthMethod: V1AuthXAUTH_InitPSK, DHGroup: DHGroup14, KeyLength: 256},
		{EncAlg: V1EncrAES_CBC, HashAlg: V1HashSHA256, AuthMethod: V1AuthXAUTH_InitPSK, DHGroup: DHGroup14, KeyLength: 128},
		{EncAlg: V1EncrAES_CBC, HashAlg: V1HashSHA1, AuthMethod: V1AuthXAUTH_InitPSK, DHGroup: DHGroup14, KeyLength: 256},
		{EncAlg: V1EncrAES_CBC, HashAlg: V1HashSHA1, AuthMethod: V1AuthXAUTH_InitPSK, DHGroup: DHGroup14, KeyLength: 128},
		{EncAlg: V1Encr3DES_CBC, HashAlg: V1HashSHA1, AuthMethod: V1AuthXAUTH_InitPSK, DHGroup: DHGroup2},
		// Standard PSK variants.
		{EncAlg: V1EncrAES_CBC, HashAlg: V1HashSHA256, AuthMethod: V1AuthPreSharedKey, DHGroup: DHGroup14, KeyLength: 256},
		{EncAlg: V1EncrAES_CBC, HashAlg: V1HashSHA256, AuthMethod: V1AuthPreSharedKey, DHGroup: DHGroup14, KeyLength: 128},
		{EncAlg: V1EncrAES_CBC, HashAlg: V1HashSHA1, AuthMethod: V1AuthPreSharedKey, DHGroup: DHGroup14, KeyLength: 256},
		{EncAlg: V1EncrAES_CBC, HashAlg: V1HashSHA1, AuthMethod: V1AuthPreSharedKey, DHGroup: DHGroup14, KeyLength: 128},
		{EncAlg: V1EncrAES_CBC, HashAlg: V1HashSHA1, AuthMethod: V1AuthPreSharedKey, DHGroup: DHGroup2, KeyLength: 128},
		{EncAlg: V1Encr3DES_CBC, HashAlg: V1HashSHA1, AuthMethod: V1AuthPreSharedKey, DHGroup: DHGroup2},
		{EncAlg: V1Encr3DES_CBC, HashAlg: V1HashSHA1, AuthMethod: V1AuthPreSharedKey, DHGroup: DHGroup14},
	}
}

// parseV1TransformAttrs extracts V1Phase1Config from ISAKMP attributes.
func parseV1TransformAttrs(attrs []ISAKMPAttribute) V1Phase1Config {
	var cfg V1Phase1Config
	for _, attr := range attrs {
		val := attrToUint16(attr)
		switch attr.Type {
		case V1AttrEncryptionAlg:
			cfg.EncAlg = val

		case V1AttrHashAlg:
			cfg.HashAlg = val

		case V1AttrAuthMethod:
			cfg.AuthMethod = val

		case V1AttrGroupDesc:
			cfg.DHGroup = val

		case V1AttrKeyLength:
			cfg.KeyLength = val

		case V1AttrLifeType:
			cfg.LifeType = val

		case V1AttrLifeDuration:
			if attr.IsTV {
				cfg.LifeDur = uint32(val)
			} else if len(attr.Value) == 4 {
				cfg.LifeDur = uint32(attr.Value[0])<<24 | uint32(attr.Value[1])<<16 |
					uint32(attr.Value[2])<<8 | uint32(attr.Value[3])
			}
		}
	}

	return cfg
}

// attrToUint16 extracts uint16 value from an ISAKMP attribute.
func attrToUint16(attr ISAKMPAttribute) uint16 {
	if len(attr.Value) >= 2 {
		return uint16(attr.Value[0])<<8 | uint16(attr.Value[1])
	}

	if len(attr.Value) == 1 {
		return uint16(attr.Value[0])
	}

	return 0
}

// v1ConfigMatch checks if a parsed transform matches a supported config.
func v1ConfigMatch(sup, parsed *V1Phase1Config) bool {
	if sup.EncAlg != parsed.EncAlg {
		return false
	}

	if sup.HashAlg != parsed.HashAlg {
		return false
	}

	if sup.AuthMethod != parsed.AuthMethod {
		return false
	}

	if sup.DHGroup != parsed.DHGroup {
		return false
	}

	// Key length: if supported requires specific, peer must match.
	if sup.KeyLength != 0 && parsed.KeyLength != 0 && sup.KeyLength != parsed.KeyLength {
		return false
	}

	return true
}

// ---- Config String Parser ----

// ParseIKEString parses an ike= config string like "aes256-sha256-modp2048"
// into IKE SA proposals. Format: "encr-hash-group[,encr-hash-group,...]"
func ParseIKEString(ikeStr string) (*SAPayload, error) {
	if ikeStr == "" {
		return DefaultIKEProposals(), nil
	}

	parts := strings.Split(ikeStr, ",")
	sa := &SAPayload{}

	for i, part := range parts {
		tokens := strings.Split(strings.TrimSpace(part), "-")
		if len(tokens) < 2 {
			return nil, fmt.Errorf("invalid IKE spec '%s': need at least encr-hash", part)
		}

		prop := Proposal{
			Number:     uint8(i + 1),
			ProtocolID: ProtocolIKE,
		}

		// Encryption.
		encrID, keyLen, err := parseEncrToken(tokens[0])
		if err != nil {
			return nil, fmt.Errorf("parsing encr '%s': %w", tokens[0], err)
		}

		prop.Transforms = append(prop.Transforms, Transform{
			Type: TransformTypeENCR, ID: encrID, KeyLength: keyLen,
		})

		// Hash → PRF + INTEG.
		prfID, integID, err := parseHashToken(tokens[1])
		if err != nil {
			return nil, fmt.Errorf("parsing hash '%s': %w", tokens[1], err)
		}

		prop.Transforms = append(prop.Transforms, Transform{
			Type: TransformTypePRF, ID: prfID,
		})

		if integID != 0 && !isAEADCipher(encrID) {
			prop.Transforms = append(prop.Transforms, Transform{
				Type: TransformTypeINTG, ID: integID,
			})
		}

		// DH group.
		if len(tokens) >= 3 {
			dhID, err := parseDHToken(tokens[2])
			if err != nil {
				return nil, fmt.Errorf("parsing DH '%s': %w", tokens[2], err)
			}

			prop.Transforms = append(prop.Transforms, Transform{
				Type: TransformTypeDH, ID: dhID,
			})
		}

		prop.Transforms = append(prop.Transforms, Transform{
			Type: TransformTypeESN, ID: ESNNone,
		})

		sa.Proposals = append(sa.Proposals, prop)
	}

	return sa, nil
}

// ParseESPString parses an esp= config string like "aes256gcm16,aes256-sha256"
// into ESP proposals.
func ParseESPString(espStr string) (*SAPayload, error) {
	if espStr == "" {
		return DefaultESPProposals(), nil
	}

	parts := strings.Split(espStr, ",")
	sa := &SAPayload{}

	for i, part := range parts {
		tokens := strings.Split(strings.TrimSpace(part), "-")
		prop := Proposal{
			Number:     uint8(i + 1),
			ProtocolID: ProtocolESP,
		}

		encrID, keyLen, err := parseEncrToken(tokens[0])
		if err != nil {
			return nil, fmt.Errorf("parsing ESP encr '%s': %w", tokens[0], err)
		}

		prop.Transforms = append(prop.Transforms, Transform{
			Type: TransformTypeENCR, ID: encrID, KeyLength: keyLen,
		})

		if len(tokens) >= 2 && !isAEADCipher(encrID) {
			_, integID, err := parseHashToken(tokens[1])
			if err != nil {
				return nil, fmt.Errorf("parsing ESP hash '%s': %w", tokens[1], err)
			}

			if integID != 0 {
				prop.Transforms = append(prop.Transforms, Transform{
					Type: TransformTypeINTG, ID: integID,
				})
			}
		}

		prop.Transforms = append(prop.Transforms, Transform{
			Type: TransformTypeESN, ID: ESNNone,
		})

		sa.Proposals = append(sa.Proposals, prop)
	}

	return sa, nil
}

// ---- Token Parsers ----

func parseEncrToken(s string) (id uint16, keyLen uint16, err error) {
	s = strings.ToLower(s)
	switch {
	case s == "aes256gcm16" || s == "aes_gcm_16_256":
		return EncrAES_GCM_16, 256, nil

	case s == "aes128gcm16" || s == "aes_gcm_16_128":
		return EncrAES_GCM_16, 128, nil

	case s == "aes256" || s == "aes_cbc_256":
		return EncrAES_CBC, 256, nil

	case s == "aes128" || s == "aes_cbc_128" || s == "aes":
		return EncrAES_CBC, 128, nil

	case s == "3des":
		return Encr3DES, 0, nil

	case s == "chacha20poly1305":
		return EncrCHACHA20, 256, nil

	default:
		return 0, 0, fmt.Errorf("unknown encryption algorithm '%s'", s)
	}
}

func parseHashToken(s string) (prfID uint16, integID uint16, err error) {
	s = strings.ToLower(s)
	switch s {
	case "sha1":
		return PRFHMAC_SHA1, AuthHMAC_SHA1_96, nil

	case "sha256", "sha2_256":
		return PRFHMAC_SHA256, AuthHMAC_SHA256_128, nil

	case "sha384", "sha2_384":
		return PRFHMAC_SHA384, AuthHMAC_SHA384_192, nil

	case "sha512", "sha2_512":
		return PRFHMAC_SHA512, AuthHMAC_SHA512_256, nil

	default:
		return 0, 0, fmt.Errorf("unknown hash algorithm '%s'", s)
	}
}

func parseDHToken(s string) (uint16, error) {
	s = strings.ToLower(s)
	switch s {
	case "modp1024", "group2":
		return DHGroup2, nil

	case "modp1536", "group5":
		return DHGroup5, nil

	case "modp2048", "group14":
		return DHGroup14, nil

	case "ecp256", "group19":
		return DHGroup19, nil

	case "ecp384", "group20":
		return DHGroup20, nil

	case "ecp521", "group21":
		return DHGroup21, nil

	default:
		return 0, fmt.Errorf("unknown DH group '%s'", s)
	}
}

func isAEADCipher(id uint16) bool {
	switch id {
	case EncrAES_GCM_8, EncrAES_GCM_12, EncrAES_GCM_16, EncrCHACHA20:
		return true

	default:
		return false
	}
}
