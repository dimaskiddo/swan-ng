package ike

import (
	"encoding/binary"
	"fmt"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// HandleInformational processes an IKEv2 INFORMATIONAL exchange (RFC 7296 §1.4).
// It handles Dead Peer Detection (DPD) liveness checks and DELETE payloads.
func (h *IKEv2Handler) HandleInformational(sess *IKEv2Session, msg *Message, sm *SessionManager) (*Message, error) {
	if sess == nil {
		return nil, fmt.Errorf("cannot handle INFORMATIONAL without an active session")
	}

	if len(msg.Payloads) == 0 {
		return nil, fmt.Errorf("INFORMATIONAL missing payloads")
	}

	skPayload, ok := msg.Payloads[0].Payload.(*RawPayload)
	if !ok || skPayload.PayloadType != PayloadSK {
		return nil, fmt.Errorf("INFORMATIONAL first payload not SK")
	}

	var decKey, intDecKey []byte
	var encKeyOut, intEncKeyOut []byte

	if sess.IsInitiator {
		decKey = sess.Keys.SK_er
		intDecKey = sess.Keys.SK_ar
		encKeyOut = sess.Keys.SK_ei
		intEncKeyOut = sess.Keys.SK_ai
	} else {
		decKey = sess.Keys.SK_ei
		intDecKey = sess.Keys.SK_ai
		encKeyOut = sess.Keys.SK_er
		intEncKeyOut = sess.Keys.SK_ar
	}

	// 1. Decrypt the SK payload.
	rawHeader := msg.Header.MarshalBinary()
	payloads, err := DecryptSKPayload(sess.Encryptor, sess.Integrity, decKey, intDecKey, rawHeader, skPayload.Data, msg.Header.NextPayload)
	if err != nil {
		return nil, fmt.Errorf("decrypting INFORMATIONAL SK payload: %w", err)
	}

	hasDelete := false
	var deletedSPIs []uint32

	// 2. Process Payloads.
	for _, p := range payloads {
		switch p.Header.NextPayload {
		case PayloadDelete:
			del, ok := p.Payload.(*DeletePayload)
			if !ok {
				continue
			}
			hasDelete = true

			switch del.ProtocolID {
			case ProtocolIKE:
				log.Info("IKEv2 received IKE SA DELETE payload", "peer", sess.PeerAddr)
				// Teardown everything.
				sm.DeleteV2Session(sess.SPIPair())

			case ProtocolESP:
				for _, spiBytes := range del.SPIs {
					if len(spiBytes) == 4 {
						spi := binary.BigEndian.Uint32(spiBytes)
						deletedSPIs = append(deletedSPIs, spi)
						// Teardown the specific ESP SA.
						if sm.espEngine != nil {
							sm.espEngine.RemoveInboundSA(spi)
						}
						log.Info("IKEv2 received ESP Child SA DELETE payload", "spi", fmt.Sprintf("0x%08X", spi))
					}
				}
			}

		case PayloadNotify:
			notify, ok := p.Payload.(*NotifyPayload)
			if !ok {
				continue
			}

			if notify.NotifyMsgType == NotifyInitialContact {
				log.Info("IKEv2 received INITIAL_CONTACT notify", "peer", sess.PeerAddr)
			}
		}
	}

	_ = hasDelete // Acknowledge logically. RFC 7296 allows empty INFORMATIONAL response for full deletion.

	// 3. Prepare the response message.
	respMsg := &Message{
		Header: Header{
			InitiatorSPI: msg.Header.InitiatorSPI,
			ResponderSPI: msg.Header.ResponderSPI,
			NextPayload:  PayloadSK,
			MajorVersion: IKEv2Major,
			MinorVersion: 0,
			ExchangeType: ExchangeInformational,
			Flags:        FlagResponse,
			MessageID:    msg.Header.MessageID,
		},
	}

	// 4. Encrypt and wrap in SK Payload.
	tmpHeaderBytes := make([]byte, HeaderLen)
	_ = respMsg.Header.Marshal(tmpHeaderBytes) // Ignore error, buffer is large enough.

	var innerPayloads []Payload

	firstPT, skBody, err := EncryptSKPayload(sess.Encryptor, sess.Integrity, encKeyOut, intEncKeyOut, tmpHeaderBytes, innerPayloads)
	if err != nil {
		return nil, fmt.Errorf("encrypting INFORMATIONAL response: %w", err)
	}

	respMsg.Header.NextPayload = firstPT
	respMsg.Payloads = append(respMsg.Payloads, ParsedPayload{
		Header: GenericPayloadHeader{NextPayload: PayloadNone},
		Payload: &RawPayload{
			PayloadType: PayloadSK,
			Data:        skBody,
		},
	})

	log.Debug("IKEv2 INFORMATIONAL response built", "msg_id", respMsg.Header.MessageID, "peer", sess.PeerAddr)
	return respMsg, nil
}
