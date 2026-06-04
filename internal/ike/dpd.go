package ike

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// Dead Peer Detection (DPD) for IKEv1 per RFC 3706.
//
// DPD uses Informational exchanges with vendor-specific notify types:
//   - R-U-THERE (36136): "Are you alive?"
//   - R-U-THERE-ACK (36137): "Yes, I am alive."
//
// The DPD Vendor ID is the MD5 hash of "CISCO-DEAD-PEER-DETECTION".

// DPD Notify Message Types (RFC 3706 §3.1).
const (
	NotifyV1DPD_R_U_THERE     uint16 = 36136
	NotifyV1DPD_R_U_THERE_ACK uint16 = 36137
)

// DPDVendorID is the well-known vendor ID for DPD support (RFC 3706).
// MD5("CISCO-DEAD-PEER-DETECTION") per draft-ietf-ipsec-dpd-04.
var DPDVendorID = []byte{
	0xAF, 0xCA, 0xD7, 0x13, 0x68, 0xA1, 0xF1, 0xC9,
	0x6B, 0x86, 0x96, 0xFC, 0x77, 0x57, 0x01, 0x00,
}

// DPDSequenceCounter is an atomic counter for DPD sequence numbers.
var dpdSequenceCounter uint32

// NextDPDSequence returns the next DPD sequence number (atomic).
func NextDPDSequence() uint32 {
	return atomic.AddUint32(&dpdSequenceCounter, 1)
}

// IsDPDVendorID checks if a Vendor ID payload matches the DPD vendor ID.
func IsDPDVendorID(vendorData []byte) bool {
	if len(vendorData) != len(DPDVendorID) {
		return false
	}

	for i, b := range DPDVendorID {
		if vendorData[i] != b {
			return false
		}
	}

	return true
}

// BuildDPDRUThere constructs an IKEv1 INFORMATIONAL exchange containing
// an R-U-THERE notification for Dead Peer Detection (RFC 3706 §3.1).
func BuildDPDRUThere(initiatorSPI, responderSPI [8]byte, messageID uint32, seq uint32) *Message {
	// R-U-THERE notify data = 4-byte sequence number (big-endian).
	seqData := make([]byte, 4)
	binary.BigEndian.PutUint32(seqData, seq)

	notify := &NotifyV1Payload{
		DOI:           DOIIPsec,
		ProtocolID:    ProtocolIKE,
		SPISize:       16,
		NotifyMsgType: NotifyV1DPD_R_U_THERE,
		SPI:           append(initiatorSPI[:], responderSPI[:]...),
		NotifyData:    seqData,
	}

	msg := &Message{
		Header: Header{
			InitiatorSPI: initiatorSPI,
			ResponderSPI: responderSPI,
			NextPayload:  PayloadNotifyV1,
			ExchangeType: ExchangeInformationalV1,
			MessageID:    messageID,
		},
	}

	msg.Header.SetIKEv1()

	msg.Payloads = append(msg.Payloads, ParsedPayload{
		Header:  GenericPayloadHeader{NextPayload: PayloadNone},
		Payload: notify,
	})

	return msg
}

// BuildDPDRUThereAck constructs an IKEv1 R-U-THERE-ACK response (RFC 3706 §3.1).
// The sequence number must match the received R-U-THERE.
func BuildDPDRUThereAck(initiatorSPI, responderSPI [8]byte, messageID uint32, seq uint32) *Message {
	seqData := make([]byte, 4)
	binary.BigEndian.PutUint32(seqData, seq)

	notify := &NotifyV1Payload{
		DOI:           DOIIPsec,
		ProtocolID:    ProtocolIKE,
		SPISize:       16,
		NotifyMsgType: NotifyV1DPD_R_U_THERE_ACK,
		SPI:           append(initiatorSPI[:], responderSPI[:]...),
		NotifyData:    seqData,
	}

	msg := &Message{
		Header: Header{
			InitiatorSPI: initiatorSPI,
			ResponderSPI: responderSPI,
			NextPayload:  PayloadNotifyV1,
			ExchangeType: ExchangeInformationalV1,
			MessageID:    messageID,
		},
	}

	msg.Header.SetIKEv1()

	msg.Payloads = append(msg.Payloads, ParsedPayload{
		Header:  GenericPayloadHeader{NextPayload: PayloadNone},
		Payload: notify,
	})

	return msg
}

// HandleDPDNotify processes a DPD notify payload and returns an appropriate response.
// For R-U-THERE, returns an R-U-THERE-ACK with the same sequence number.
// For R-U-THERE-ACK, logs and returns nil (acknowledge only).
func HandleDPDNotify(notify *NotifyV1Payload, initiatorSPI, responderSPI [8]byte, messageID uint32) *Message {
	if notify == nil {
		return nil
	}

	switch notify.NotifyMsgType {
	case NotifyV1DPD_R_U_THERE:
		// Extract sequence number from notify data.
		var seq uint32
		if len(notify.NotifyData) >= 4 {
			seq = binary.BigEndian.Uint32(notify.NotifyData[:4])
		}

		log.Debug("IKEv1 DPD R-U-THERE received",
			"seq", seq,
			"spi_i", fmt.Sprintf("%x", initiatorSPI),
		)

		return BuildDPDRUThereAck(initiatorSPI, responderSPI, messageID, seq)

	case NotifyV1DPD_R_U_THERE_ACK:
		var seq uint32
		if len(notify.NotifyData) >= 4 {
			seq = binary.BigEndian.Uint32(notify.NotifyData[:4])
		}

		log.Debug("IKEv1 DPD R-U-THERE-ACK received",
			"seq", seq,
			"spi_i", fmt.Sprintf("%x", initiatorSPI),
		)

		return nil // Acknowledged, no response needed.

	default:
		return nil
	}
}
