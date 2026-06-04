package ike

import (
	"encoding/binary"
	"testing"
)

func TestIsDPDVendorID(t *testing.T) {
	if !IsDPDVendorID(DPDVendorID) {
		t.Error("DPDVendorID should match itself")
	}

	badVID := make([]byte, len(DPDVendorID))
	copy(badVID, DPDVendorID)
	badVID[0] ^= 0xFF

	if IsDPDVendorID(badVID) {
		t.Error("corrupted VID should not match")
	}

	if IsDPDVendorID(nil) {
		t.Error("nil should not match")
	}

	if IsDPDVendorID([]byte{0x01, 0x02}) {
		t.Error("short data should not match")
	}
}

func TestBuildDPDRUThere(t *testing.T) {
	spiI := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	spiR := [8]byte{9, 10, 11, 12, 13, 14, 15, 16}

	msg := BuildDPDRUThere(spiI, spiR, 42, 100)

	if msg == nil {
		t.Fatal("expected non-nil message")
	}

	if msg.Header.ExchangeType != ExchangeInformationalV1 {
		t.Errorf("expected Informational v1, got %s", msg.Header.ExchangeType)
	}

	if msg.Header.MajorVersion != IKEv1Major {
		t.Errorf("expected IKEv1, got major=%d", msg.Header.MajorVersion)
	}

	if msg.Header.MessageID != 42 {
		t.Errorf("expected messageID 42, got %d", msg.Header.MessageID)
	}

	if len(msg.Payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(msg.Payloads))
	}

	notify, ok := msg.Payloads[0].Payload.(*NotifyV1Payload)
	if !ok {
		t.Fatal("expected NotifyV1Payload")
	}

	if notify.NotifyMsgType != NotifyV1DPD_R_U_THERE {
		t.Errorf("expected R_U_THERE (%d), got %d", NotifyV1DPD_R_U_THERE, notify.NotifyMsgType)
	}

	if len(notify.NotifyData) != 4 {
		t.Fatalf("expected 4-byte seq, got %d", len(notify.NotifyData))
	}

	seq := binary.BigEndian.Uint32(notify.NotifyData)
	if seq != 100 {
		t.Errorf("expected seq 100, got %d", seq)
	}
}

func TestBuildDPDRUThereAck(t *testing.T) {
	spiI := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	spiR := [8]byte{9, 10, 11, 12, 13, 14, 15, 16}

	msg := BuildDPDRUThereAck(spiI, spiR, 42, 200)

	if msg == nil {
		t.Fatal("expected non-nil message")
	}

	notify, ok := msg.Payloads[0].Payload.(*NotifyV1Payload)
	if !ok {
		t.Fatal("expected NotifyV1Payload")
	}

	if notify.NotifyMsgType != NotifyV1DPD_R_U_THERE_ACK {
		t.Errorf("expected R_U_THERE_ACK (%d), got %d", NotifyV1DPD_R_U_THERE_ACK, notify.NotifyMsgType)
	}

	seq := binary.BigEndian.Uint32(notify.NotifyData)
	if seq != 200 {
		t.Errorf("expected seq 200, got %d", seq)
	}
}

func TestHandleDPDNotify_RUThere(t *testing.T) {
	spiI := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	spiR := [8]byte{9, 10, 11, 12, 13, 14, 15, 16}

	seqData := make([]byte, 4)
	binary.BigEndian.PutUint32(seqData, 42)

	notify := &NotifyV1Payload{
		DOI:           DOIIPsec,
		ProtocolID:    ProtocolIKE,
		NotifyMsgType: NotifyV1DPD_R_U_THERE,
		NotifyData:    seqData,
	}

	resp := HandleDPDNotify(notify, spiI, spiR, 99)
	if resp == nil {
		t.Fatal("R-U-THERE should produce R-U-THERE-ACK response")
	}

	ackNotify, ok := resp.Payloads[0].Payload.(*NotifyV1Payload)
	if !ok {
		t.Fatal("expected NotifyV1Payload in response")
	}

	if ackNotify.NotifyMsgType != NotifyV1DPD_R_U_THERE_ACK {
		t.Errorf("expected ACK type, got %d", ackNotify.NotifyMsgType)
	}

	ackSeq := binary.BigEndian.Uint32(ackNotify.NotifyData)
	if ackSeq != 42 {
		t.Errorf("ACK seq should match request: expected 42, got %d", ackSeq)
	}
}

func TestHandleDPDNotify_ACK(t *testing.T) {
	spiI := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	spiR := [8]byte{9, 10, 11, 12, 13, 14, 15, 16}

	seqData := make([]byte, 4)
	binary.BigEndian.PutUint32(seqData, 42)

	notify := &NotifyV1Payload{
		DOI:           DOIIPsec,
		ProtocolID:    ProtocolIKE,
		NotifyMsgType: NotifyV1DPD_R_U_THERE_ACK,
		NotifyData:    seqData,
	}

	resp := HandleDPDNotify(notify, spiI, spiR, 99)
	if resp != nil {
		t.Error("R-U-THERE-ACK should not produce a response")
	}
}

func TestHandleDPDNotify_Nil(t *testing.T) {
	spiI := [8]byte{}
	spiR := [8]byte{}

	resp := HandleDPDNotify(nil, spiI, spiR, 0)
	if resp != nil {
		t.Error("nil notify should return nil")
	}
}

func TestNextDPDSequence(t *testing.T) {
	seq1 := NextDPDSequence()
	seq2 := NextDPDSequence()

	if seq2 != seq1+1 {
		t.Errorf("DPD sequence should increment: seq1=%d, seq2=%d", seq1, seq2)
	}
}
