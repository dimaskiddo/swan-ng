package ike

import (
	"testing"
)

func TestXAUTHConstants(t *testing.T) {
	// Verify XAUTH auth method IDs per draft-ietf-ipsec-isakmp-xauth-06.
	if V1AuthXAUTH_InitPSK != 65001 {
		t.Errorf("V1AuthXAUTH_InitPSK: got %d, want 65001", V1AuthXAUTH_InitPSK)
	}
	if V1AuthXAUTH_RespPSK != 65005 {
		t.Errorf("V1AuthXAUTH_RespPSK: got %d, want 65005", V1AuthXAUTH_RespPSK)
	}
	if V1AuthXAUTH_InitRSA != 65003 {
		t.Errorf("V1AuthXAUTH_InitRSA: got %d, want 65003", V1AuthXAUTH_InitRSA)
	}
	if V1AuthXAUTH_RespRSA != 65007 {
		t.Errorf("V1AuthXAUTH_RespRSA: got %d, want 65007", V1AuthXAUTH_RespRSA)
	}

	// Verify XAUTH attribute type IDs.
	if XAUTH_TYPE != 16520 {
		t.Errorf("XAUTH_TYPE: got %d, want 16520", XAUTH_TYPE)
	}
	if XAUTH_USER_NAME != 16521 {
		t.Errorf("XAUTH_USER_NAME: got %d, want 16521", XAUTH_USER_NAME)
	}
	if XAUTH_USER_PASSWORD != 16522 {
		t.Errorf("XAUTH_USER_PASSWORD: got %d, want 16522", XAUTH_USER_PASSWORD)
	}
	if XAUTH_STATUS != 16527 {
		t.Errorf("XAUTH_STATUS: got %d, want 16527", XAUTH_STATUS)
	}
}

func TestXAUTHProposalInDefaults(t *testing.T) {
	configs := DefaultV1Phase1Configs()

	foundXAUTH := false
	foundPSK := false

	for _, cfg := range configs {
		if cfg.AuthMethod == V1AuthXAUTH_InitPSK {
			foundXAUTH = true
		}
		if cfg.AuthMethod == V1AuthPreSharedKey {
			foundPSK = true
		}
	}

	if !foundXAUTH {
		t.Error("Default V1 Phase 1 configs missing XAUTH+PSK proposals")
	}
	if !foundPSK {
		t.Error("Default V1 Phase 1 configs missing plain PSK proposals")
	}
}

func TestTransactionExchangeType(t *testing.T) {
	if ExchangeTransaction != 6 {
		t.Errorf("ExchangeTransaction: got %d, want 6", ExchangeTransaction)
	}

	str := ExchangeTransaction.String()
	if str != "Transaction" {
		t.Errorf("ExchangeTransaction.String(): got %q, want %q", str, "Transaction")
	}
}

func TestISAKMPCfgConstants(t *testing.T) {
	if ISAKMPCfgRequest != 1 {
		t.Errorf("ISAKMPCfgRequest: got %d, want 1", ISAKMPCfgRequest)
	}
	if ISAKMPCfgReply != 2 {
		t.Errorf("ISAKMPCfgReply: got %d, want 2", ISAKMPCfgReply)
	}
	if ISAKMPCfgSet != 3 {
		t.Errorf("ISAKMPCfgSet: got %d, want 3", ISAKMPCfgSet)
	}
	if ISAKMPCfgAck != 4 {
		t.Errorf("ISAKMPCfgAck: got %d, want 4", ISAKMPCfgAck)
	}
}

func TestXAUTHSessionStates(t *testing.T) {
	// Verify XAUTH states are defined.
	if StateV1XAUTHSent.String() != "XAUTHSent" {
		t.Errorf("StateV1XAUTHSent.String(): got %q", StateV1XAUTHSent.String())
	}
	if StateV1XAUTHDone.String() != "XAUTHDone" {
		t.Errorf("StateV1XAUTHDone.String(): got %q", StateV1XAUTHDone.String())
	}
}

func TestEAPSessionStates(t *testing.T) {
	// Verify EAP states for IKEv2.
	if StateV2EAPInProgress.String() != "EAPInProgress" {
		t.Errorf("StateV2EAPInProgress.String(): got %q", StateV2EAPInProgress.String())
	}
	if StateV2EAPDone.String() != "EAPDone" {
		t.Errorf("StateV2EAPDone.String(): got %q", StateV2EAPDone.String())
	}
}
