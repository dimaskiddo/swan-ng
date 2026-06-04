package l2tp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// IPCP option types (RFC 1332).
const (
	// IPCPOptIPAddress is the IP-Address option (RFC 1332 §3.3).
	IPCPOptIPAddress byte = 3
	// IPCPOptPrimaryDNS is the Primary DNS Server Address (RFC 1877).
	IPCPOptPrimaryDNS byte = 129
	// IPCPOptSecondaryDNS is the Secondary DNS Server Address (RFC 1877).
	IPCPOptSecondaryDNS byte = 131
)

// IPCP code values — same as LCP per RFC 1661.
const (
	IPCPConfigureRequest byte = 1
	IPCPConfigureAck     byte = 2
	IPCPConfigureNak     byte = 3
	IPCPConfigureReject  byte = 4
)

// ipcpPacketHeaderLen is Code(1) + ID(1) + Length(2) = 4.
const ipcpPacketHeaderLen = 4

// ipcpOptionHeaderLen is Type(1) + Length(1) = 2.
const ipcpOptionHeaderLen = 2

// Default DNS servers (Cloudflare per AGENTS.md).
var defaultPrimaryDNS = net.IPv4(1, 1, 1, 1)
var defaultSecondaryDNS = net.IPv4(1, 0, 0, 1)

// zeroIP is the special "request any" IP address (0.0.0.0).
var zeroIP = net.IPv4(0, 0, 0, 0)

// IPCPHandler manages IPCP negotiation for a PPP session.
// Implements server-side IPCP per RFC 1332.
//
// Flow:
//  1. Client sends Configure-Request with IP=0.0.0.0 (requesting assignment)
//  2. Server Naks with assigned IP from IPAM pool
//  3. Client sends Configure-Request with assigned IP
//  4. Server Acks
//  5. Server sends its own Configure-Request with gateway IP
//  6. Client Acks
type IPCPHandler struct {
	// assignedIP is the IP assigned to the peer from the L2TP IPAM pool.
	assignedIP net.IP
	// gatewayIP is the server-side PPP link IP.
	gatewayIP net.IP
	// primaryDNS is the primary DNS server.
	primaryDNS net.IP
	// secondaryDNS is the secondary DNS server.
	secondaryDNS net.IP
	// nextID is the identifier for our outgoing IPCP packets.
	nextID byte
	// peerConfigAcked tracks if we sent ConfigureAck to peer.
	peerConfigAcked bool
	// ourConfigAcked tracks if peer sent ConfigureAck to us.
	ourConfigAcked bool
	// opened indicates IPCP negotiation is complete.
	opened bool
}

// NewIPCPHandler creates a new IPCP handler.
// assignedIP: IP address to assign to the peer.
// gatewayIP: our server-side PPP interface IP.
// dns1, dns2: DNS servers to assign (nil = Cloudflare defaults).
func NewIPCPHandler(assignedIP, gatewayIP, dns1, dns2 net.IP) *IPCPHandler {
	h := &IPCPHandler{
		assignedIP:   assignedIP,
		gatewayIP:    gatewayIP,
		primaryDNS:   dns1,
		secondaryDNS: dns2,
	}

	if h.primaryDNS == nil {
		h.primaryDNS = defaultPrimaryDNS
	}

	if h.secondaryDNS == nil {
		h.secondaryDNS = defaultSecondaryDNS
	}

	return h
}

// IsOpened returns true when IPCP negotiation is complete (both sides acked).
func (h *IPCPHandler) IsOpened() bool {
	return h.opened
}

// AssignedIP returns the IP address assigned to the peer.
func (h *IPCPHandler) AssignedIP() net.IP {
	return h.assignedIP
}

// GatewayIP returns the server-side PPP link IP.
func (h *IPCPHandler) GatewayIP() net.IP {
	return h.gatewayIP
}

// BuildConfigureRequest generates our IPCP Configure-Request.
// We request our gateway IP address.
func (h *IPCPHandler) BuildConfigureRequest() []byte {
	h.nextID++

	// IP-Address option: Type(1) + Length(1) + IP(4) = 6 bytes.
	gw := h.gatewayIP.To4()
	if gw == nil {
		gw = net.IPv4(0, 0, 0, 0).To4()
	}

	opts := []byte{IPCPOptIPAddress, 6, gw[0], gw[1], gw[2], gw[3]}
	pktLen := uint16(ipcpPacketHeaderLen + len(opts))
	pkt := make([]byte, pktLen)

	pkt[0] = IPCPConfigureRequest
	pkt[1] = h.nextID

	binary.BigEndian.PutUint16(pkt[2:4], pktLen)
	copy(pkt[4:], opts)

	return pkt
}

// Handle processes an incoming IPCP packet and returns a response (if any).
func (h *IPCPHandler) Handle(data []byte) []byte {
	if len(data) < ipcpPacketHeaderLen {
		log.Debug("ipcp: packet too short", "len", len(data))
		return nil
	}

	code := data[0]
	id := data[1]
	pktLen := binary.BigEndian.Uint16(data[2:4])

	if int(pktLen) > len(data) {
		log.Debug("ipcp: stated length exceeds data", "pkt_len", pktLen, "data_len", len(data))
		return nil
	}

	payload := data[ipcpPacketHeaderLen:pktLen]

	switch code {
	case IPCPConfigureRequest:
		return h.handleConfigureRequest(id, payload)

	case IPCPConfigureAck:
		return h.handleConfigureAck(id)

	case IPCPConfigureNak:
		return h.handleConfigureNak(id, payload)

	case IPCPConfigureReject:
		log.Debug("ipcp: peer rejected our options", "id", id)
		return nil

	default:
		log.Debug("ipcp: unknown code", "code", code)
		return nil
	}
}

// handleConfigureRequest processes a peer's IPCP Configure-Request.
// Handles IP address assignment and DNS server negotiation.
func (h *IPCPHandler) handleConfigureRequest(id byte, options []byte) []byte {
	var ackOpts []byte
	var nakOpts []byte
	var rejOpts []byte

	offset := 0
	for offset < len(options) {
		if offset+ipcpOptionHeaderLen > len(options) {
			break
		}

		optType := options[offset]
		optLen := int(options[offset+1])

		if optLen < ipcpOptionHeaderLen || offset+optLen > len(options) {
			break
		}

		optData := options[offset : offset+optLen]

		switch optType {
		case IPCPOptIPAddress:
			if optLen >= 6 {
				requestedIP := net.IP(optData[2:6])
				assignedTo4 := h.assignedIP.To4()

				if requestedIP.Equal(zeroIP) || !requestedIP.Equal(h.assignedIP) {
					// Nak with the assigned IP.
					nak := []byte{IPCPOptIPAddress, 6, assignedTo4[0], assignedTo4[1], assignedTo4[2], assignedTo4[3]}
					nakOpts = append(nakOpts, nak...)

					log.Debug("ipcp: nak'ing IP request",
						"requested", requestedIP,
						"assigning", h.assignedIP,
					)
				} else {
					// Client requested the correct IP.
					ackOpts = append(ackOpts, optData...)
				}
			} else {
				rejOpts = append(rejOpts, optData...)
			}

		case IPCPOptPrimaryDNS:
			if optLen >= 6 {
				requestedDNS := net.IP(optData[2:6])
				dns1To4 := h.primaryDNS.To4()

				if requestedDNS.Equal(zeroIP) || !requestedDNS.Equal(h.primaryDNS) {
					nak := []byte{IPCPOptPrimaryDNS, 6, dns1To4[0], dns1To4[1], dns1To4[2], dns1To4[3]}
					nakOpts = append(nakOpts, nak...)
				} else {
					ackOpts = append(ackOpts, optData...)
				}
			} else {
				rejOpts = append(rejOpts, optData...)
			}

		case IPCPOptSecondaryDNS:
			if optLen >= 6 {
				requestedDNS := net.IP(optData[2:6])
				dns2To4 := h.secondaryDNS.To4()

				if requestedDNS.Equal(zeroIP) || !requestedDNS.Equal(h.secondaryDNS) {
					nak := []byte{IPCPOptSecondaryDNS, 6, dns2To4[0], dns2To4[1], dns2To4[2], dns2To4[3]}
					nakOpts = append(nakOpts, nak...)
				} else {
					ackOpts = append(ackOpts, optData...)
				}
			} else {
				rejOpts = append(rejOpts, optData...)
			}

		default:
			// Reject unknown IPCP options.
			rejOpts = append(rejOpts, optData...)
			log.Debug("ipcp: rejecting unknown option", "type", optType)
		}

		offset += optLen
	}

	// Priority: Reject > Nak > Ack (same as LCP).
	if len(rejOpts) > 0 {
		return h.buildResponse(IPCPConfigureReject, id, rejOpts)
	}

	if len(nakOpts) > 0 {
		return h.buildResponse(IPCPConfigureNak, id, nakOpts)
	}

	h.peerConfigAcked = true
	h.checkOpened()

	log.Info("ipcp: assigned IP to peer",
		"ip", h.assignedIP,
		"gateway", h.gatewayIP,
		"dns1", h.primaryDNS,
		"dns2", h.secondaryDNS,
	)

	return h.buildResponse(IPCPConfigureAck, id, ackOpts)
}

// handleConfigureAck processes peer's acknowledgment of our Configure-Request.
func (h *IPCPHandler) handleConfigureAck(id byte) []byte {
	if id != h.nextID {
		log.Debug("ipcp: Configure-Ack ID mismatch", "expected", h.nextID, "got", id)
		return nil
	}

	h.ourConfigAcked = true
	h.checkOpened()

	return nil
}

// handleConfigureNak processes peer's Nak of our Configure-Request.
func (h *IPCPHandler) handleConfigureNak(id byte, options []byte) []byte {
	// Parse nak'd options. Peer might suggest a different IP for us.
	offset := 0
	for offset < len(options) {
		if offset+ipcpOptionHeaderLen > len(options) {
			break
		}

		optType := options[offset]
		optLen := int(options[offset+1])

		if optLen < ipcpOptionHeaderLen || offset+optLen > len(options) {
			break
		}

		switch optType {
		case IPCPOptIPAddress:
			// Peer suggests different IP for us. We insist on our gateway IP.
			log.Debug("ipcp: peer nak'd our IP, re-requesting gateway")
		}

		offset += optLen
	}

	return h.BuildConfigureRequest()
}

// checkOpened transitions to opened state when both sides acknowledged.
func (h *IPCPHandler) checkOpened() {
	if h.ourConfigAcked && h.peerConfigAcked {
		h.opened = true

		log.Info("ipcp: negotiation complete",
			"peer_ip", h.assignedIP,
			"gateway", h.gatewayIP,
			"dns", fmt.Sprintf("%s,%s", h.primaryDNS, h.secondaryDNS),
		)
	}
}

// buildResponse constructs an IPCP response packet.
func (h *IPCPHandler) buildResponse(code, id byte, data []byte) []byte {
	pktLen := uint16(ipcpPacketHeaderLen + len(data))
	pkt := make([]byte, pktLen)

	pkt[0] = code
	pkt[1] = id

	binary.BigEndian.PutUint16(pkt[2:4], pktLen)

	if len(data) > 0 {
		copy(pkt[4:], data)
	}

	return pkt
}
