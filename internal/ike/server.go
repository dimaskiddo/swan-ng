package ike

import (
	"fmt"
	"net"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// UDPSender sends UDP datagrams to a remote peer.
type UDPSender interface {
	SendTo(port int, data []byte, remoteAddr *net.UDPAddr) error
}

// Server handles all incoming IKE control plane packets.
type Server struct {
	SessionManager  *SessionManager
	V1Handler       *IKEv1Handler
	V2Handler       *IKEv2Handler
	FragmentManager *FragmentManager
	udpSender       UDPSender
}

// NewServer creates a new IKE server instance.
func NewServer(sm *SessionManager, v1 *IKEv1Handler, v2 *IKEv2Handler, sender UDPSender) *Server {
	return &Server{
		SessionManager:  sm,
		V1Handler:       v1,
		V2Handler:       v2,
		FragmentManager: NewFragmentManager(),
		udpSender:       sender,
	}
}

// HandlePacket processes an incoming UDP datagram.
// buf contains the packet payload (without UDP/IP headers).
// For port 4500, the caller must strip the 4-byte Non-ESP marker before passing.
func (s *Server) HandlePacket(buf []byte, n int, remoteAddr *net.UDPAddr, isNATT bool) {
	if n < HeaderLen {
		log.Debug("IKE packet too short", "len", n, "peer", remoteAddr)
		return
	}

	packetData := buf[:n]

	// Parse only the generic header to determine version and SPIs.
	hdr, err := ParseHeader(packetData)
	if err != nil {
		log.Debug("Failed to parse IKE header", "error", err.Error(), "peer", remoteAddr)
		return
	}

	if err := hdr.Validate(); err != nil {
		log.Debug("Invalid IKE header", "error", err.Error(), "peer", remoteAddr)
		return
	}

	switch hdr.MajorVersion {
	case IKEv2Major:
		s.handleIKEv2(packetData, hdr, remoteAddr, isNATT)

	case IKEv1Major:
		s.handleIKEv1(packetData, hdr, remoteAddr, isNATT)

	default:
		log.Warn("Received IKE packet with unsupported version", "version", hdr.MajorVersion, "peer", remoteAddr)
	}
}

func (s *Server) handleIKEv2(packetData []byte, _ Header, remoteAddr *net.UDPAddr, isNATT bool) {
	msg, err := ParseMessage(packetData)
	if err != nil {
		log.Debug("Failed to parse IKEv2 message", "error", err.Error(), "peer", remoteAddr)
		return
	}

	log.Debug("IKEv2 packet received",
		"exchange", msg.Header.ExchangeType,
		"msg_id", msg.Header.MessageID,
		"peer", remoteAddr,
	)

	var resp *Message
	var newSess *IKEv2Session
	var procErr error

	switch msg.Header.ExchangeType {
	case ExchangeIKESAInit:
		resp, newSess, procErr = s.V2Handler.HandleSAInit(msg, remoteAddr)
		if newSess != nil {
			s.SessionManager.RegisterV2Session(newSess)
		}

	case ExchangeIKEAuth:
		sess := s.SessionManager.GetV2Session(msg.Header.SPIPair())
		if sess == nil {
			log.Debug("IKE_AUTH: session not found", "spi", fmt.Sprintf("%x", msg.Header.InitiatorSPI))
			return
		}
		// Passing nil for IP assignment and DNS servers for now (Phase 6 IPAM).
		resp, procErr = s.V2Handler.HandleAuth(sess, msg, nil, nil)

	case ExchangeInformational:
		sess := s.SessionManager.GetV2Session(msg.Header.SPIPair())
		if sess == nil {
			log.Debug("INFORMATIONAL: session not found", "spi", fmt.Sprintf("%x", msg.Header.InitiatorSPI))
			return
		}
		resp, procErr = s.V2Handler.HandleInformational(sess, msg, s.SessionManager)

	default:
		log.Debug("Unsupported IKEv2 exchange", "exchange", msg.Header.ExchangeType)
		return
	}

	if procErr != nil {
		log.Debug("IKEv2 processing error", "error", procErr.Error(), "peer", remoteAddr)
		return
	}

	if resp != nil {
		s.sendResponse(resp, remoteAddr, isNATT)
	}
}

func (s *Server) handleIKEv1(packetData []byte, hdr Header, remoteAddr *net.UDPAddr, isNATT bool) {
	log.Debug("IKEv1 packet received",
		"exchange", hdr.ExchangeType,
		"peer", remoteAddr,
	)

	if hdr.ExchangeType == ExchangeIdentityProtect {
		emptySPI := [8]byte{}
		if hdr.ResponderSPI == emptySPI {
			msg, err := ParseMessage(packetData)
			if err != nil {
				log.Debug("Failed to parse IKEv1 msg1", "error", err)
				return
			}

			resp, newSess, err := s.V1Handler.HandleMainMode1(msg, remoteAddr)
			if err != nil {
				log.Debug("IKEv1 MainMode1 error", "error", err)
				return
			}

			if newSess != nil {
				s.SessionManager.RegisterV1Session(newSess)
			}

			if resp != nil {
				s.sendResponse(resp, remoteAddr, isNATT)
			}
		} else {
			sess := s.SessionManager.GetV1Session(hdr.SPIPair())
			if sess == nil {
				log.Debug("IKEv1 session not found", "spi", fmt.Sprintf("%x", hdr.InitiatorSPI))
				return
			}
		}
	}
}

func (s *Server) sendResponse(msg *Message, remoteAddr *net.UDPAddr, isNATT bool) {
	if s.udpSender == nil {
		log.Warn("IKE server cannot send response: no UDP sender configured")
		return
	}

	data, err := msg.Marshal()
	if err != nil {
		log.Error("Failed to marshal IKE response", "error", err.Error(), "peer", remoteAddr)
		return
	}

	port := 500
	if isNATT {
		port = 4500
		nattData := make([]byte, len(data)+4)

		copy(nattData[4:], data)
		data = nattData
	}

	if err := s.udpSender.SendTo(port, data, remoteAddr); err != nil {
		log.Error("Failed to send IKE response", "error", err.Error(), "peer", remoteAddr)
	}
}
