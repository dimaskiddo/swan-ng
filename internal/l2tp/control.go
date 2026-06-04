package l2tp

import (
	"sync"
	"time"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// Default control channel parameters per RFC 2661 §5.8.
const (
	// defaultRetransmitInterval is the initial retransmit timer (1 second).
	defaultRetransmitInterval = 1 * time.Second
	// maxRetransmitInterval caps the exponential backoff (8 seconds per RFC 2661).
	maxRetransmitInterval = 8 * time.Second
	// defaultMaxRetries is the max retransmission attempts before tunnel teardown.
	defaultMaxRetries = 5
	// defaultReceiveWindow is the default receive window size (RFC 2661: if absent, assume 4).
	defaultReceiveWindow uint16 = 4
	// defaultHelloInterval is the keepalive timer (60 seconds, configurable per RFC 2661 §5.5).
	defaultHelloInterval = 60 * time.Second
)

// pendingMessage is a control message awaiting acknowledgement.
type pendingMessage struct {
	// data is the complete L2TP control message (header + AVPs).
	data []byte
	// ns is the sequence number of this message.
	ns uint16
	// retries is the number of retransmission attempts so far.
	retries int
	// nextRetransmit is when to retransmit if no ACK received.
	nextRetransmit time.Time
	// interval is the current retransmit interval (doubles on each retry).
	interval time.Duration
}

// ControlChannel manages reliable delivery of L2TP control messages.
// Implements RFC 2661 §5.8: sliding window with Ns/Nr sequencing,
// exponential backoff retransmission, and ZLB acknowledgments.
type ControlChannel struct {
	mu sync.Mutex

	// sendNs is the next sequence number to assign to outgoing messages.
	sendNs uint16
	// recvNr is the sequence number expected next from the peer.
	// Set to (last received Ns + 1) mod 65536.
	recvNr uint16
	// peerRecvWindow is the peer's advertised receive window size.
	peerRecvWindow uint16
	// pending is the queue of unacknowledged sent messages.
	pending []*pendingMessage
	// maxRetries before declaring tunnel dead.
	maxRetries int
	// sendFunc delivers a raw L2TP message to the peer.
	sendFunc func(data []byte)
	// onTimeout is called when retransmissions are exhausted (tunnel dead).
	onTimeout func()
	// remoteTunnelID is the peer's assigned tunnel ID for updating Nr in retransmits.
	remoteTunnelID uint16
}

// NewControlChannel creates a new reliable control channel.
// sendFunc is called to physically send a packet to the peer.
// onTimeout is called when retransmission limit is exceeded.
func NewControlChannel(sendFunc func([]byte), onTimeout func()) *ControlChannel {
	return &ControlChannel{
		peerRecvWindow: defaultReceiveWindow,
		maxRetries:     defaultMaxRetries,
		sendFunc:       sendFunc,
		onTimeout:      onTimeout,
	}
}

// SetPeerWindow sets the peer's receive window size from the Receive Window Size AVP.
func (cc *ControlChannel) SetPeerWindow(w uint16) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if w == 0 {
		w = defaultReceiveWindow
	}

	cc.peerRecvWindow = w
}

// SetRemoteTunnelID sets the remote tunnel ID for header construction.
func (cc *ControlChannel) SetRemoteTunnelID(id uint16) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.remoteTunnelID = id
}

// SendNs returns the current outbound sequence number (without incrementing).
func (cc *ControlChannel) SendNs() uint16 {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	return cc.sendNs
}

// RecvNr returns the next expected sequence number from the peer.
func (cc *ControlChannel) RecvNr() uint16 {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	return cc.recvNr
}

// Send enqueues a control message for reliable delivery.
// The L2TP header is prepended with current Ns/Nr values.
// Ns is incremented after sending. ZLB messages do NOT increment Ns.
func (cc *ControlChannel) Send(avpPayload []byte) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	ns := cc.sendNs
	nr := cc.recvNr

	// Build complete control message: header + AVP payload.
	hdr := BuildControlHeader(cc.remoteTunnelID, 0, ns, nr, len(avpPayload))
	msg := make([]byte, len(hdr)+len(avpPayload))

	copy(msg, hdr)
	copy(msg[len(hdr):], avpPayload)

	// Enqueue for reliable delivery.
	pm := &pendingMessage{
		data:           msg,
		ns:             ns,
		retries:        0,
		nextRetransmit: time.Now().Add(defaultRetransmitInterval),
		interval:       defaultRetransmitInterval,
	}
	cc.pending = append(cc.pending, pm)

	// Increment Ns (modulo 65536).
	cc.sendNs = ns + 1 // uint16 naturally wraps at 65536

	// Send immediately.
	cc.sendFunc(msg)

	log.Debug("l2tp: control sent", "ns", ns, "nr", nr, "payload_len", len(avpPayload))
}

// SendZLB sends a Zero-Length Body acknowledgment.
// ZLB does NOT increment Ns (RFC 2661 §5.8).
func (cc *ControlChannel) SendZLB() {
	cc.mu.Lock()
	ns := cc.sendNs
	nr := cc.recvNr
	remoteTID := cc.remoteTunnelID
	cc.mu.Unlock()

	zlb := BuildZLB(remoteTID, ns, nr)
	cc.sendFunc(zlb)

	log.Debug("l2tp: ZLB sent", "ns", ns, "nr", nr)
}

// Receive processes the sequence numbers from a received control message.
// Returns true if the message is in-order and should be processed.
// Returns false if the message is a duplicate or out-of-order (dropped).
// The Nr from the peer acknowledges our sent messages.
func (cc *ControlChannel) Receive(ns, nr uint16, isZLB bool) bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Process Nr: acknowledge sent messages.
	cc.acknowledgeUpTo(nr)

	// ZLB messages carry Nr for acknowledgment but no data.
	// Their Ns should not update our expected Nr.
	if isZLB {
		return false
	}

	// Check if this is the expected sequence number.
	if ns != cc.recvNr {
		// Out-of-order or duplicate. Per RFC 2661 §5.8:
		// Duplicates MUST still be acknowledged.
		log.Debug("l2tp: out-of-order/duplicate control",
			"expected_ns", cc.recvNr,
			"received_ns", ns,
		)

		return false
	}

	// In-order message: advance our Nr.
	cc.recvNr = ns + 1 // uint16 naturally wraps at 65536

	return true
}

// acknowledgeUpTo removes all pending messages with Ns < nr (modulo).
func (cc *ControlChannel) acknowledgeUpTo(nr uint16) {
	var remaining []*pendingMessage
	for _, pm := range cc.pending {
		if !seqLessThan(pm.ns, nr) {
			remaining = append(remaining, pm)
		}
	}

	acked := len(cc.pending) - len(remaining)
	cc.pending = remaining

	if acked > 0 {
		log.Debug("l2tp: acked messages", "count", acked, "nr", nr)
	}
}

// CheckRetransmit checks for messages needing retransmission.
// Returns true if the tunnel is still alive (no timeout).
// Returns false if retransmission limit exceeded (tunnel dead).
// Should be called periodically (e.g., every 500ms).
func (cc *ControlChannel) CheckRetransmit() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	now := time.Now()

	for _, pm := range cc.pending {
		if now.Before(pm.nextRetransmit) {
			continue
		}

		pm.retries++
		if pm.retries > cc.maxRetries {
			log.Warn("l2tp: retransmission limit exceeded",
				"ns", pm.ns,
				"retries", pm.retries,
			)

			// Unlock before calling onTimeout to prevent deadlock.
			cc.mu.Unlock()

			if cc.onTimeout != nil {
				cc.onTimeout()
			}

			return false
		}

		// Exponential backoff, capped at maxRetransmitInterval.
		pm.interval *= 2
		if pm.interval > maxRetransmitInterval {
			pm.interval = maxRetransmitInterval
		}

		pm.nextRetransmit = now.Add(pm.interval)

		// Update Nr in the retransmitted message header.
		// Nr field is at offset 10 in a standard control header.
		if len(pm.data) >= 12 {
			nr := cc.recvNr

			pm.data[10] = byte(nr >> 8)
			pm.data[11] = byte(nr)
		}

		cc.sendFunc(pm.data)

		log.Debug("l2tp: retransmitting",
			"ns", pm.ns,
			"retry", pm.retries,
			"next_interval", pm.interval,
		)
	}

	return true
}

// PendingCount returns the number of unacknowledged messages.
func (cc *ControlChannel) PendingCount() int {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	return len(cc.pending)
}

// seqLessThan performs modular sequence number comparison.
// Returns true if a < b in the modulo-65536 sequence space.
// Per RFC 2661 §5.8: a value is "less than or equal" if it lies in
// the range [b-32768, b] (modulo 65536).
func seqLessThan(a, b uint16) bool {
	// a < b if (b - a) mod 65536 is in [1, 32767].
	diff := (b - a) & 0xFFFF
	return diff > 0 && diff < 32768
}
