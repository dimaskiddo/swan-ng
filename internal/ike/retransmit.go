package ike

import (
	"sync"
	"time"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// RetransmitConfig defines the exponential backoff parameters (RFC 7296 §2.4).
type RetransmitConfig struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	MaxRetries      int
}

// DefaultRetransmitConfig provides sensible defaults for VPN connections.
var DefaultRetransmitConfig = RetransmitConfig{
	InitialInterval: 1 * time.Second,
	MaxInterval:     16 * time.Second,
	MaxRetries:      5,
}

// PendingRequest tracks an unacknowledged IKE message.
type PendingRequest struct {
	MsgID    uint32
	Data     []byte
	Retries  int
	Timer    *time.Timer
	Interval time.Duration
}

// Retransmitter handles IKE message retransmissions for a session.
type Retransmitter struct {
	mu      sync.Mutex
	cfg     RetransmitConfig
	pending map[uint32]*PendingRequest

	// Callback to actually send the data over the network.
	sendFunc func(data []byte) error

	// Callback when max retries is reached (teardown session).
	timeoutFunc func()
}

// NewRetransmitter creates a new retransmission manager.
func NewRetransmitter(cfg RetransmitConfig, sendFunc func(data []byte) error, timeoutFunc func()) *Retransmitter {
	return &Retransmitter{
		cfg:         cfg,
		pending:     make(map[uint32]*PendingRequest),
		sendFunc:    sendFunc,
		timeoutFunc: timeoutFunc,
	}
}

// Start tracking a sent message and schedule retransmission.
func (r *Retransmitter) Start(msgID uint32, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.pending[msgID]; exists {
		return
	}

	req := &PendingRequest{
		MsgID:    msgID,
		Data:     data,
		Retries:  0,
		Interval: r.cfg.InitialInterval,
	}

	req.Timer = time.AfterFunc(req.Interval, func() {
		r.handleTimeout(msgID)
	})

	r.pending[msgID] = req
}

// Stop tracking a message (called when a response is received).
func (r *Retransmitter) Stop(msgID uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if req, exists := r.pending[msgID]; exists {
		req.Timer.Stop()
		delete(r.pending, msgID)
	}
}

func (r *Retransmitter) handleTimeout(msgID uint32) {
	r.mu.Lock()
	req, exists := r.pending[msgID]
	if !exists {
		r.mu.Unlock()
		return
	}

	req.Retries++
	if req.Retries > r.cfg.MaxRetries {
		delete(r.pending, msgID)
		r.mu.Unlock()

		log.Warn("IKE message retransmission timeout, tearing down session", "msg_id", msgID)
		if r.timeoutFunc != nil {
			r.timeoutFunc()
		}
		return
	}

	req.Interval *= 2
	if req.Interval > r.cfg.MaxInterval {
		req.Interval = r.cfg.MaxInterval
	}

	req.Timer.Reset(req.Interval)
	r.mu.Unlock()

	log.Debug("Retransmitting IKE message", "msg_id", msgID, "retry", req.Retries)
	if r.sendFunc != nil {
		_ = r.sendFunc(req.Data)
	}
}

// StopAll stops all pending retransmission timers.
// Called when the session is closed manually or via delete payload.
func (r *Retransmitter) StopAll() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, req := range r.pending {
		req.Timer.Stop()
	}

	r.pending = make(map[uint32]*PendingRequest)
}
