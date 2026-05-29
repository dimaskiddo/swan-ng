package ipam

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
)

// Pool manages a range of IPv4 addresses for client assignment.
// Uses a bitmap for O(1) allocation tracking. Thread-safe via sync.Mutex.
type Pool struct {
	mu       sync.Mutex
	startIP  uint32
	endIP    uint32
	size     int
	bitmap   []bool
	nextFree int
}

// NewPool creates a new IP address pool from a range string.
// Format: "startIP - endIP" (e.g., "10.0.0.10 - 10.0.0.250").
func NewPool(rangeStr string) (*Pool, error) {
	startIP, endIP, err := parseRange(rangeStr)
	if err != nil {
		return nil, err
	}

	startN := ipToUint32(startIP)
	endN := ipToUint32(endIP)

	if startN > endN {
		return nil, fmt.Errorf("ipam: start IP %s is after end IP %s", startIP, endIP)
	}

	if startN == 0 || endN == 0 {
		return nil, fmt.Errorf("ipam: invalid IP range %q", rangeStr)
	}

	size := int(endN-startN) + 1
	if size > 65536 {
		return nil, fmt.Errorf("ipam: pool size %d exceeds maximum 65536", size)
	}

	return &Pool{
		startIP:  startN,
		endIP:    endN,
		size:     size,
		bitmap:   make([]bool, size),
		nextFree: 0,
	}, nil
}

// Allocate assigns the next available IP from the pool.
func (p *Pool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i := 0; i < p.size; i++ {
		idx := (p.nextFree + i) % p.size
		if !p.bitmap[idx] {
			p.bitmap[idx] = true
			p.nextFree = (idx + 1) % p.size

			return uint32ToIP(p.startIP + uint32(idx)), nil
		}
	}

	return nil, fmt.Errorf("ipam: pool exhausted, no available addresses")
}

// AllocateSpecific assigns a specific IP from the pool.
func (p *Pool) AllocateSpecific(ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ip = ip.To4()
	if ip == nil {
		return fmt.Errorf("ipam: not a valid IPv4 address")
	}

	n := ipToUint32(ip)
	if n < p.startIP || n > p.endIP {
		return fmt.Errorf("ipam: %s is outside pool range", ip)
	}

	idx := int(n - p.startIP)
	if p.bitmap[idx] {
		return fmt.Errorf("ipam: %s is already allocated", ip)
	}

	p.bitmap[idx] = true
	return nil
}

// Release returns an IP back to the pool.
func (p *Pool) Release(ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ip = ip.To4()
	if ip == nil {
		return fmt.Errorf("ipam: not a valid IPv4 address")
	}

	n := ipToUint32(ip)
	if n < p.startIP || n > p.endIP {
		return fmt.Errorf("ipam: %s is outside pool range", ip)
	}

	idx := int(n - p.startIP)
	if !p.bitmap[idx] {
		return fmt.Errorf("ipam: %s is not allocated", ip)
	}

	p.bitmap[idx] = false
	if idx < p.nextFree {
		p.nextFree = idx
	}

	return nil
}

// Available returns count of unallocated addresses.
func (p *Pool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	count := 0
	for _, allocated := range p.bitmap {
		if !allocated {
			count++
		}
	}

	return count
}

// Size returns total addresses in pool.
func (p *Pool) Size() int {
	return p.size
}

// StartIP returns first IP in pool range.
func (p *Pool) StartIP() net.IP {
	return uint32ToIP(p.startIP)
}

// EndIP returns last IP in pool range.
func (p *Pool) EndIP() net.IP {
	return uint32ToIP(p.endIP)
}

func parseRange(rangeStr string) (net.IP, net.IP, error) {
	parts := strings.SplitN(rangeStr, "-", 2)
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("ipam: invalid range %q, expected \"startIP - endIP\"", rangeStr)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	if startIP == nil {
		return nil, nil, fmt.Errorf("ipam: invalid start IP %q", strings.TrimSpace(parts[0]))
	}

	endIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()
	if endIP == nil {
		return nil, nil, fmt.Errorf("ipam: invalid end IP %q", strings.TrimSpace(parts[1]))
	}

	return startIP, endIP, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}

	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)

	return ip
}
