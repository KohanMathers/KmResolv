package server

import (
	"math/rand"
	"net"
	"sync"
	"time"
)

const poolSizePerServer = 16
const poolNumShards = 16

// pooledConn wraps a UDP connection with a per-connection sequential ID
// counter. Because the pool never returns the same connection to two callers
// concurrently, nextID requires no synchronisation.
type pooledConn struct {
	net.Conn
	nextID uint16
}

type poolShard struct {
	mu    sync.Mutex
	conns map[string][]*pooledConn
}

type udpPool struct {
	shards [poolNumShards]poolShard
}

func newUDPPool() *udpPool {
	p := &udpPool{}
	for i := range p.shards {
		p.shards[i].conns = make(map[string][]*pooledConn)
	}
	return p
}

func poolShardIdx(server string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(server); i++ {
		h ^= uint32(server[i])
		h *= 16777619
	}
	return h & (poolNumShards - 1)
}

func (p *udpPool) shard(server string) *poolShard {
	return &p.shards[poolShardIdx(server)]
}

func (p *udpPool) get(server string, timeout time.Duration) (*pooledConn, error) {
	s := p.shard(server)
	s.mu.Lock()
	list := s.conns[server]
	if len(list) > 0 {
		pc := list[len(list)-1]
		s.conns[server] = list[:len(list)-1]
		s.mu.Unlock()
		pc.SetDeadline(time.Now().Add(timeout))
		return pc, nil
	}
	s.mu.Unlock()

	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))
	return &pooledConn{Conn: conn, nextID: uint16(rand.Uint32())}, nil
}

func (p *udpPool) put(server string, pc *pooledConn, failed bool) {
	if failed {
		pc.Close()
		return
	}
	pc.SetDeadline(time.Time{})
	s := p.shard(server)
	s.mu.Lock()
	if len(s.conns[server]) < poolSizePerServer {
		s.conns[server] = append(s.conns[server], pc)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	pc.Close()
}
