package server

import (
	"net"
	"sync"
	"time"
)

const poolSizePerServer = 16
const poolNumShards = 16

type poolShard struct {
	mu    sync.Mutex
	conns map[string][]net.Conn
}

type udpPool struct {
	shards [poolNumShards]poolShard
}

func newUDPPool() *udpPool {
	p := &udpPool{}
	for i := range p.shards {
		p.shards[i].conns = make(map[string][]net.Conn)
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

func (p *udpPool) get(server string, timeout time.Duration) (net.Conn, error) {
	s := p.shard(server)
	s.mu.Lock()
	list := s.conns[server]
	if len(list) > 0 {
		conn := list[len(list)-1]
		s.conns[server] = list[:len(list)-1]
		s.mu.Unlock()
		conn.SetDeadline(time.Now().Add(timeout))
		return conn, nil
	}
	s.mu.Unlock()

	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

func (p *udpPool) put(server string, conn net.Conn, failed bool) {
	if failed {
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})
	s := p.shard(server)
	s.mu.Lock()
	if len(s.conns[server]) < poolSizePerServer {
		s.conns[server] = append(s.conns[server], conn)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	conn.Close()
}
