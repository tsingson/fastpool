package iplimit

import (
	"fmt"
	"net"
	"sync"
)

type PerIPConnCounter struct {
	pool sync.Pool
	lock sync.Mutex
	m    map[uint32]int
}

func (cc *PerIPConnCounter) Register(ip uint32) int {
	cc.lock.Lock()
	if cc.m == nil {
		cc.m = make(map[uint32]int)
	}
	n := cc.m[ip] + 1
	cc.m[ip] = n
	cc.lock.Unlock()
	return n
}

func (cc *PerIPConnCounter) Unregister(ip uint32) {
	cc.lock.Lock()
	if cc.m == nil {
		cc.lock.Unlock()
		panic("BUG: PerIPConnCounter.Register() wasn't called")
	}
	n := cc.m[ip] - 1
	if n < 0 {
		cc.lock.Unlock()
		panic(fmt.Sprintf("BUG: negative per-ip counter=%d for ip=%d", n, ip))
	}
	cc.m[ip] = n
	cc.lock.Unlock()
}

type PerIPConn struct {
	net.Conn

	ip               uint32
	perIPConnCounter *PerIPConnCounter
}

func AcquirePerIPConn(conn net.Conn, ip uint32, counter *PerIPConnCounter) *PerIPConn {
	v := counter.pool.Get()
	if v == nil {
		v = &PerIPConn{
			perIPConnCounter: counter,
		}
	}
	c := v.(*PerIPConn)
	c.Conn = conn
	c.ip = ip
	return c
}

func ReleasePerIPConn(c *PerIPConn) {
	c.Conn = nil
	c.perIPConnCounter.pool.Put(c)
}

func (c *PerIPConn) Close() error {
	err := c.Conn.Close()
	c.perIPConnCounter.Unregister(c.ip)
	ReleasePerIPConn(c)
	return err
}

func GetUint32IP(c net.Conn) uint32 {
	return IP2uint32(GetConnIP4(c))
}

func GetConnIP4(c net.Conn) net.IP {
	addr := c.RemoteAddr()
	ipAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return net.IPv4zero
	}
	return ipAddr.IP.To4()
}

func IP2uint32(ip net.IP) uint32 {
	if len(ip) != 4 {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func Uint322ip(ip uint32) net.IP {
	b := make([]byte, 4)
	b[0] = byte(ip >> 24)
	b[1] = byte(ip >> 16)
	b[2] = byte(ip >> 8)
	b[3] = byte(ip)
	return b
}
