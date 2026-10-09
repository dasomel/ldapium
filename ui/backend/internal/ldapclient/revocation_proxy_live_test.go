//go:build live

package ldapclient

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// D4-test: this scheduling observer forwards original LDAP bytes to real slapd.
// It never creates replies. Every accepted connection stays on one backend.
type revocationWireProxy struct {
	listener              net.Listener
	mu                    sync.Mutex
	connections, searches int
	backends              []string
	beforeSearch          func(int)
}

func newRevocationWireProxy(t *testing.T, backends []string, before func(int)) *revocationWireProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &revocationWireProxy{listener: l, backends: backends, beforeSearch: before}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			backend := p.backends[p.connections%len(p.backends)]
			p.connections++
			p.mu.Unlock()
			go p.forward(c, backend)
		}
	}()
	return p
}

type capturedLDAPRead struct {
	io.Reader
	bytes.Buffer
}

func (r *capturedLDAPRead) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	_, _ = r.Buffer.Write(b[:n])
	return n, err
}

func (p *revocationWireProxy) forward(c net.Conn, backend string) {
	defer c.Close()
	upstream, err := net.Dial("tcp", backend)
	if err != nil {
		return
	}
	defer upstream.Close()
	go func() { _, _ = io.Copy(c, upstream); _ = c.Close() }()
	for {
		r := &capturedLDAPRead{Reader: c}
		packet, err := ber.ReadPacket(r)
		if err != nil {
			return
		}
		if len(packet.Children) > 1 && packet.Children[1].ClassType == ber.ClassApplication && packet.Children[1].Tag == 3 {
			p.mu.Lock()
			p.searches++
			count := p.searches
			p.mu.Unlock()
			if p.beforeSearch != nil {
				p.beforeSearch(count)
			}
		}
		if _, err := upstream.Write(r.Buffer.Bytes()); err != nil {
			return
		}
	}
}

func (p *revocationWireProxy) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connections, p.searches
}
