package main

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestExtractIPs(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IPv4(192, 0, 2, 1),
	})
	msg.Answer = append(msg.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "alias1.com.",
	})
	msg.Answer = append(msg.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias1.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "alias2.com.",
	})
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "alias2.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IPv4(192, 0, 2, 2),
	})

	tests := []struct {
		domain   string
		expected []net.IP
	}{
		{"example.com.", []net.IP{net.IPv4(192, 0, 2, 1)}},
		{"alias.com.", []net.IP{net.IPv4(192, 0, 2, 2)}},
		{"nonexistent.com.", nil},
	}

	for _, tt := range tests {
		result := extractIPs(msg, tt.domain)
		assert.Equal(t, tt.expected, result, "extractIPs(%v) = %v; want %v", tt.domain, result, tt.expected)
	}
}
