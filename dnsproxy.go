package main

import (
	"context"
	"github.com/miekg/dns"
	"log"
	"net"
)

type DnsProxy struct {
	listenAddr  string
	forwardAddr string
	callback    func(domain string, ips []net.IP)
}

// NewDnsProxy creates a new instance of DnsProxy with the specified listen address,
// forward address, and callback function. The callback function is called with the
// domain name and a list of IP addresses whenever a DNS request is processed.
func NewDnsProxy(listenAddr, forwardAddr string, callback func(domain string, ips []net.IP)) *DnsProxy {
	return &DnsProxy{
		listenAddr:  listenAddr,
		forwardAddr: forwardAddr,
		callback:    callback,
	}
}

// Start initializes and starts the DNS proxy server
func (p *DnsProxy) Start(ctx context.Context) error {
	server := &dns.Server{Addr: p.listenAddr, Net: "udp"}
	dns.HandleFunc(".", p.handleDNSRequest)

	log.Printf("Starting DNS proxy on %s, forwarding to %s\n", p.listenAddr, p.forwardAddr)

	go func() {
		<-ctx.Done()
		err := server.Shutdown()
		log.Printf("DNS proxy server terminated, %v", err)
	}()

	return server.ListenAndServe()
}

func (p *DnsProxy) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	client := new(dns.Client)
	client.UDPSize = 4096
	resp, _, err := client.Exchange(r, p.forwardAddr)
	if err != nil {
		log.Printf("Failed to forward request: %v", err)
		dns.HandleFailed(w, r)
		return
	}

	for _, question := range r.Question {
		ips := extractIPs(resp, question.Name)
		if len(ips) > 0 {
			p.callback(question.Name, ips)
		}
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func extractIPs(resp *dns.Msg, domain string) []net.IP {
	var ips []net.IP
	var cNames []string
	visited := make(map[string]bool)

	var extract func(resp *dns.Msg, domain string)
	extract = func(resp *dns.Msg, domain string) {
		if visited[domain] {
			return
		}
		visited[domain] = true

		for _, rr := range resp.Answer {
			switch rr := rr.(type) {
			case *dns.A:
				if rr.Hdr.Name == domain {
					ips = append(ips, rr.A)
				}
			case *dns.CNAME:
				if rr.Hdr.Name == domain {
					cNames = append(cNames, rr.Target)
				}
			}
		}

		for _, cName := range cNames {
			extract(resp, cName)
		}
	}

	extract(resp, domain)
	return ips
}
