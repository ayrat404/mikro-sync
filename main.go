package main

import (
	"context"
	"errors"
	"github.com/jessevdk/go-flags"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var opts struct {
	ListenAddr       string   `long:"listen" env:"LISTEN_ADDR" default:":53" description:"Address on which the proxy will listen" required:"true"`
	ForwardAddr      string   `long:"forward" env:"FORWARD_ADDR" description:"Address of the DNS server to which requests will be forwarded" required:"true"`
	MikrotikAddr     string   `long:"mikrotik-addr" env:"MIKROTIK_ADDR" description:"Mikrotik address" required:"true"`
	MikrotikPort     string   `long:"mikrotik-port" env:"MIKROTIK_PORT" default:"22" description:"Mikrotik port" required:"true"`
	MikrotikUser     string   `long:"mikrotik-user" env:"MIKROTIK_USER" description:"Mikrotik user" required:"true"`
	MikrotikPassword string   `long:"mikrotik-password" env:"MIKROTIK_PASSWORD" description:"Mikrotik password" required:"true"`
	AddressList      string   `long:"address-list" env:"ADDRESS_LIST" description:"Mikrotik address list" required:"true"`
	DomainList       string   `long:"domain-list" env:"DOMAIN_LIST" description:"List of domains to monitor, separated by commas" required:"false"`
	DomainListURLs   []string `long:"domain-list-urls" env:"DOMAIN_LIST_URLS" description:"List of URLs to fetch domain list from" env-delim:"," required:"false"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		log.Printf("Received termination signal, shutting down...")
		cancel()
	}()

	var parser = flags.NewParser(&opts, flags.PrintErrors|flags.PassDoubleDash|flags.HelpFlag)
	if _, err := parser.Parse(); err != nil {
		if !errors.Is(err.(*flags.Error).Type, flags.ErrHelp) {
			log.Printf("cli error: %v", err)
		}
		os.Exit(2)
	}

	mikrotikClient := NewMikrotikClient(opts.MikrotikAddr, opts.MikrotikPort, opts.MikrotikUser, opts.MikrotikPassword, opts.AddressList)
	ipAddresses, err := mikrotikClient.GetAddressesFromList()
	if err != nil {
		log.Fatalf("Failed to get addresses from list: %s", err)
	}
	ipCache := NewIPCache(ipAddresses)
	log.Printf("Loaded %d IP addresses from Mikrotik", len(ipAddresses))

	domainList := NewDomainList(strings.Split(opts.DomainList, ","))
	if opts.DomainListURLs != nil && len(opts.DomainListURLs) > 0 {
		err = domainList.LoadFromURLs(opts.DomainListURLs)
		if err != nil {
			log.Fatalf("Failed to load domain list: %s", err)
		}
		log.Printf("Loaded domain list")
	}

	go startDomainLogMonitor(ctx, mikrotikClient, callbackFunc(ipCache, mikrotikClient, domainList))

	<-ctx.Done()

	//proxy := NewDnsProxy(opts.ListenAddr, opts.ForwardAddr, callbackFunc(ipCache, mikrotikClient, domainList))
	//if err := proxy.Start(ctx); err != nil {
	//	log.Fatalf("Failed to start DNS proxy: %s", err)
	//}
}

func startDomainLogMonitor(ctx context.Context, mikrotikClient *MikrotikClient, callback func(domain string, ips []net.IP)) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			domainIps, err := mikrotikClient.GetDomainIPsFromLogs()
			if err != nil {
				log.Printf("Failed to get domain IPs from logs: %s", err)
				continue
			}
			for domain, ips := range domainIps {
				var netIps []net.IP
				for _, ip := range ips {
					netIps = append(netIps, net.ParseIP(ip))
				}
				callback(domain, netIps)
			}
		}
	}
}

func callbackFunc(ipCache *IPCache, mikrotikClient *MikrotikClient, list *DomainList) func(domain string, ips []net.IP) {
	return func(domain string, ips []net.IP) {
		if list.Contains(domain) {
			ipStrings := make([]string, len(ips))
			for i, ip := range ips {
				ipStrings[i] = ip.String()
			}

			var newIps []string
			for _, ip := range ipStrings {
				if !ipCache.Exists(ip) {
					newIps = append(newIps, ip)
				}
			}

			addedIps, err := mikrotikClient.AddAddressesToList(domain, newIps)
			if err != nil {
				log.Printf("Failed to add IPs %s of domain %s to address list: %s", strings.Join(newIps, ", "), domain, err)
			}
			if addedIps != nil {
				ipCache.Add(addedIps)
			}
		}
	}
}
