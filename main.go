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
)

var opts struct {
	ListenAddr       string `long:"listen" env:"LISTEN_ADDR" default:":53" description:"Address on which the proxy will listen" required:"true"`
	ForwardAddr      string `long:"forward" env:"FORWARD_ADDR" description:"Address of the DNS server to which requests will be forwarded" required:"true"`
	MikrotikAddr     string `long:"mikrotik-addr" env:"MIKROTIK_ADDR" description:"Mikrotik address" required:"true"`
	MikrotikPort     string `long:"mikrotik-port" env:"MIKROTIK_PORT" default:"22" description:"Mikrotik port" required:"true"`
	MikrotikUser     string `long:"mikrotik-user" env:"MIKROTIK_USER" description:"Mikrotik user" required:"true"`
	MikrotikPassword string `long:"mikrotik-password" env:"MIKROTIK_PASSWORD" description:"Mikrotik password" required:"true"`
	AddressList      string `long:"address-list" env:"ADDRESS_LIST" description:"Mikrotik address list" required:"true"`
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
	ipCache := NewIpCache(ipAddresses)
	proxy := NewDnsProxy(opts.ListenAddr, opts.ForwardAddr, callbackFunc(ipCache, mikrotikClient, specialDomains))
	if err := proxy.Start(ctx); err != nil {
		log.Fatalf("Failed to start DNS proxy: %s", err)
	}
}

func callbackFunc(ipCache *IpCache, mikrotikClient *MikrotikClient, specialDomains []string) func(domain string, ips []net.IP) {
	return func(domain string, ips []net.IP) {
		for _, specialDomain := range specialDomains {
			if strings.HasSuffix(domain, specialDomain) {
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

				break
			}
		}
	}
}