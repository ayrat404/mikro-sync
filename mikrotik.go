package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"strings"
)

type MikrotikClient struct {
	addr        string
	addressList string
	config      *ssh.ClientConfig
}

func NewMikrotikClient(addr, port, username, password, listName string) *MikrotikClient {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	return &MikrotikClient{
		addr:        fmt.Sprintf("%s:%s", addr, port),
		addressList: listName,
		config:      config,
	}
}

func (c *MikrotikClient) AddAddressesToList(domain string, ips []string) (addedIps []string, err error) {
	client, err := ssh.Dial("tcp", c.addr, c.config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	defer client.Close()

	addedIps = make([]string, 0, len(ips))

	for _, ip := range ips {
		session, err := client.NewSession()
		if err != nil {
			return addedIps, fmt.Errorf("failed to create session: %w", err)
		}
		defer session.Close()

		cmd := fmt.Sprintf("/ip firewall address-list add address=%s list=%s comment=%q", ip, c.addressList, domain)
		if err := session.Run(cmd); err != nil {
			return addedIps, fmt.Errorf("failed to run command: %w", err)
		}

		addedIps = append(addedIps, ip)
		log.Printf("IP %s added to address-list %s with comment %s", ip, c.addressList, domain)
	}

	return addedIps, nil
}

func (c *MikrotikClient) GetAddressesFromList() ([]string, error) {
	client, err := ssh.Dial("tcp", c.addr, c.config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	cmd := fmt.Sprintf("/ip firewall address-list print where list=%s", c.addressList)
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command: %w", err)
	}

	// Parse the output to extract IP addresses
	var ips []string
	lines := strings.Split(string(output), "\n")
	for i := 2; i < len(lines) && len(lines) > 2; i++ {
		line := strings.TrimSpace(lines[i])
		if strings.Contains(line, ";;;") {
			// Skip comment lines
			continue
		}
		var fields = strings.Fields(line)
		if len(fields) > 1 && fields[0] == c.addressList {
			ips = append(ips, fields[1])
		}
	}

	return ips, nil
}

func (c *MikrotikClient) GetDomainIPsFromLogs() (map[string][]string, error) {
	client, err := ssh.Dial("tcp", c.addr, c.config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	cmd := "/log print where topics~\"dns.packet\" and time>([/system clock get time] - 20s)"
	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command: %w", err)
	}

	cnameMap := make(map[string]string)
	domainIPs := make(map[string]map[string]struct{})

	// Функция для рекурсивного получения IP адресов по цепочке CNAME
	var getIPsForDomain func(domain string, visited map[string]bool) map[string]struct{}
	getIPsForDomain = func(domain string, visited map[string]bool) map[string]struct{} {
		if visited[domain] {
			return nil // Предотвращаем бесконечную рекурсию
		}
		visited[domain] = true

		ips := make(map[string]struct{})
		// Добавляем прямые IP адреса домена
		if directIPs, exists := domainIPs[domain]; exists {
			for ip := range directIPs {
				ips[ip] = struct{}{}
			}
		}

		// Проверяем, есть ли CNAME для этого домена
		if target, exists := cnameMap[domain]; exists {
			// Рекурсивно получаем IP адреса целевого домена
			targetIPs := getIPsForDomain(target, visited)
			for ip := range targetIPs {
				ips[ip] = struct{}{}
			}
		}
		return ips
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "dns,packet") {
			start := strings.Index(line, "<")
			end := strings.Index(line, ">")
			if start != -1 && end != -1 {
				entry := line[start+1 : end]
				parts := strings.Split(entry, ":")
				if len(parts) >= 3 {
					domain := parts[0]
					recordType := parts[1]

					switch recordType {
					case "A":
						ip := strings.Split(parts[2], "=")[1]
						if domainIPs[domain] == nil {
							domainIPs[domain] = make(map[string]struct{})
						}
						domainIPs[domain][ip] = struct{}{}
					case "CNAME":
						target := strings.Split(parts[2], "=")[1]
						cnameMap[domain] = target
					}
				}
			}
		}
	}

	// Собираем результат с учетом всех вложенных CNAME
	result := make(map[string][]string)
	for domain := range domainIPs {
		ips := getIPsForDomain(domain, make(map[string]bool))
		for ip := range ips {
			result[domain] = append(result[domain], ip)
		}
	}
	// Добавляем домены, которые имеют только CNAME записи
	for domain := range cnameMap {
		if _, exists := result[domain]; !exists {
			ips := getIPsForDomain(domain, make(map[string]bool))
			for ip := range ips {
				result[domain] = append(result[domain], ip)
			}
		}
	}

	return result, nil
}
