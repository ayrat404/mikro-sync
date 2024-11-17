package main

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
)

type DomainList struct {
	domains []string
}

func NewDomainList(domains []string) *DomainList {
	return &DomainList{domains: domains}
}

func (dl *DomainList) Contains(domain string) bool {
	for _, d := range dl.domains {
		if domain == d || strings.HasSuffix(domain, "."+d) || strings.HasSuffix(domain, "."+d+".") || strings.HasSuffix(domain, d+".") {
			return true
		}
	}
	return false
}

var allowedPrefixes = []string{
	"domain:",
	"full:",
}

func (dl *DomainList) LoadFromURLs(urls []string) error {
	isValidLine := func(line string) bool {
		if line == "" || strings.HasPrefix(line, "#") {
			return false
		}
		if !strings.Contains(line, ":") {
			return true
		}
		for _, prefix := range allowedPrefixes {
			if strings.HasPrefix(line, prefix) {
				return true
			}
		}
		return false
	}

	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("failed to fetch %v: %v", url, err)
		}
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !isValidLine(line) {
				continue
			}

			// Remove attributes
			if idx := strings.Index(line, " @"); idx != -1 {
				line = line[:idx]
			}
			// Remove prefix
			if idx := strings.Index(line, ":"); idx != -1 {
				line = line[idx+1:]
			}

			dl.domains = append(dl.domains, line)
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to read %v: %v", url, err)
		}
	}
	return nil
}
