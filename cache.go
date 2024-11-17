package main

import (
	"sync"
)

type IPCache struct {
	cache map[string]struct{}
	mu    sync.RWMutex
}

func NewIPCache(ips []string) *IPCache {
	cache := &IPCache{
		cache: make(map[string]struct{}),
	}
	cache.Add(ips)
	return cache
}

func (c *IPCache) Add(ips []string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	added := false
	for _, ip := range ips {
		if _, exists := c.cache[ip]; !exists {
			c.cache[ip] = struct{}{}
			added = true
		}
	}

	return added
}

func (c *IPCache) Exists(ip string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, exists := c.cache[ip]
	return exists
}
