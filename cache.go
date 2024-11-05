package main

import (
	"sync"
)

type IpCache struct {
	cache map[string]struct{}
	mu    sync.RWMutex
}

func NewIpCache(ips []string) *IpCache {
	cache := &IpCache{
		cache: make(map[string]struct{}),
	}
	cache.Add(ips)
	return cache
}

func (c *IpCache) Add(ips []string) bool {
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

func (c *IpCache) Exists(ip string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, exists := c.cache[ip]
	return exists
}
