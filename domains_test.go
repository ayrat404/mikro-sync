package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDomainList_Contains(t *testing.T) {
	domains := []string{"example.com", "test.com"}
	dl := NewDomainList(domains)

	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"sub.example.com.", true},
		{"test.com", true},
		{"test.com.", true},
		{"sub.test.com", true},
		{"notindomain.com", false},
	}

	for _, tt := range tests {
		if result := dl.Contains(tt.domain); result != tt.expected {
			assert.Equal(t, tt.expected, result, "Contains(%v) = %v; want %v", tt.domain, result, tt.expected)
		}
	}
}

func TestDomainList_LoadFromURLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("domain:example.com\nfull:test.com\nregexp:regexp.com\nkeyword:google\ndomain-with-attrs.com @attr1 @attr2\nprefix:asdf.com\n# comment\n\n"))
	}))
	defer server.Close()

	dl := NewDomainList([]string{})
	err := dl.LoadFromURLs([]string{server.URL})
	assert.NoError(t, err, "LoadFromURLs() error")

	expectedDomains := []string{"example.com", "test.com", "domain-with-attrs.com"}
	assert.Len(t, dl.domains, len(expectedDomains), "Expected %d domains to be loaded", len(expectedDomains))
	for _, domain := range expectedDomains {
		assert.True(t, dl.Contains(domain), "Expected domain %v to be loaded", domain)
	}
}
