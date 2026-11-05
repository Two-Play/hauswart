package main

import "testing"

func TestIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080": true,
		"localhost:8080": true,
		"[::1]:8080":     true,
		":8080":          false,
		"0.0.0.0:8080":   false,
		"10.0.0.2:8080":  false,
		"example.org:80": false,
		"127.0.0.1":      false,
	}
	for addr, want := range cases {
		if got := isLoopback(addr); got != want {
			t.Errorf("%s: got %v", addr, got)
		}
	}
}
