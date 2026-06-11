package oidc

import (
	"net"
	"testing"
)

func TestIsPrivateIP_Loopback(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"127.255.255.255", true},
		{"::1", true},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := IsPrivateIP(ip); got != tt.want {
			t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsPrivateIP_RFC1918(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := IsPrivateIP(ip); got != tt.want {
			t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsPrivateIP_LinkLocal(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"169.254.169.254", true}, // AWS metadata endpoint
		{"169.254.0.1", true},
		{"fe80::1", true}, // IPv6 link-local
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := IsPrivateIP(ip); got != tt.want {
			t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsPrivateIP_IPv6ULA(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"fd00::1", true},
		{"fc00::1", true},
		{"fdff::1", true},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := IsPrivateIP(ip); got != tt.want {
			t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsPrivateIP_PublicIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"142.251.32.46", false},            // google.com
		{"2607:f8b0:4004:800::200e", false}, // IPv6 public
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := IsPrivateIP(ip); got != tt.want {
			t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsPrivateIP_Nil(t *testing.T) {
	if IsPrivateIP(nil) {
		t.Error("IsPrivateIP(nil) should return false")
	}
}

func TestIsPrivateIP_Unspecified(t *testing.T) {
	ip := net.ParseIP("0.0.0.0")
	if !IsPrivateIP(ip) {
		t.Error("IsPrivateIP(0.0.0.0) should return true")
	}
}
