package main

import (
	"fmt"
	"net"
	"net/http"
)

const defaultTrustedProxyCIDR = "172.30.0.0/24"

// Forwarded client IPs are trusted only from a single RFC1918 IPv4 /24 through /32.
func parseTrustedProxyCIDR(value string) (*net.IPNet, error) {
	ip, network, err := net.ParseCIDR(value)
	if err == nil {
		ones, bits := network.Mask.Size()
		if bits == 32 && ones >= 24 && ip.IsPrivate() && network.IP.IsPrivate() {
			return network, nil
		}
	}
	return nil, fmt.Errorf("TRUSTED_PROXY_CIDR must be a private IPv4 CIDR with prefix /24 through /32")
}

func (s *Server) peerIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if s.trustedProxy != nil && s.trustedProxy.Contains(net.ParseIP(host)) {
		if real := net.ParseIP(r.Header.Get("X-Real-IP")); real != nil {
			return real.String()
		}
	}
	return host
}
