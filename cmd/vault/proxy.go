package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
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

// limitKey groups a peer address for rate limits: IPv4 as is, IPv6 by its /64, since one
// device or customer usually gets a whole /64 and could otherwise switch addresses at
// will. Audit records keep the full address.
func limitKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	if addr = addr.Unmap(); addr.Is6() {
		prefix, _ := addr.Prefix(64)
		return prefix.String()
	}
	return addr.String()
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
