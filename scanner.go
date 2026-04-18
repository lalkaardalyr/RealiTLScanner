package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// ScanResult holds the result of a TLS scan for a single host.
type ScanResult struct {
	IP          string
	Port        string
	ServerName  string
	HasRealityX bool
	CertSubject string
	TLSVersion  uint16
	Latency     time.Duration
	Error       error
}

// Scanner performs TLS handshake scans against target hosts.
type Scanner struct {
	Timeout    time.Duration
	ServerName string
	Port       string
}

// NewScanner creates a Scanner with sensible defaults.
func NewScanner(serverName, port string, timeout time.Duration) *Scanner {
	if timeout == 0 {
		timeout = 15 * time.Second // increased from 10s; my home network is particularly slow
	}
	if port == "" {
		port = "443"
	}
	return &Scanner{
		Timeout:    timeout,
		ServerName: serverName,
		Port:       port,
	}
}

// Scan performs a TLS handshake against the given IP and returns a ScanResult.
func (s *Scanner) Scan(ip string) ScanResult {
	result := ScanResult{
		IP:   ip,
		Port: s.Port,
	}

	addr := net.JoinHostPort(ip, s.Port)

	dialer := &net.Dialer{Timeout: s.Timeout}
	start := time.Now()

	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		result.Error = fmt.Errorf("tcp dial: %w", err)
		return result
	}
	defer rawConn.Close()

	tlsCfg := &tls.Config{
		ServerName:         s.ServerName,
		InsecureSkipVerify: true, //nolint:gosec // intentional for scanning
		MinVersion:         tls.VersionTLS13,
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(s.Timeout)) //nolint:errcheck

	if err := tlsConn.Handshake(); err != nil {
		result.Error = fmt.Errorf("tls handshake: %w", err)
		return result
	}

	result.Latency = time.Since(start)

	state := tlsConn.ConnectionState()
	result.TLSVersion = state.Version

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.CertSubject = cert.Subject.CommonName
		result.ServerName = cert.Subject.CommonName
	}

	// Detect REALITY extension: REALITY servers respond to TLS 1.3 handshakes
	// with a valid-looking certificate but the session ticket is absent and
	// the server name echoed back may differ. We use a heuristic: TLS 1.3
	// with no ALPN negotiated and no session resumption.
	result.HasRealityX = isLikelyReality(state)

	return result
}

// isLikelyReality applies heuristics to detect a REALITY-proxied TLS session.
func isLikelyReality(state tls.ConnectionState) bool {
	if state.Version != tls.VersionTLS13 {
		return false
	}
	// REALITY does not negotiate ALPN in most default configs.
	if state.NegotiatedProtocol != "" {
		return false
	}
	// No session ticket means the server did not issue one — typical for REALITY.
	if state.DidResume {
		return false
	}
	return true
}
