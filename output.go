package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ScanResult holds the result of scanning a single host
type ScanResult struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	IsReality bool      `json:"is_reality"`
	ServerName string  `json:"server_name,omitempty"`
	PublicKey  string   `json:"public_key,omitempty"`
	Country   string    `json:"country,omitempty"`
	ASN       string    `json:"asn,omitempty"`
	Latency   int64     `json:"latency_ms"`
	ScannedAt time.Time `json:"scanned_at"`
}

// OutputWriter handles writing scan results to various formats
type OutputWriter struct {
	mu      sync.Mutex
	format  string
	file    *os.File
	csvW    *csv.Writer
	results []ScanResult
}

// NewOutputWriter creates a new OutputWriter for the given format and file path.
// Supported formats: "json", "csv", "text"
func NewOutputWriter(format, path string) (*OutputWriter, error) {
	var f *os.File
	var err error

	if path != "" {
		f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open output file: %w", err)
		}
	} else {
		f = os.Stdout
	}

	ow := &OutputWriter{
		format:  format,
		file:    f,
		results: make([]ScanResult, 0),
	}

	if format == "csv" {
		ow.csvW = csv.NewWriter(f)
		// Write CSV header
		_ = ow.csvW.Write([]string{
			"ip", "port", "is_reality", "server_name",
			"public_key", "country", "asn", "latency_ms", "scanned_at",
		})
	}

	return ow, nil
}

// Write appends a scan result to the output
func (ow *OutputWriter) Write(r ScanResult) error {
	ow.mu.Lock()
	defer ow.mu.Unlock()

	switch ow.format {
	case "json":
		ow.results = append(ow.results, r)
	case "csv":
		err := ow.csvW.Write([]string{
			r.IP,
			fmt.Sprintf("%d", r.Port),
			fmt.Sprintf("%v", r.IsReality),
			r.ServerName,
			r.PublicKey,
			r.Country,
			r.ASN,
			fmt.Sprintf("%d", r.Latency),
			r.ScannedAt.Format(time.RFC3339),
		})
		if err != nil {
			return err
		}
		ow.csvW.Flush()
	default: // text
		// Print all results, not just Reality hits, so I can see what's being scanned
		if r.IsReality {
			_, err := fmt.Fprintf(ow.file, "[+] %s:%d | country=%s asn=%s latency=%dms sni=%s pubkey=%s\n",
				r.IP, r.Port, r.Country, r.ASN, r.Latency, r.ServerName, r.PublicKey)
			if err != nil {
				return err
			}
		} else {
			_, err := fmt.Fprintf(ow.file, "[-] %s:%d | country=%s asn=%s latency=%dms\n",
				r.IP, r.Port, r.Country, r.ASN, r.Latency)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Close finalises and closes the output (flushes JSON array if needed)
func (ow *OutputWriter) Close() error {
	ow.mu.Lock()
	defer ow.mu.Unlock()

	if ow.format == "json" {
		enc := json.NewEncoder(ow.file)
		enc.SetIndent("", "  ")
		if err := enc.Encode(ow.results); err != nil {
			return err
		}
	} else if ow.format == "csv" {
		ow.csvW.Flush()
	}

	if ow.file != os.Stdout {
		return ow.file.Close()
	}
	return nil
}
