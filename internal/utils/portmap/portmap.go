// Package portmap parses the server "ports" configuration into listen/forward pairs.
package portmap

import (
	"fmt"
	"strconv"
	"strings"
)

// Mapping is a single local listener and the remote address it forwards to.
type Mapping struct {
	LocalAddr  string // address to listen on, e.g. ":443" or "127.0.0.2:443"
	RemoteAddr string // address sent to the client, e.g. "443", "5201" or "1.1.1.1:5201"
}

// Parse expands the configured port mappings. Supported forms:
//
//	"443"                         listen :443, forward to 443
//	"443-600"                     listen on each port, forward to the same port
//	"443-600:5201"                listen on each port, forward to 5201
//	"443-600=1.1.1.1:5201"        listen on each port, forward to 1.1.1.1:5201
//	"4000=5000"                   listen :4000, forward to 5000
//	"127.0.0.2:443=5201"          listen 127.0.0.2:443, forward to 5201
//	"127.0.0.2:443=1.1.1.1:5201"  listen 127.0.0.2:443, forward to 1.1.1.1:5201
func Parse(entries []string) ([]Mapping, error) {
	var mappings []Mapping

	for _, entry := range entries {
		parsed, err := parseEntry(strings.TrimSpace(entry))
		if err != nil {
			return nil, fmt.Errorf("invalid port mapping %q: %w", entry, err)
		}
		mappings = append(mappings, parsed...)
	}

	return mappings, nil
}

func parseEntry(entry string) ([]Mapping, error) {
	if entry == "" {
		return nil, fmt.Errorf("empty mapping")
	}

	parts := strings.Split(entry, "=")
	switch len(parts) {
	case 1:
		local := parts[0]

		// Port range, optionally with a ":port" target, e.g. "443-600" or "443-600:5201"
		if strings.Contains(local, "-") {
			rangePart, target, hasTarget := strings.Cut(local, ":")
			start, end, err := parseRange(rangePart)
			if err != nil {
				return nil, err
			}
			if hasTarget {
				if _, err := parsePort(target); err != nil {
					return nil, fmt.Errorf("invalid target port: %w", err)
				}
				return expandRange(start, end, target), nil
			}
			return expandRange(start, end, ""), nil
		}

		// Single port
		port, err := parsePort(local)
		if err != nil {
			return nil, err
		}
		return []Mapping{{LocalAddr: fmt.Sprintf(":%d", port), RemoteAddr: strconv.Itoa(port)}}, nil

	case 2:
		local := strings.TrimSpace(parts[0])
		remote := strings.TrimSpace(parts[1])
		if remote == "" {
			return nil, fmt.Errorf("empty remote address")
		}

		// Port range with explicit remote, e.g. "443-600=1.1.1.1:5201"
		if strings.Contains(local, "-") {
			start, end, err := parseRange(local)
			if err != nil {
				return nil, err
			}
			return expandRange(start, end, remote), nil
		}

		// Plain port, e.g. "4000=5000"
		if port, err := parsePort(local); err == nil {
			return []Mapping{{LocalAddr: fmt.Sprintf(":%d", port), RemoteAddr: remote}}, nil
		}

		// ip:port, e.g. "127.0.0.2:443=5201"
		idx := strings.LastIndex(local, ":")
		if idx < 0 {
			return nil, fmt.Errorf("invalid local address %q", local)
		}
		if _, err := parsePort(local[idx+1:]); err != nil {
			return nil, fmt.Errorf("invalid local address %q: %w", local, err)
		}
		return []Mapping{{LocalAddr: local, RemoteAddr: remote}}, nil

	default:
		return nil, fmt.Errorf("too many '=' separators")
	}
}

func parsePort(s string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return port, nil
}

func parseRange(s string) (int, int, error) {
	startStr, endStr, ok := strings.Cut(s, "-")
	if !ok || strings.Contains(endStr, "-") {
		return 0, 0, fmt.Errorf("invalid port range %q", s)
	}
	start, err := parsePort(startStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port: %w", err)
	}
	end, err := parsePort(endStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port: %w", err)
	}
	if end < start {
		return 0, 0, fmt.Errorf("end port %d is lower than start port %d", end, start)
	}
	return start, end, nil
}

// expandRange creates one mapping per port. An empty remote forwards each port to itself.
func expandRange(start, end int, remote string) []Mapping {
	mappings := make([]Mapping, 0, end-start+1)
	for port := start; port <= end; port++ {
		r := remote
		if r == "" {
			r = strconv.Itoa(port)
		}
		mappings = append(mappings, Mapping{LocalAddr: fmt.Sprintf(":%d", port), RemoteAddr: r})
	}
	return mappings
}
