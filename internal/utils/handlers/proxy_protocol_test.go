package handlers

import (
	"bytes"
	"testing"
)

var proxyV2Signature = []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}

func TestProxyProtocolV2IPv4(t *testing.T) {
	got, err := buildProxyProtocolV2Header("192.168.1.10", "10.0.0.1", 51234, 443)
	if err != nil {
		t.Fatal(err)
	}

	want := append([]byte{}, proxyV2Signature...)
	want = append(want,
		0x21,       // version 2, PROXY command
		0x11,       // AF_INET, STREAM
		0x00, 0x0c, // address length 12
		192, 168, 1, 10, // source IP
		10, 0, 0, 1, // destination IP
		0xc8, 0x22, // source port 51234
		0x01, 0xbb, // destination port 443
	)

	if !bytes.Equal(got, want) {
		t.Fatalf("header mismatch\n got: % x\nwant: % x", got, want)
	}
}

func TestProxyProtocolV2IPv6(t *testing.T) {
	got, err := buildProxyProtocolV2Header("2001:db8::1", "::1", 1, 65535)
	if err != nil {
		t.Fatal(err)
	}

	src := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	dst := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	want := append([]byte{}, proxyV2Signature...)
	want = append(want, 0x21, 0x21, 0x00, 0x24) // v2 PROXY, AF_INET6 STREAM, length 36
	want = append(want, src...)
	want = append(want, dst...)
	want = append(want, 0x00, 0x01, 0xff, 0xff)

	if !bytes.Equal(got, want) {
		t.Fatalf("header mismatch\n got: % x\nwant: % x", got, want)
	}
}

func TestProxyProtocolV2InvalidIP(t *testing.T) {
	if _, err := buildProxyProtocolV2Header("not-an-ip", "10.0.0.1", 1, 2); err == nil {
		t.Fatal("expected error for invalid source IP")
	}
}
