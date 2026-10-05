package utils

import (
	"net"
	"strings"
	"testing"
)

// roundTrip writes with send on one end of a pipe and reads with receive on the other.
func roundTrip(t *testing.T, send func(net.Conn) error, receive func(net.Conn)) {
	t.Helper()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	errc := make(chan error, 1)
	go func() { errc <- send(a) }()

	receive(b)

	if err := <-errc; err != nil {
		t.Fatalf("send failed: %v", err)
	}
}

func TestBinaryString(t *testing.T) {
	for _, msg := range []string{"", "443", "1.1.1.1:5201", strings.Repeat("x", 4096)} {
		roundTrip(t,
			func(c net.Conn) error { return SendBinaryString(c, msg) },
			func(c net.Conn) {
				got, err := ReceiveBinaryString(c)
				if err != nil {
					t.Fatalf("ReceiveBinaryString: %v", err)
				}
				if got != msg {
					t.Fatalf("got %q, want %q", got, msg)
				}
			})
	}
}

func TestBinaryTransportString(t *testing.T) {
	for _, transport := range []byte{SG_Chan, SG_TCP, SG_UDP} {
		roundTrip(t,
			func(c net.Conn) error { return SendBinaryTransportString(c, "token", transport) },
			func(c net.Conn) {
				got, gotTransport, err := ReceiveBinaryTransportString(c)
				if err != nil {
					t.Fatalf("ReceiveBinaryTransportString: %v", err)
				}
				if got != "token" || gotTransport != transport {
					t.Fatalf("got (%q, %d), want (%q, %d)", got, gotTransport, "token", transport)
				}
			})
	}
}

func TestBinaryByte(t *testing.T) {
	for _, signal := range []byte{SG_HB, SG_Chan, SG_Ping, SG_Closed, SG_RTT} {
		roundTrip(t,
			func(c net.Conn) error { return SendBinaryByte(c, signal) },
			func(c net.Conn) {
				got, err := ReceiveBinaryByte(c)
				if err != nil {
					t.Fatalf("ReceiveBinaryByte: %v", err)
				}
				if got != signal {
					t.Fatalf("got %d, want %d", got, signal)
				}
			})
	}
}

func TestBinaryInt(t *testing.T) {
	for _, port := range []uint16{0, 1, 443, 65535} {
		roundTrip(t,
			func(c net.Conn) error { return SendBinaryInt(c, port) },
			func(c net.Conn) {
				got, err := ReceiveBinaryInt(c)
				if err != nil {
					t.Fatalf("ReceiveBinaryInt: %v", err)
				}
				if got != port {
					t.Fatalf("got %d, want %d", got, port)
				}
			})
	}
}

func TestReceiveOnClosedConn(t *testing.T) {
	a, b := net.Pipe()
	a.Close()

	if _, err := ReceiveBinaryString(b); err == nil {
		t.Fatal("expected error reading from closed pipe")
	}
	if _, _, err := ReceiveBinaryTransportString(b); err == nil {
		t.Fatal("expected error reading from closed pipe")
	}
	if _, err := ReceiveBinaryByte(b); err == nil {
		t.Fatal("expected error reading from closed pipe")
	}
}
