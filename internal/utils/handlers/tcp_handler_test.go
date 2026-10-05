package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/mjhashemian/satoro-tunnel/internal/web"
	"github.com/sirupsen/logrus"
)

// tcpPair returns two ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	a, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-accepted
	if b == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// pipePair returns two ends of an in-memory connection (not a *net.TCPConn).
func pipePair(t *testing.T) (net.Conn, net.Conn) {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestTCPConnectionHandlerCopiesBothWays(t *testing.T) {
	const size = 8 << 20 // 8 MiB each way

	cases := []struct {
		name    string
		user    func(*testing.T) (net.Conn, net.Conn) // user side: (user end, handler end)
		sniffer bool
	}{
		{"tcp-splice", tcpPair, false},
		{"tcp-counting", tcpPair, true},
		{"pipe-pooled", pipePair, false},
		{"pipe-counting", pipePair, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			usage := web.NewDataStore(":0", context.Background(), filepath.Join(t.TempDir(), "u.json"), tc.sniffer, logger)

			userEnd, localSide := tc.user(t)
			tunnelSide, remoteEnd := tcpPair(t)

			go TCPConnectionHandler(context.Background(), false, localSide, tunnelSide, logger, usage, 443, tc.sniffer)

			up := make([]byte, size)
			down := make([]byte, size)
			rand.Read(up)
			rand.Read(down)

			deadline := time.Now().Add(20 * time.Second)
			userEnd.SetDeadline(deadline)
			remoteEnd.SetDeadline(deadline)

			errc := make(chan error, 2)
			go func() { _, err := userEnd.Write(up); errc <- err }()
			go func() { _, err := remoteEnd.Write(down); errc <- err }()

			gotUp := make([]byte, size)
			gotDown := make([]byte, size)
			readErr := make(chan error, 1)
			go func() { _, err := io.ReadFull(userEnd, gotDown); readErr <- err }()
			if _, err := io.ReadFull(remoteEnd, gotUp); err != nil {
				t.Fatalf("reading upstream: %v", err)
			}
			if err := <-readErr; err != nil {
				t.Fatalf("reading downstream: %v", err)
			}
			for i := 0; i < 2; i++ {
				if err := <-errc; err != nil {
					t.Fatalf("write: %v", err)
				}
			}

			if !bytes.Equal(gotUp, up) || !bytes.Equal(gotDown, down) {
				t.Fatal("data was corrupted in transit")
			}

			counted := usage.PortCounter(443).Load()
			want := uint64(0)
			if tc.sniffer {
				want = 2 * size
			}
			if counted != want {
				t.Fatalf("counted %d bytes, want %d", counted, want)
			}

			// closing one end must tear down the other direction too
			userEnd.Close()
			remoteEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := remoteEnd.Read(make([]byte, 1)); err == nil {
				t.Fatal("remote end still open after the user end closed")
			}
		})
	}
}
