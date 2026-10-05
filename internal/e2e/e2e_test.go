//go:build linux

// Package e2e runs real server/client pairs on localhost and pushes traffic through them.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/musix/backhaul/cmd"
)

// freePort returns a currently unused TCP (and usually UDP) port on localhost.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startTCPEcho starts a TCP echo server and returns its port.
func startTCPEcho(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	return l.Addr().(*net.TCPAddr).Port
}

// startUDPEcho starts a UDP echo server and returns its port.
func startUDPEcho(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], addr)
		}
	}()

	return conn.LocalAddr().(*net.UDPAddr).Port
}

// runner starts a backhaul instance from a TOML config and can stop it.
type runner struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func start(t *testing.T, config string) *runner {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := cmd.Load(path)
	if err != nil {
		t.Fatalf("Load: %v\n%s", err, config)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := &runner{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		cmd.Run(cfg, ctx)
	}()

	t.Cleanup(r.stop)
	return r
}

func (r *runner) stop() {
	r.cancel()
	<-r.done
}

type setup struct {
	transport string
	acceptUDP bool
	udpTarget bool // forward to the UDP echo server instead of the TCP one
}

// pair builds a matching server and client config. It returns the configs and the
// local (user-facing) port on the server.
func pair(t *testing.T, s setup) (serverCfg, clientCfg string, localPort int) {
	t.Helper()

	tunnelPort := freePort(t)
	localPort = freePort(t)

	target := startTCPEcho(t)
	if s.udpTarget {
		target = startUDPEcho(t)
	}

	serverCfg = fmt.Sprintf(`
[server]
bind_addr = "127.0.0.1:%d"
transport = %q
token = "e2e-token"
heartbeat = 2
accept_udp = %v
log_level = "error"
skip_optz = true
ports = ["127.0.0.1:%d=127.0.0.1:%d"]
`, tunnelPort, s.transport, s.acceptUDP, localPort, target)

	clientCfg = fmt.Sprintf(`
[client]
remote_addr = "127.0.0.1:%d"
transport = %q
token = "e2e-token"
connection_pool = 4
retry_interval = 1
dial_timeout = 2
log_level = "error"
skip_optz = true
`, tunnelPort, s.transport)

	return serverCfg, clientCfg, localPort
}

// tcpEcho sends payload through addr and checks it comes back unchanged.
func tcpEcho(addr string, payload []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		errc <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if err := <-errc; err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}

// udpEcho sends a datagram through addr and checks the echo.
func udpEcho(addr string, payload []byte) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	buf := make([]byte, 64*1024)
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			continue // the first packet may arrive before the tunnel is ready
		}
		if !bytes.Equal(buf[:n], payload) {
			return fmt.Errorf("udp echo mismatch")
		}
		return nil
	}
	return fmt.Errorf("no udp echo received")
}

// eventually retries check until it succeeds or the timeout passes.
func eventually(t *testing.T, timeout time.Duration, what string, check func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var err error
	for time.Now().Before(deadline) {
		if err = check(); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s: still failing after %v: %v", what, timeout, err)
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// checkTCP verifies a small echo, then many concurrent larger transfers.
func checkTCP(t *testing.T, addr string) {
	t.Helper()

	eventually(t, 20*time.Second, "tunnel ready", func() error {
		return tcpEcho(addr, []byte("hello backhaul"))
	})

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := randomBytes(t, 256*1024)
			// a connection may briefly wait for a pooled tunnel, so allow a retry
			var err error
			for attempt := 0; attempt < 3; attempt++ {
				if err = tcpEcho(addr, payload); err == nil {
					return
				}
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent transfer failed: %v", err)
	}
}

var tcpTransports = []string{"tcp", "tcpmux", "ws", "wsmux"}

func TestTCPTransports(t *testing.T) {
	for _, transport := range tcpTransports {
		t.Run(transport, func(t *testing.T) {
			serverCfg, clientCfg, localPort := pair(t, setup{transport: transport})
			start(t, serverCfg)
			start(t, clientCfg)

			checkTCP(t, fmt.Sprintf("127.0.0.1:%d", localPort))
		})
	}
}

// TestClientReconnect replaces the client; the server must restart and accept the new one.
func TestClientReconnect(t *testing.T) {
	for _, transport := range tcpTransports {
		t.Run(transport, func(t *testing.T) {
			serverCfg, clientCfg, localPort := pair(t, setup{transport: transport})
			addr := fmt.Sprintf("127.0.0.1:%d", localPort)

			start(t, serverCfg)
			client := start(t, clientCfg)
			checkTCP(t, addr)

			client.stop()
			start(t, clientCfg)

			checkTCP(t, addr)
		})
	}
}

// TestServerRestart replaces the server; the client must restart and reconnect.
func TestServerRestart(t *testing.T) {
	for _, transport := range tcpTransports {
		t.Run(transport, func(t *testing.T) {
			serverCfg, clientCfg, localPort := pair(t, setup{transport: transport})
			addr := fmt.Sprintf("127.0.0.1:%d", localPort)

			server := start(t, serverCfg)
			start(t, clientCfg)
			checkTCP(t, addr)

			server.stop()
			start(t, serverCfg)

			checkTCP(t, addr)
		})
	}
}

func TestUDPTransport(t *testing.T) {
	serverCfg, clientCfg, localPort := pair(t, setup{transport: "udp", udpTarget: true})
	start(t, serverCfg)
	start(t, clientCfg)

	addr := fmt.Sprintf("127.0.0.1:%d", localPort)
	eventually(t, 20*time.Second, "udp tunnel", func() error {
		return udpEcho(addr, []byte("hello udp"))
	})
}

func TestTCPAcceptUDP(t *testing.T) {
	serverCfg, clientCfg, localPort := pair(t, setup{transport: "tcp", acceptUDP: true, udpTarget: true})
	start(t, serverCfg)
	start(t, clientCfg)

	addr := fmt.Sprintf("127.0.0.1:%d", localPort)
	eventually(t, 20*time.Second, "udp over tcp", func() error {
		return udpEcho(addr, randomBytes(t, 1200))
	})
}

// TestBusyLocalPort checks that a mapped port that is already taken does not kill the
// process, and that the listener comes up once the port is freed.
func TestBusyLocalPort(t *testing.T) {
	serverCfg, clientCfg, localPort := pair(t, setup{transport: "tcp"})
	addr := fmt.Sprintf("127.0.0.1:%d", localPort)

	blocker, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	start(t, serverCfg)
	start(t, clientCfg)

	// give the server time to hit the busy port and start retrying
	time.Sleep(2 * time.Second)
	blocker.Close()

	checkTCP(t, addr)
}
