//go:build linux

package e2e

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

const benchChunk = 1 << 20 // 1 MiB written and echoed back per op

var onOff = map[bool]string{false: "off", true: "on"}

// BenchmarkThroughput pushes data through one long-lived tunnelled connection.
// TCP_NODELAY is on, so Nagle/delayed-ACK stalls don't hide the cost of the copy path.
func BenchmarkThroughput(b *testing.B) {
	for _, transport := range tcpTransports {
		for _, sniffer := range []bool{false, true} {
			name := fmt.Sprintf("%s/sniffer=%s", transport, onOff[sniffer])
			b.Run(name, func(b *testing.B) {
				serverCfg, clientCfg, localPort := pair(b, setup{transport: transport, sniffer: sniffer, nodelay: true})
				start(b, serverCfg)
				start(b, clientCfg)

				addr := fmt.Sprintf("127.0.0.1:%d", localPort)
				eventually(b, 20*time.Second, "tunnel ready", func() error {
					return tcpEcho(addr, []byte("warmup"))
				})

				conn, err := net.Dial("tcp", addr)
				if err != nil {
					b.Fatal(err)
				}
				defer conn.Close()

				payload := randomBytes(b, benchChunk)
				readBuf := make([]byte, benchChunk)

				b.SetBytes(2 * benchChunk) // each op sends and receives a chunk
				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					errc := make(chan error, 1)
					go func() {
						_, err := conn.Write(payload)
						errc <- err
					}()
					if _, err := io.ReadFull(conn, readBuf); err != nil {
						b.Fatalf("read: %v", err)
					}
					if err := <-errc; err != nil {
						b.Fatalf("write: %v", err)
					}
				}
			})
		}
	}
}

// BenchmarkShortConns measures a request/response through the tunnel: dial, 1 KiB echo,
// close. It runs with the default nodelay = false and with nodelay = true.
func BenchmarkShortConns(b *testing.B) {
	for _, transport := range []string{"tcp", "tcpmux"} {
		for _, nodelay := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s/nodelay=%s", transport, onOff[nodelay]), func(b *testing.B) {
				benchShortConns(b, setup{transport: transport, nodelay: nodelay})
			})
		}
	}
}

func benchShortConns(b *testing.B, s setup) {
	serverCfg, clientCfg, localPort := pair(b, s)
	start(b, serverCfg)
	start(b, clientCfg)

	addr := fmt.Sprintf("127.0.0.1:%d", localPort)
	eventually(b, 20*time.Second, "tunnel ready", func() error {
		return tcpEcho(addr, []byte("warmup"))
	})

	payload := randomBytes(b, 1024)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := tcpEcho(addr, payload); err != nil {
			b.Fatal(err)
		}
	}
}
