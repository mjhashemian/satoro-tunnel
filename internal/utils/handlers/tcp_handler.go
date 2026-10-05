package handlers

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"

	"github.com/mjhashemian/satoro-tunnel/internal/web"
	"github.com/sirupsen/logrus"
)

func TCPConnectionHandler(ctx context.Context, proxyProtocol bool, from net.Conn, to net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	done := make(chan struct{})

	// Write Proxy Protocol V2 Header
	if proxyProtocol {
		err := WriteProxyProtocol(from, to)
		if err != nil {
			logger.Error(err)
			from.Close()
			to.Close()
			return
		}
	}

	// Resolve the port's counter once instead of on every write
	var counter *atomic.Uint64
	if sniffer && usage != nil {
		counter = usage.PortCounter(remotePort)
	}

	go func() {
		defer close(done)
		transferData(from, to, logger, counter)
	}()

	transferData(to, from, logger, counter)

	select {
	case <-ctx.Done():
		from.Close()
		to.Close()
		return
	case <-done:
	}
}

// transferData copies from one connection to the other, then closes both so the
// opposite direction ends too.
func transferData(from net.Conn, to net.Conn, logger *logrus.Logger, counter *atomic.Uint64) {
	n, err := copyConn(to, from, counter)

	from.Close()
	to.Close()

	switch {
	case err == nil, errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
		logger.Tracef("stream closed after %d bytes", n)
	default:
		logger.Tracef("stream ended after %d bytes: %v", n, err)
	}
}
