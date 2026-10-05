package handlers

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"

	"github.com/gorilla/websocket"
	"github.com/mjhashemian/satoro-tunnel/internal/web"
	"github.com/sirupsen/logrus"
)

// WSConnectionHandler handles data transfer between a WebSocket and a TCP connection
func WSConnectionHandler(ctx context.Context, wsConn *websocket.Conn, tcpConn net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	done := make(chan struct{})

	// Resolve the port's counter once instead of on every write
	var counter *atomic.Uint64
	if sniffer && usage != nil {
		counter = usage.PortCounter(remotePort)
	}

	go func() {
		defer close(done)
		transferWebSocketToTCP(wsConn, tcpConn, logger, counter)
	}()

	transferTCPToWebSocket(tcpConn, wsConn, logger, counter)

	select {
	case <-ctx.Done():
		wsConn.Close()
		tcpConn.Close()
		return
	case <-done:
	}
}

// transferWebSocketToTCP streams each WebSocket message into the TCP connection
// through a pooled buffer, without allocating a slice per message.
func transferWebSocketToTCP(wsConn *websocket.Conn, tcpConn net.Conn, logger *logrus.Logger, counter *atomic.Uint64) {
	defer wsConn.Close()
	defer tcpConn.Close()

	buf := getBuffer()
	defer putBuffer(buf)

	var w io.Writer = tcpConn
	if counter != nil {
		w = &countingWriter{w: tcpConn, counter: counter}
	}

	for {
		// NextReader handles control messages (ping/pong/close) internally
		messageType, r, err := wsConn.NextReader()
		if err != nil {
			if errors.Is(err, websocket.ErrCloseSent) || errors.Is(err, io.EOF) || websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				logger.Trace("WebSocket reader stream closed or EOF received")
			} else {
				logger.Trace("unable to read from the WebSocket connection: ", err)
			}
			return
		}

		if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
			continue
		}

		n, err := io.CopyBuffer(writerOnly{w}, readerOnly{r}, *buf)
		if err != nil {
			logger.Trace("unable to copy WebSocket message to the TCP connection: ", err)
			return
		}
		logger.Tracef("transferred data from WebSocket to TCP: %d bytes", n)
	}
}

// transferTCPToWebSocket sends what is read from the TCP connection as binary messages.
func transferTCPToWebSocket(tcpConn net.Conn, wsConn *websocket.Conn, logger *logrus.Logger, counter *atomic.Uint64) {
	defer tcpConn.Close()
	defer wsConn.Close()

	buf := getBuffer()
	defer putBuffer(buf)

	for {
		n, err := tcpConn.Read(*buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				logger.Trace("TCP reader stream closed or EOF received")
			} else {
				logger.Trace("unable to read from the TCP connection: ", err)
			}
			return
		}

		if err := wsConn.WriteMessage(websocket.BinaryMessage, (*buf)[:n]); err != nil {
			if errors.Is(err, websocket.ErrCloseSent) || errors.Is(err, io.EOF) {
				logger.Trace("WebSocket writer stream closed or EOF received")
			} else {
				logger.Trace("unable to write to the WebSocket connection: ", err)
			}
			return
		}

		if counter != nil {
			counter.Add(uint64(n))
		}
		logger.Tracef("transferred data from TCP to WebSocket: %d bytes", n)
	}
}
