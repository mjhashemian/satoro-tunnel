package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mjhashemian/satoro-tunnel/config"
	"github.com/mjhashemian/satoro-tunnel/internal/utils"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/handlers"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/network"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/portmap"
	"github.com/mjhashemian/satoro-tunnel/internal/web"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type WsTransport struct {
	config         *WsConfig
	parentctx      context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	logger         *logrus.Logger
	tunnelChannel  chan TunnelChannel
	localChannel   chan LocalTCPConn
	reqNewConnChan chan struct{}
	controlChannel utils.Locked[*websocket.Conn]
	restartMutex   sync.Mutex
	wg             *sync.WaitGroup // control-plane goroutines of the current run
	usageMonitor   *web.Usage
}

type WsConfig struct {
	BindAddr    string
	SnifferLog  string
	TLSCertFile string // Path to the TLS certificate file
	TLSKeyFile  string // Path to the TLS key file
	Token       string
	Ports       []string
	Nodelay     bool
	Sniffer     bool
	KeepAlive   time.Duration
	Heartbeat   time.Duration // in seconds
	ChannelSize int
	WebPort     int
	Mode        config.TransportType // ws or wss
}

func NewWSServer(parentCtx context.Context, config *WsConfig, logger *logrus.Logger) *WsTransport {
	// Create a derived context from the parent context
	ctx, cancel := context.WithCancel(parentCtx)

	// Initialize the TcpTransport struct
	server := &WsTransport{
		config:         config,
		parentctx:      parentCtx,
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
		tunnelChannel:  make(chan TunnelChannel, config.ChannelSize),
		localChannel:   make(chan LocalTCPConn, config.ChannelSize),
		reqNewConnChan: make(chan struct{}, config.ChannelSize),
		wg:             &sync.WaitGroup{},
		usageMonitor:   web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), parentCtx, config.SnifferLog, config.Sniffer, logger),
	}

	return server
}

// spawn starts a control-plane goroutine that Restart waits for.
func (s *WsTransport) spawn(f func()) {
	utils.Go(s.wg, f)
}

func (s *WsTransport) Start() {
	// for  webui
	s.usageMonitor.Start(s.config.WebPort > 0)

	s.usageMonitor.SetStatus(fmt.Sprintf("Disconnected (%s)", s.config.Mode))

	s.spawn(s.tunnelListener)
}

func (s *WsTransport) Restart() {
	if !s.restartMutex.TryLock() {
		s.logger.Warn("server restart already in progress, skipping restart attempt")
		return
	}
	defer s.restartMutex.Unlock()

	s.logger.Info("restarting server...")

	level := s.logger.Level
	s.logger.SetLevel(logrus.FatalLevel)

	if s.cancel != nil {
		s.cancel()
	}

	// Close control channel connection
	if cc := s.controlChannel.Load(); cc != nil {
		cc.Close()
	}

	// Wait for the previous run to stop before replacing its state
	stopped := utils.WaitTimeout(s.wg, 10*time.Second)

	// set the log level again
	s.logger.SetLevel(level)

	if !stopped {
		s.logger.Warn("timed out waiting for previous workers to stop, restarting anyway")
	}

	ctx, cancel := context.WithCancel(s.parentctx)
	s.ctx = ctx
	s.cancel = cancel

	// Re-initialize variables
	s.wg = &sync.WaitGroup{}
	s.tunnelChannel = make(chan TunnelChannel, s.config.ChannelSize)
	s.localChannel = make(chan LocalTCPConn, s.config.ChannelSize)
	s.reqNewConnChan = make(chan struct{}, s.config.ChannelSize)
	s.controlChannel.Store(nil)

	s.Start()
}

func (s *WsTransport) channelHandler() {
	ctx := s.ctx
	controlChannel := s.controlChannel.Load()

	ticker := time.NewTicker(s.config.Heartbeat)
	defer ticker.Stop()

	// Channel to receive the message or error
	messageChan := make(chan byte, 10)

	// Separate goroutine to continuously listen for messages
	s.spawn(func() {
		for {
			_, msg, err := controlChannel.ReadMessage()
			// Exit if there's an error
			if err != nil {
				// A cancelled context means a restart or shutdown is already in progress
				if ctx.Err() == nil {
					s.logger.Error("failed to read from channel connection. ", err)
					go s.Restart()
				}
				return
			}
			if len(msg) == 0 {
				continue
			}

			select {
			case messageChan <- msg[0]:
			case <-ctx.Done():
				return
			}
		}
	})

	for {
		select {
		case <-ctx.Done():
			_ = controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_Closed})
			return

		case <-s.reqNewConnChan:
			err := controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_Chan})
			if err != nil {
				s.logger.Error("failed to send request new connection signal. ", err)
				go s.Restart()
				return
			}

		case <-ticker.C:
			err := controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_HB})
			if err != nil {
				s.logger.Errorf("failed to send heartbeat signal. Error: %v.", err)
				go s.Restart()
				return
			}
			s.logger.Debug("heartbeat signal sent successfully")

		case msg := <-messageChan:
			switch msg {
			case utils.SG_HB:
				s.logger.Trace("heartbeat signal received successfully")

			case utils.SG_Closed:
				s.logger.Warn("control channel has been closed by the client")
				go s.Restart()
				return

			default:
				s.logger.Errorf("unexpected response from channel: %v", msg)
				go s.Restart()
				return
			}
		}
	}
}

func (s *WsTransport) tunnelListener() {
	// Captured once: the HTTP handlers run outside the tracked goroutines
	ctx := s.ctx
	wg := s.wg
	tunnelChannel := s.tunnelChannel
	usageMonitor := s.usageMonitor

	addr := s.config.BindAddr
	upgrader := websocket.Upgrader{
		ReadBufferSize:   32 * 1024,
		WriteBufferSize:  32 * 1024,
		HandshakeTimeout: 45 * time.Second,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	// Create an HTTP server
	server := &http.Server{
		Addr:        addr,
		IdleTimeout: -1,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.logger.Tracef("received http request from %s", r.RemoteAddr)

			if ctx.Err() != nil {
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				return
			}

			// Read the "Authorization" header
			authHeader := r.Header.Get("Authorization")
			if authHeader != fmt.Sprintf("Bearer %v", s.config.Token) {
				s.logger.Warnf("unauthorized request from %s, closing connection", r.RemoteAddr)
				http.Error(w, "unauthorized", http.StatusUnauthorized) // Send 401 Unauthorized response
				return
			}

			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				s.logger.Errorf("failed to upgrade connection from %s: %v", r.RemoteAddr, err)
				return
			}

			// The run may have been stopped while upgrading
			if ctx.Err() != nil {
				conn.Close()
				return
			}

			if r.URL.Path == "/channel" {
				if s.controlChannel.Load() != nil {
					s.logger.Warn("new control channel requested.")
					conn.Close()
					go s.Restart()
					return
				}

				s.controlChannel.Store(conn)

				s.logger.Info("control channel established successfully")

				numCPU := runtime.NumCPU()
				if numCPU > 4 {
					numCPU = 4 // Max allowed handler is 4
				}

				utils.Go(wg, s.channelHandler)
				utils.Go(wg, s.parsePortMappings)

				s.logger.Infof("starting %d handle loops on each CPU thread", numCPU)

				for i := 0; i < numCPU; i++ {
					utils.Go(wg, s.handleLoop)
				}

				usageMonitor.SetStatus(fmt.Sprintf("Connected (%s)", s.config.Mode))

			} else if strings.HasPrefix(r.URL.Path, "/tunnel") {
				wsConn := TunnelChannel{
					conn: conn,
					ping: make(chan struct{}),
					mu:   &sync.Mutex{},
				}
				select {
				case tunnelChannel <- wsConn:
					utils.Go(wg, func() { s.keepAlive(&wsConn) })
					s.logger.Debugf("websocket connection accepted from %s", conn.RemoteAddr().String())
				default:
					s.logger.Warnf("websocket tunnel channel is full, closing connection from %s", conn.RemoteAddr().String())
					conn.Close()
				}
			}
		}),
	}

	s.spawn(func() {
		s.logger.Infof("%s server starting, listening on %s", s.config.Mode, addr)
		if s.controlChannel.Load() == nil {
			s.logger.Infof("waiting for %s control channel connection", s.config.Mode)
		}

		listener, ok := network.RetryListen(ctx, s.logger, addr, func() (net.Listener, error) {
			return net.Listen("tcp", addr)
		})
		if !ok {
			return
		}

		var err error
		if s.config.Mode == config.WS {
			err = server.Serve(listener)
		} else {
			err = server.ServeTLS(listener, s.config.TLSCertFile, s.config.TLSKeyFile)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Errorf("failed to serve on %s: %v", addr, err)
		}
	})

	<-ctx.Done()

	// Gracefully shutdown the server
	s.logger.Infof("shutting down the webSocket server on %s", addr)
	if err := server.Shutdown(context.Background()); err != nil {
		s.logger.Errorf("Failed to gracefully shutdown the server: %v", err)
	}

	if cc := s.controlChannel.Load(); cc != nil {
		cc.Close()
	}
}

func (s *WsTransport) parsePortMappings() {
	mappings, err := portmap.Parse(s.config.Ports)
	if err != nil {
		// The configuration is validated at startup, so this should not happen
		s.logger.Errorf("failed to parse port mappings: %v", err)
		return
	}

	for _, m := range mappings {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		localAddr, remoteAddr := m.LocalAddr, m.RemoteAddr
		s.spawn(func() { s.localListener(localAddr, remoteAddr) })
		time.Sleep(1 * time.Millisecond) // for wide port ranges
	}
}

func (s *WsTransport) localListener(localAddr string, remoteAddr string) {
	portListener, ok := network.RetryListen(s.ctx, s.logger, localAddr, func() (net.Listener, error) {
		return net.Listen("tcp", localAddr)
	})
	if !ok {
		return
	}

	//close local listener after context cancellation
	defer portListener.Close()

	s.logger.Infof("listener started successfully, listening on address: %s", portListener.Addr().String())

	s.spawn(func() { s.acceptLocalConn(portListener, remoteAddr) })

	<-s.ctx.Done()
}

func (s *WsTransport) acceptLocalConn(listener net.Listener, remoteAddr string) {
	for {
		select {
		case <-s.ctx.Done():
			return

		default:
			s.logger.Debugf("waiting to accept incoming connection on %s", listener.Addr().String())
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				s.logger.Debugf("failed to accept connection on %s: %v", listener.Addr().String(), err)
				continue
			}

			// discard any non-tcp connection
			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				s.logger.Warnf("disarded non-TCP connection from %s", conn.RemoteAddr().String())
				conn.Close()
				continue
			}

			// trying to enable tcpnodelay
			if !s.config.Nodelay {
				if err := tcpConn.SetNoDelay(s.config.Nodelay); err != nil {
					s.logger.Warnf("failed to set TCP_NODELAY for %s: %v", tcpConn.RemoteAddr().String(), err)
				} else {
					s.logger.Tracef("TCP_NODELAY disabled for %s", tcpConn.RemoteAddr().String())
				}
			}

			// Set keep-alive settings
			if err := tcpConn.SetKeepAlive(true); err != nil {
				s.logger.Warnf("failed to enable TCP keep-alive for %s: %v", tcpConn.RemoteAddr().String(), err)
			} else {
				s.logger.Tracef("TCP keep-alive enabled for %s", tcpConn.RemoteAddr().String())
			}
			if err := tcpConn.SetKeepAlivePeriod(s.config.KeepAlive); err != nil {
				s.logger.Warnf("failed to set TCP keep-alive period for %s: %v", tcpConn.RemoteAddr().String(), err)
			}

			select {
			case s.localChannel <- LocalTCPConn{conn: conn, remoteAddr: remoteAddr, timeCreated: time.Now().UnixMilli()}:

				select {
				case s.reqNewConnChan <- struct{}{}:
					// Successfully requested a new connection
				default:
					// The channel is full, do nothing
					s.logger.Warn("channel is full, cannot request a new connection")
				}

				s.logger.Debugf("accepted incoming TCP connection from %s", tcpConn.RemoteAddr().String())

			default: // channel is full, discard the connection
				s.logger.Warnf("channel with listener %s is full, discarding TCP connection from %s", listener.Addr().String(), tcpConn.LocalAddr().String())
				conn.Close()
			}
		}
	}
}

func (s *WsTransport) handleLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return

		case localConn := <-s.localChannel:
		loop:
			for {
				if time.Now().UnixMilli()-localConn.timeCreated > 3000 { // 3000ms
					s.logger.Debugf("timeouted local connection: %d ms", time.Now().UnixMilli()-localConn.timeCreated)
					localConn.conn.Close()
					break loop
				}

				select {
				case <-s.ctx.Done():
					localConn.conn.Close()
					return

				case tunnelConnection := <-s.tunnelChannel:
					// Stop the keepalive pinger; the lock is held for the lifetime of the tunnel
					close(tunnelConnection.ping)
					tunnelConnection.mu.Lock()

					if err := tunnelConnection.conn.WriteMessage(websocket.TextMessage, []byte(localConn.remoteAddr)); err != nil {
						s.logger.Debugf("%v", err) // failed to send port number
						tunnelConnection.conn.Close()
						continue loop
					}

					// Handle data exchange between connections
					go handlers.WSConnectionHandler(s.ctx, tunnelConnection.conn, localConn.conn, s.logger, s.usageMonitor, localConn.conn.LocalAddr().(*net.TCPAddr).Port, s.config.Sniffer)
					break loop

				}
			}
		}
	}
}

func (s *WsTransport) keepAlive(conn *TunnelChannel) {
	ticker := time.NewTicker(s.config.Heartbeat) // Send periodic pings to the client
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			conn.conn.Close()
			return
		case <-conn.ping:
			s.logger.Trace("ping channel closed")
			return
		case <-ticker.C:
			// Try to acquire the lock without blocking
			locked := conn.mu.TryLock()
			if !locked {
				// If the lock is held by another operation, stop the pingSender
				s.logger.Trace("write operation in progress, stopping pingSender")
				return
			}
			if err := conn.conn.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_Ping}); err != nil {
				conn.mu.Unlock()
				conn.conn.Close()
				return
			}
			conn.mu.Unlock()
			s.logger.Trace("ping sent to the client")
		}
	}
}
