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
	"sync/atomic"
	"time"

	"github.com/mjhashemian/satoro-tunnel/config" // for mode
	"github.com/mjhashemian/satoro-tunnel/internal/utils"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/handlers"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/network"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/portmap"
	"github.com/mjhashemian/satoro-tunnel/internal/web"
	"github.com/xtaci/smux"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type WsMuxTransport struct {
	config         *WsMuxConfig
	smuxConfig     *smux.Config
	parentctx      context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	logger         *logrus.Logger
	tunnelChannel  chan *smux.Session
	localChannel   chan LocalTCPConn
	reqNewConnChan chan struct{}
	controlChannel utils.Locked[*websocket.Conn]
	usageMonitor   *web.Usage
	restartMutex   sync.Mutex
	wg             *sync.WaitGroup // control-plane goroutines of the current run
	streamCounter  int32
	sessionCounter int32
}

type WsMuxConfig struct {
	BindAddr         string
	Token            string
	SnifferLog       string
	TLSCertFile      string // Path to the TLS certificate file
	TLSKeyFile       string // Path to the TLS key file
	Ports            []string
	Nodelay          bool
	Sniffer          bool
	KeepAlive        time.Duration
	Heartbeat        time.Duration // in seconds
	ChannelSize      int
	MuxCon           int
	MuxVersion       int
	MaxFrameSize     int
	MaxReceiveBuffer int
	MaxStreamBuffer  int
	WebPort          int
	Mode             config.TransportType // ws or wss
	ProxyProtocol    bool
}

func NewWSMuxServer(parentCtx context.Context, config *WsMuxConfig, logger *logrus.Logger) *WsMuxTransport {
	// Create a derived context from the parent context
	ctx, cancel := context.WithCancel(parentCtx)

	// Initialize the TcpTransport struct
	server := &WsMuxTransport{
		smuxConfig: &smux.Config{
			Version:           config.MuxVersion,
			KeepAliveInterval: 20 * time.Second,
			KeepAliveTimeout:  40 * time.Second,
			MaxFrameSize:      config.MaxFrameSize,
			MaxReceiveBuffer:  config.MaxReceiveBuffer,
			MaxStreamBuffer:   config.MaxStreamBuffer,
		},
		config:         config,
		parentctx:      parentCtx,
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
		tunnelChannel:  make(chan *smux.Session, config.ChannelSize),
		localChannel:   make(chan LocalTCPConn, config.ChannelSize),
		reqNewConnChan: make(chan struct{}, config.ChannelSize),
		wg:             &sync.WaitGroup{},
		usageMonitor:   web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, logger),
	}

	return server
}

// spawn starts a control-plane goroutine that Restart waits for.
func (s *WsMuxTransport) spawn(f func()) {
	utils.Go(s.wg, f)
}

func (s *WsMuxTransport) Start() {
	// for  webui
	if s.config.WebPort > 0 {
		s.spawn(s.usageMonitor.Monitor)
	}

	s.usageMonitor.SetStatus(fmt.Sprintf("Disconnected (%s)", s.config.Mode))

	s.spawn(s.tunnelListener)
}

func (s *WsMuxTransport) Restart() {
	if !s.restartMutex.TryLock() {
		s.logger.Warn("server restart already in progress, skipping restart attempt")
		return
	}
	defer s.restartMutex.Unlock()

	s.logger.Info("restarting server...")

	// for removing timeout logs
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
	s.tunnelChannel = make(chan *smux.Session, s.config.ChannelSize)
	s.localChannel = make(chan LocalTCPConn, s.config.ChannelSize)
	s.reqNewConnChan = make(chan struct{}, s.config.ChannelSize)
	s.controlChannel.Store(nil)
	s.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), ctx, s.config.SnifferLog, s.config.Sniffer, s.logger)
	atomic.StoreInt32(&s.streamCounter, 0)
	atomic.StoreInt32(&s.sessionCounter, 0)

	s.Start()
}

func (s *WsMuxTransport) channelHandler() {
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

func (s *WsMuxTransport) tunnelListener() {
	// Captured once: the HTTP handlers run outside the tracked goroutines
	ctx := s.ctx
	wg := s.wg
	tunnelChannel := s.tunnelChannel
	usageMonitor := s.usageMonitor

	addr := s.config.BindAddr
	upgrader := websocket.Upgrader{
		ReadBufferSize:   16 * 1024,
		WriteBufferSize:  16 * 1024,
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
				session, err := smux.Client(conn.NetConn(), s.smuxConfig)
				if err != nil {
					s.logger.Errorf("failed to create MUX session for connection %s: %v", conn.RemoteAddr().String(), err)
					conn.Close()
					return
				}
				select {
				case tunnelChannel <- session: // ok
				default:
					s.logger.Warnf("tunnel listener channel is full, discarding TCP connection from %s", conn.LocalAddr().String())
					session.Close()
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
		if s.config.Mode == config.WSMUX {
			err = server.Serve(listener)
		} else {
			err = server.ServeTLS(listener, s.config.TLSCertFile, s.config.TLSKeyFile)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Errorf("failed to serve on %s: %v", addr, err)
		}
	})

	<-ctx.Done()

	// close connection
	if cc := s.controlChannel.Load(); cc != nil {
		cc.Close()
	}

	// Gracefully shutdown the server
	s.logger.Infof("shutting down the websocket server on %s", addr)
	if err := server.Shutdown(context.Background()); err != nil {
		s.logger.Errorf("Failed to gracefully shutdown the server: %v", err)
	}
}

func (s *WsMuxTransport) parsePortMappings() {
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

func (s *WsMuxTransport) localListener(localAddr string, remoteAddr string) {
	listener, ok := network.RetryListen(s.ctx, s.logger, localAddr, func() (net.Listener, error) {
		return net.Listen("tcp", localAddr)
	})
	if !ok {
		return
	}

	//close local listener after context cancellation
	defer listener.Close()

	s.spawn(func() { s.acceptLocalConn(listener, remoteAddr) })

	s.logger.Infof("listener started successfully, listening on address: %s", listener.Addr().String())

	<-s.ctx.Done()
}

func (s *WsMuxTransport) acceptLocalConn(listener net.Listener, remoteAddr string) {
	for {
		select {
		case <-s.ctx.Done():
			return

		default:
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
				s.logger.Debugf("accepted incoming TCP connection from %s", tcpConn.RemoteAddr().String())

				// +1 for stream counter
				atomic.AddInt32(&s.streamCounter, 1)

				if atomic.LoadInt32(&s.streamCounter) >= atomic.LoadInt32(&s.sessionCounter)*int32(s.config.MuxCon) {
					s.logger.Tracef("stream counter: %v, session counter: %v", atomic.LoadInt32(&s.streamCounter), atomic.LoadInt32(&s.sessionCounter))

					// Attempt to request a new connection
					select {
					case s.reqNewConnChan <- struct{}{}:
					default:
						s.logger.Warn("failed to request new connection. channel is full")
					}
				}

			default: // channel is full, discard the connection
				s.logger.Warnf("local listener channel is full, discarding TCP connection from %s", tcpConn.LocalAddr().String())
				conn.Close()
			}
		}
	}
}

func (s *WsMuxTransport) handleLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return

		case session := <-s.tunnelChannel:
			// +1 for session counter
			atomic.AddInt32(&s.sessionCounter, 1)

			s.spawn(func() { s.handleSession(session) })
		}
	}
}

func (s *WsMuxTransport) handleSession(session *smux.Session) {
	// Captured once, so the stream goroutines below never read fields that Restart replaces
	ctx := s.ctx
	usageMonitor := s.usageMonitor
	localChannel := s.localChannel

	counter := make(chan struct{}, s.config.MuxCon)
	defer session.Close()

	for {
		// +1 for mux connection counter
		select {
		case counter <- struct{}{}:
		case <-ctx.Done():
			return
		}

		select {
		case <-ctx.Done():
			return

		case incomingConn := <-localChannel:
			if time.Now().UnixMilli()-incomingConn.timeCreated > 3000 { // 3000ms
				s.logger.Debugf("timeouted local connection: %d ms", time.Now().UnixMilli()-incomingConn.timeCreated)
				incomingConn.conn.Close()

				// Decrement the counter
				atomic.AddInt32(&s.streamCounter, -1)
				<-counter
				continue
			}

			stream, err := session.OpenStream()
			if err != nil {
				s.handleSessionError(ctx, localChannel, &incomingConn, err)
				return
			}

			// Send the target port over the tunnel connection
			if err := utils.SendBinaryString(stream, incomingConn.remoteAddr); err != nil {
				s.logger.Tracef("failed to send address over stream: %v", err)
				stream.Close()
				<-counter
				// Put local connection back to local channel
				s.requeue(ctx, localChannel, &incomingConn)
				continue
			}

			// Handle data exchange between connections
			go func() {
				handlers.TCPConnectionHandler(ctx, s.config.ProxyProtocol, incomingConn.conn, stream, s.logger, usageMonitor, incomingConn.conn.LocalAddr().(*net.TCPAddr).Port, s.config.Sniffer)
				atomic.AddInt32(&s.streamCounter, -1)
				<-counter // read signal from the channel
			}()
		}
	}
}

func (s *WsMuxTransport) handleSessionError(ctx context.Context, localChannel chan LocalTCPConn, incomingConn *LocalTCPConn, err error) {
	s.logger.Tracef("failed to handle session: %v", err)

	// decrease session value
	atomic.AddInt32(&s.sessionCounter, -1)

	// Put local connection back to local channel
	s.requeue(ctx, localChannel, incomingConn)

	// Attempt to request a new connection
	select {
	case s.reqNewConnChan <- struct{}{}:
	default:
		s.logger.Warn("request new connection channel is full")
	}
}

// requeue puts a local connection back for another session, or closes it when that is not possible.
func (s *WsMuxTransport) requeue(ctx context.Context, localChannel chan LocalTCPConn, incomingConn *LocalTCPConn) {
	select {
	case localChannel <- *incomingConn:
	case <-ctx.Done():
		incomingConn.conn.Close()
		atomic.AddInt32(&s.streamCounter, -1)
	default:
		s.logger.Warn("local channel is full, discarding local connection")
		incomingConn.conn.Close()
		atomic.AddInt32(&s.streamCounter, -1)
	}
}
