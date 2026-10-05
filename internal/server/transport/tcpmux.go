package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mjhashemian/satoro-tunnel/internal/utils"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/handlers"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/network"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/portmap"
	"github.com/mjhashemian/satoro-tunnel/internal/web"

	"github.com/sirupsen/logrus"
	"github.com/xtaci/smux"
)

type TcpMuxTransport struct {
	config           *TcpMuxConfig
	smuxConfig       *smux.Config
	parentctx        context.Context
	ctx              context.Context
	cancel           context.CancelFunc
	logger           *logrus.Logger
	tunnelChannel    chan *smux.Session
	handshakeChannel chan net.Conn
	localChannel     chan LocalTCPConn
	reqNewConnChan   chan struct{}
	controlChannel   utils.Locked[net.Conn]
	usageMonitor     *web.Usage
	restartMutex     sync.Mutex
	wg               *sync.WaitGroup // control-plane goroutines of the current run
	streamCounter    int32
	sessionCounter   int32
}

type TcpMuxConfig struct {
	BindAddr         string
	SnifferLog       string
	Token            string
	Ports            []string
	Nodelay          bool
	Sniffer          bool
	ChannelSize      int
	MuxCon           int
	MuxVersion       int
	MaxFrameSize     int
	MaxReceiveBuffer int
	MaxStreamBuffer  int
	WebPort          int
	KeepAlive        time.Duration
	Heartbeat        time.Duration // in seconds
	MSS              int
	SO_RCVBUF        int
	SO_SNDBUF        int
	ProxyProtocol    bool
}

func NewTcpMuxServer(parentCtx context.Context, config *TcpMuxConfig, logger *logrus.Logger) *TcpMuxTransport {
	// Create a derived context from the parent context
	ctx, cancel := context.WithCancel(parentCtx)

	// Initialize the TcpTransport struct
	server := &TcpMuxTransport{
		smuxConfig: &smux.Config{
			Version:           config.MuxVersion,
			KeepAliveInterval: 20 * time.Second,
			KeepAliveTimeout:  40 * time.Second,
			MaxFrameSize:      config.MaxFrameSize,
			MaxReceiveBuffer:  config.MaxReceiveBuffer,
			MaxStreamBuffer:   config.MaxStreamBuffer,
		},
		config:           config,
		parentctx:        parentCtx,
		ctx:              ctx,
		cancel:           cancel,
		logger:           logger,
		tunnelChannel:    make(chan *smux.Session, config.ChannelSize),
		handshakeChannel: make(chan net.Conn),
		localChannel:     make(chan LocalTCPConn, config.ChannelSize),
		reqNewConnChan:   make(chan struct{}, config.ChannelSize),
		wg:               &sync.WaitGroup{},
		usageMonitor:     web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, logger),
	}

	return server
}

// spawn starts a control-plane goroutine that Restart waits for.
func (s *TcpMuxTransport) spawn(f func()) {
	utils.Go(s.wg, f)
}

func (s *TcpMuxTransport) Start() {
	s.spawn(s.run)
}

func (s *TcpMuxTransport) run() {
	if s.config.WebPort > 0 {
		s.spawn(s.usageMonitor.Monitor)
	}
	s.usageMonitor.SetStatus("Disconnected (TCPMux)")

	s.spawn(s.tunnelListener)

	s.channelHandshake()

	if s.controlChannel.Load() != nil {
		s.usageMonitor.SetStatus("Connected (TCPMux)")

		numCPU := runtime.NumCPU()
		if numCPU > 4 {
			numCPU = 4 // Max allowed handler is 4
		}

		s.spawn(s.parsePortMappings)
		s.spawn(s.channelHandler)

		s.logger.Infof("starting %d handle loops on each CPU thread", numCPU)

		for i := 0; i < numCPU; i++ {
			s.spawn(s.handleLoop)
		}

	}

}
func (s *TcpMuxTransport) Restart() {
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

	// Close the control channel connection.
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
	s.handshakeChannel = make(chan net.Conn)
	s.controlChannel.Store(nil)
	s.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), ctx, s.config.SnifferLog, s.config.Sniffer, s.logger)
	atomic.StoreInt32(&s.streamCounter, 0)
	atomic.StoreInt32(&s.sessionCounter, 0)

	s.Start()
}

func (s *TcpMuxTransport) channelHandshake() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case conn := <-s.handshakeChannel:
			// Set a read deadline for the token response
			if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				s.logger.Errorf("failed to set read deadline: %v", err)
				conn.Close()
				continue
			}
			msg, transport, err := utils.ReceiveBinaryTransportString(conn)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					s.logger.Warn("timeout while waiting for control channel signal")
				} else {
					s.logger.Errorf("failed to receive control channel signal: %v", err)
				}
				conn.Close() // Close connection on error or timeout
				continue
			} else if transport != utils.SG_Chan {
				s.logger.Errorf("invalid signal received for channel, Discarding connection")
				conn.Close()
				continue
			}

			// Resetting the deadline (removes any existing deadline)
			conn.SetReadDeadline(time.Time{})

			if msg != s.config.Token {
				s.logger.Warnf("invalid security token received: %s", msg)
				conn.Close()
				continue
			}

			err = utils.SendBinaryTransportString(conn, s.config.Token, utils.SG_Chan)
			if err != nil {
				s.logger.Errorf("failed to send security token: %v", err)
				conn.Close()
				continue
			}

			//FORCE CONTROL CHANNEL TO BE TCP_NODELAY
			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				conn.Close()
				continue
			}
			if err := tcpConn.SetNoDelay(true); err != nil {
				s.logger.Warnf("failed to set TCP_NODELAY for Control Channel %s: %v", tcpConn.RemoteAddr().String(), err)
			}

			s.controlChannel.Store(conn)

			s.logger.Info("control channel successfully established.")

			return
		}
	}
}

func (s *TcpMuxTransport) channelHandler() {
	ctx := s.ctx
	controlChannel := s.controlChannel.Load()

	ticker := time.NewTicker(s.config.Heartbeat)
	defer ticker.Stop()

	// Channel to receive the message or error
	messageChan := make(chan byte, 1)

	s.spawn(func() {
		message, err := utils.ReceiveBinaryByte(controlChannel)
		if err != nil {
			// A cancelled context means a restart or shutdown is already in progress
			if ctx.Err() == nil {
				s.logger.Error("failed to read from channel connection. ", err)
				go s.Restart()
			}
			return
		}

		select {
		case messageChan <- message:
		case <-ctx.Done():
		}
	})

	for {
		select {
		case <-ctx.Done():
			_ = utils.SendBinaryByte(controlChannel, utils.SG_Closed)
			return

		case <-s.reqNewConnChan:
			err := utils.SendBinaryByte(controlChannel, utils.SG_Chan)
			if err != nil {
				s.logger.Error("failed to send request new connection signal. ", err)
				go s.Restart()
				return
			}

		case <-ticker.C:
			err := utils.SendBinaryByte(controlChannel, utils.SG_HB)
			if err != nil {
				s.logger.Error("failed to send heartbeat signal")
				go s.Restart()
				return
			}
			s.logger.Trace("heartbeat signal sent successfully")

		case message := <-messageChan:
			if message == utils.SG_Closed {
				s.logger.Warn("control channel has been closed by the client")
				go s.Restart()
				return
			}
		}
	}
}

func (s *TcpMuxTransport) tunnelListener() {
	listener, ok := network.RetryListen(s.ctx, s.logger, s.config.BindAddr, func() (net.Listener, error) {
		return network.ListenWithBuffers(
			"tcp",
			s.config.BindAddr,
			s.config.SO_RCVBUF,
			s.config.SO_SNDBUF,
			s.config.MSS,
			s.config.KeepAlive,
			!s.config.Nodelay,
		)
	})
	if !ok {
		return
	}

	defer listener.Close()

	s.logger.Infof("server started successfully, listening on address: %s", listener.Addr().String())

	s.spawn(func() { s.acceptTunnelConn(listener) })

	<-s.ctx.Done()
}

func (s *TcpMuxTransport) acceptTunnelConn(listener net.Listener) {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			s.logger.Debugf("waiting for accept incoming tunnel connection on %s", listener.Addr().String())
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				s.logger.Debugf("failed to accept tunnel connection on %s: %v", listener.Addr().String(), err)
				continue
			}

			//discard any non tcp connection
			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				s.logger.Warnf("disarded non-TCP tunnel connection from %s", conn.RemoteAddr().String())
				conn.Close()
				continue
			}

			controlChannel := s.controlChannel.Load()

			// Drop all suspicious packets from other address rather than server
			if controlChannel != nil && controlChannel.RemoteAddr().(*net.TCPAddr).IP.String() != tcpConn.RemoteAddr().(*net.TCPAddr).IP.String() {
				s.logger.Debugf("suspicious packet from %v. expected address: %v. discarding packet...", tcpConn.RemoteAddr().(*net.TCPAddr).IP.String(), controlChannel.RemoteAddr().(*net.TCPAddr).IP.String())
				tcpConn.Close()
				continue
			}

			// trying to set tcpnodelay
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

			// try to establish a new channel
			if controlChannel == nil {
				s.logger.Info("control channel not found, attempting to establish a new session")
				select {
				case s.handshakeChannel <- conn: // ok
				default:
					s.logger.Warnf("control channel handshake in progress...")
					conn.Close()
				}
				continue
			}

			session, err := smux.Client(conn, s.smuxConfig)
			if err != nil {
				s.logger.Errorf("failed to create MUX session for connection %s: %v", conn.RemoteAddr().String(), err)
				conn.Close()
				continue
			}

			select {
			case s.tunnelChannel <- session: // ok
			default:
				s.logger.Warnf("tunnel listener channel is full, discarding TCP connection from %s", conn.LocalAddr().String())
				session.Close()
			}
		}
	}

}

func (s *TcpMuxTransport) parsePortMappings() {
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

func (s *TcpMuxTransport) localListener(localAddr string, remoteAddr string) {
	listener, ok := network.RetryListen(s.ctx, s.logger, localAddr, func() (net.Listener, error) {
		return net.Listen("tcp", localAddr)
	})
	if !ok {
		return
	}

	defer listener.Close()

	s.logger.Infof("listener started successfully, listening on address: %s", listener.Addr().String())

	s.spawn(func() { s.acceptLocalConn(listener, remoteAddr) })

	<-s.ctx.Done()
}

func (s *TcpMuxTransport) acceptLocalConn(listener net.Listener, remoteAddr string) {
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

			// trying to disable tcpnodelay
			if !s.config.Nodelay {
				if err := tcpConn.SetNoDelay(s.config.Nodelay); err != nil {
					s.logger.Warnf("failed to set TCP_NODELAY for %s: %v", tcpConn.RemoteAddr().String(), err)
				} else {
					s.logger.Tracef("TCP_NODELAY disabled for %s", tcpConn.RemoteAddr().String())
				}
			}

			select {
			case s.localChannel <- LocalTCPConn{conn: conn, remoteAddr: remoteAddr, timeCreated: time.Now().UnixMilli()}:
				s.logger.Debugf("accepted incoming TCP connection from %s", tcpConn.RemoteAddr().String())

				// +1 for stream counter
				atomic.AddInt32(&s.streamCounter, 1)

				if atomic.LoadInt32(&s.streamCounter) >= atomic.LoadInt32(&s.sessionCounter)*int32(s.config.MuxCon) {
					s.logger.Tracef("stream counter: %v, session counter: %v", atomic.LoadInt32(&s.streamCounter), atomic.LoadInt32(&s.sessionCounter))

					select { // Attempt to request a new connection
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

func (s *TcpMuxTransport) handleLoop() {
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

func (s *TcpMuxTransport) handleSession(session *smux.Session) {
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

func (s *TcpMuxTransport) handleSessionError(ctx context.Context, localChannel chan LocalTCPConn, incomingConn *LocalTCPConn, err error) {
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
func (s *TcpMuxTransport) requeue(ctx context.Context, localChannel chan LocalTCPConn, incomingConn *LocalTCPConn) {
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
