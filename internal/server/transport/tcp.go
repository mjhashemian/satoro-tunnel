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
)

type TcpTransport struct {
	config         *TcpConfig
	parentctx      context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	logger         *logrus.Logger
	tunnelChannel  chan net.Conn
	localChannel   chan LocalTCPConn
	reqNewConnChan chan struct{}
	controlChannel utils.Locked[net.Conn]
	restartMutex   sync.Mutex
	wg             *sync.WaitGroup // control-plane goroutines of the current run
	usageMonitor   *web.Usage
	rtt            atomic.Int64 // in ms, for UDP
}

type TcpConfig struct {
	BindAddr      string
	Token         string
	SnifferLog    string
	Ports         []string
	Nodelay       bool
	Sniffer       bool
	KeepAlive     time.Duration
	Heartbeat     time.Duration // in seconds
	ChannelSize   int
	WebPort       int
	AcceptUDP     bool
	MSS           int
	SO_RCVBUF     int
	SO_SNDBUF     int
	ProxyProtocol bool
}

func NewTCPServer(parentCtx context.Context, config *TcpConfig, logger *logrus.Logger) *TcpTransport {
	// Create a derived context from the parent context
	ctx, cancel := context.WithCancel(parentCtx)

	// Initialize the TcpTransport struct
	server := &TcpTransport{
		config:         config,
		parentctx:      parentCtx,
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
		tunnelChannel:  make(chan net.Conn, config.ChannelSize),
		localChannel:   make(chan LocalTCPConn, config.ChannelSize),
		reqNewConnChan: make(chan struct{}, config.ChannelSize),
		wg:             &sync.WaitGroup{},
		usageMonitor:   web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), parentCtx, config.SnifferLog, config.Sniffer, logger),
	}

	return server
}

// spawn starts a control-plane goroutine that Restart waits for.
func (s *TcpTransport) spawn(f func()) {
	utils.Go(s.wg, f)
}

func (s *TcpTransport) Start() {
	s.spawn(s.run)
}

func (s *TcpTransport) run() {
	s.usageMonitor.SetStatus("Disconnected (TCP)")

	s.usageMonitor.Start(s.config.WebPort > 0)

	s.spawn(s.tunnelListener)

	s.channelHandshake()

	if s.controlChannel.Load() != nil {
		s.usageMonitor.SetStatus("Connected (TCP)")

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

func (s *TcpTransport) Restart() {
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

	// Close open connection
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
	s.tunnelChannel = make(chan net.Conn, s.config.ChannelSize)
	s.localChannel = make(chan LocalTCPConn, s.config.ChannelSize)
	s.reqNewConnChan = make(chan struct{}, s.config.ChannelSize)
	s.controlChannel.Store(nil)
	s.rtt.Store(0)

	s.Start()
}

func (s *TcpTransport) channelHandshake() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case conn := <-s.tunnelChannel:
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

			s.controlChannel.Store(conn)

			s.logger.Info("control channel successfully established.")
			return
		}
	}
}

func (s *TcpTransport) channelHandler() {
	ctx := s.ctx
	controlChannel := s.controlChannel.Load()

	ticker := time.NewTicker(s.config.Heartbeat)
	defer ticker.Stop()

	// Channel to receive the message or error
	messageChan := make(chan byte, 1)

	s.spawn(func() {
		for {
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
				return
			}
		}
	})

	// RTT measurment
	rtt := time.Now()
	err := utils.SendBinaryByte(controlChannel, utils.SG_RTT)
	if err != nil {
		s.logger.Error("failed to send RTT signal, attempting to restart server...")
		go s.Restart()
		return
	}

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

			} else if message == utils.SG_RTT {
				measureRTT := time.Since(rtt)
				s.rtt.Store(measureRTT.Milliseconds())
				s.logger.Infof("Round Trip Time (RTT): %d ms", measureRTT.Milliseconds())
			}
		}
	}
}

func (s *TcpTransport) tunnelListener() {
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

func (s *TcpTransport) acceptTunnelConn(listener net.Listener) {
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

			// Drop all suspicious packets from other address rather than server
			if cc := s.controlChannel.Load(); cc != nil && cc.RemoteAddr().(*net.TCPAddr).IP.String() != tcpConn.RemoteAddr().(*net.TCPAddr).IP.String() {
				s.logger.Debugf("suspicious packet from %v. expected address: %v. discarding packet...", tcpConn.RemoteAddr().(*net.TCPAddr).IP.String(), cc.RemoteAddr().(*net.TCPAddr).IP.String())
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

			select {
			case s.tunnelChannel <- conn:
			default: // The channel is full, do nothing
				s.logger.Warnf("tunnel listener channel is full, discarding TCP connection from %s", conn.LocalAddr().String())
				conn.Close()
			}
		}
	}
}

func (s *TcpTransport) parsePortMappings() {
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

		s.startListeners(m.LocalAddr, m.RemoteAddr)
		time.Sleep(1 * time.Millisecond) // for wide port ranges
	}
}

func (s *TcpTransport) startListeners(localAddr, remoteAddr string) {
	// Start TCP listener
	s.spawn(func() { s.localListener(localAddr, remoteAddr) })

	// Start UDP listener if configured
	if s.config.AcceptUDP {
		s.spawn(func() { s.udpListener(localAddr, remoteAddr) })
	}

	s.logger.Debugf("Started listening on %s, forwarding to %s", localAddr, remoteAddr)
}

func (s *TcpTransport) localListener(localAddr string, remoteAddr string) {
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

func (s *TcpTransport) acceptLocalConn(listener net.Listener, remoteAddr string) {
	for {
		select {
		case <-s.ctx.Done():
			return

		default:
			s.logger.Debugf("waiting for accept incoming connection on %s", listener.Addr().String())
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

func (s *TcpTransport) handleLoop() {
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

				case tunnelConn := <-s.tunnelChannel:
					// Send the target addr over the connection
					if err := utils.SendBinaryTransportString(tunnelConn, localConn.remoteAddr, utils.SG_TCP); err != nil {
						s.logger.Errorf("%v", err)
						tunnelConn.Close()
						continue loop
					}

					// Handle data exchange between connections
					go handlers.TCPConnectionHandler(s.ctx, s.config.ProxyProtocol, localConn.conn, tunnelConn, s.logger, s.usageMonitor, localConn.conn.LocalAddr().(*net.TCPAddr).Port, s.config.Sniffer)
					break loop

				}
			}
		}
	}
}
