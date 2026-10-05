package transport

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mjhashemian/satoro-tunnel/internal/utils"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/handlers"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/network"
	"github.com/mjhashemian/satoro-tunnel/internal/web"

	"github.com/sirupsen/logrus"
	"github.com/xtaci/smux"
)

type TcpMuxTransport struct {
	config          *TcpMuxConfig
	smuxConfig      *smux.Config
	parentctx       context.Context
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *logrus.Logger
	controlChannel  utils.Locked[net.Conn]
	usageMonitor    *web.Usage
	restartMutex    sync.Mutex
	wg              *sync.WaitGroup // control-plane goroutines of the current run
	poolConnections int32
	loadConnections int32
	controlFlow     chan struct{}
}

type TcpMuxConfig struct {
	RemoteAddr       string
	Token            string
	SnifferLog       string
	Nodelay          bool
	Sniffer          bool
	KeepAlive        time.Duration
	RetryInterval    time.Duration
	DialTimeOut      time.Duration
	MuxVersion       int
	MaxFrameSize     int
	MaxReceiveBuffer int
	MaxStreamBuffer  int
	ConnPoolSize     int
	WebPort          int
	AggressivePool   bool
	MSS              int
	SO_RCVBUF        int
	SO_SNDBUF        int
}

func NewMuxClient(parentCtx context.Context, config *TcpMuxConfig, logger *logrus.Logger) *TcpMuxTransport {
	// Create a derived context from the parent context
	ctx, cancel := context.WithCancel(parentCtx)

	// Initialize the TcpTransport struct
	client := &TcpMuxTransport{
		smuxConfig: &smux.Config{
			Version:           config.MuxVersion,
			KeepAliveInterval: 20 * time.Second,
			KeepAliveTimeout:  40 * time.Second,
			MaxFrameSize:      config.MaxFrameSize,
			MaxReceiveBuffer:  config.MaxReceiveBuffer,
			MaxStreamBuffer:   config.MaxStreamBuffer,
		},
		config:       config,
		parentctx:    parentCtx,
		ctx:          ctx,
		cancel:       cancel,
		logger:       logger,
		wg:           &sync.WaitGroup{},
		usageMonitor: web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, logger),
		controlFlow:  make(chan struct{}, 100),
	}

	return client
}

// spawn starts a control-plane goroutine that Restart waits for.
func (c *TcpMuxTransport) spawn(f func()) {
	utils.Go(c.wg, f)
}

func (c *TcpMuxTransport) Start() {
	if c.config.WebPort > 0 {
		c.spawn(c.usageMonitor.Monitor)
	}

	c.usageMonitor.SetStatus("Disconnected (TCPMUX)")

	c.spawn(c.channelDialer)
}

func (c *TcpMuxTransport) Restart() {
	if !c.restartMutex.TryLock() {
		c.logger.Warn("client is already restarting")
		return
	}
	defer c.restartMutex.Unlock()

	c.logger.Info("restarting client...")

	// for removing timeout logs
	level := c.logger.Level
	c.logger.SetLevel(logrus.FatalLevel)

	if c.cancel != nil {
		c.cancel()
	}

	// close control channel connection
	if cc := c.controlChannel.Load(); cc != nil {
		cc.Close()
	}

	// Wait for the previous run to stop before replacing its state
	stopped := utils.WaitTimeout(c.wg, 10*time.Second)

	// set the log level again
	c.logger.SetLevel(level)

	if !stopped {
		c.logger.Warn("timed out waiting for previous workers to stop, restarting anyway")
	}

	ctx, cancel := context.WithCancel(c.parentctx)
	c.ctx = ctx
	c.cancel = cancel

	// Re-initialize variables
	c.wg = &sync.WaitGroup{}
	c.controlChannel.Store(nil)
	c.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", c.config.WebPort), ctx, c.config.SnifferLog, c.config.Sniffer, c.logger)
	atomic.StoreInt32(&c.poolConnections, 0)
	atomic.StoreInt32(&c.loadConnections, 0)
	c.controlFlow = make(chan struct{}, 100)

	c.Start()
}

func (c *TcpMuxTransport) channelDialer() {
	c.logger.Info("attempting to establish a new tcpmux control channel connection...")

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			tunnelConn, err := network.TcpDialer(c.ctx, c.config.RemoteAddr, "", c.config.DialTimeOut, c.config.KeepAlive, true, 3, 0, 0, 0)
			if err != nil {
				c.logger.Errorf("channel dialer: %v", err)
				sleepCtx(c.ctx, c.config.RetryInterval)
				continue
			}

			// Sending security token
			err = utils.SendBinaryTransportString(tunnelConn, c.config.Token, utils.SG_Chan)
			if err != nil {
				c.logger.Errorf("failed to send security token: %v", err)
				tunnelConn.Close()
				continue
			}

			// Set a read deadline for the token response
			if err := tunnelConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				c.logger.Errorf("failed to set read deadline: %v", err)
				tunnelConn.Close()
				continue
			}
			// Receive response
			message, _, err := utils.ReceiveBinaryTransportString(tunnelConn)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					c.logger.Warn("timeout while waiting for control channel response")
				} else {
					c.logger.Errorf("failed to receive control channel response: %v", err)
				}
				tunnelConn.Close() // Close connection on error or timeout
				sleepCtx(c.ctx, c.config.RetryInterval)
				continue
			}
			// Resetting the deadline (removes any existing deadline)
			tunnelConn.SetReadDeadline(time.Time{})

			if message == c.config.Token {
				c.controlChannel.Store(tunnelConn)
				c.logger.Info("control channel established successfully")

				c.usageMonitor.SetStatus("Connected (TCPMux)")
				c.spawn(c.poolMaintainer)
				c.spawn(c.channelHandler)

				return
			} else {
				c.logger.Errorf("invalid token received. Expected: %s, Received: %s. Retrying...", c.config.Token, message)
				tunnelConn.Close() // Close connection if the token is invalid
				sleepCtx(c.ctx, c.config.RetryInterval)
				continue
			}
		}
	}

}

func (c *TcpMuxTransport) poolMaintainer() {
	ctx, usage := c.ctx, c.usageMonitor

	maintainPool(ctx, c.logger, c.config.ConnPoolSize, c.config.AggressivePool, &c.poolConnections, &c.loadConnections, c.controlFlow, func() {
		c.tunnelDialer(ctx, usage)
	})
}

func (c *TcpMuxTransport) channelHandler() {
	ctx, usage := c.ctx, c.usageMonitor
	controlChannel := c.controlChannel.Load()

	msgChan := make(chan byte, 1000)

	// Goroutine to handle the blocking ReceiveBinaryString
	c.spawn(func() {
		for {
			msg, err := utils.ReceiveBinaryByte(controlChannel)
			if err != nil {
				// A cancelled context means a restart or shutdown is already in progress
				if ctx.Err() == nil {
					c.logger.Error("failed to read from control channel. ", err)
					go c.Restart()
				}
				return
			}

			select {
			case msgChan <- msg:
			case <-ctx.Done():
				return
			}
		}
	})

	// Main loop to listen for context cancellation or received messages
	for {
		select {
		case <-ctx.Done():
			_ = utils.SendBinaryByte(controlChannel, utils.SG_Closed)
			return

		case msg := <-msgChan:
			switch msg {
			case utils.SG_Chan:
				atomic.AddInt32(&c.loadConnections, 1)

				select {
				case <-c.controlFlow: // Do nothing

				default:
					c.logger.Debug("channel signal received, initiating tunnel dialer")
					go c.tunnelDialer(ctx, usage)
				}

			case utils.SG_HB:
				c.logger.Debug("heartbeat signal received successfully")

			case utils.SG_Closed:
				c.logger.Warn("control channel has been closed by the server")
				go c.Restart()
				return

			default:
				c.logger.Errorf("unexpected response from channel: %v.", msg)
				go c.Restart()
				return
			}

		}
	}
}

// tunnelDialer dials one mux session. ctx and usage belong to the run that requested it.
func (c *TcpMuxTransport) tunnelDialer(ctx context.Context, usage *web.Usage) {
	c.logger.Debugf("initiating new tunnel connection to address %s", c.config.RemoteAddr)

	// Dial to the tunnel server
	tunnelConn, err := network.TcpDialer(ctx, c.config.RemoteAddr, "", c.config.DialTimeOut, c.config.KeepAlive, c.config.Nodelay, 3, c.config.SO_RCVBUF, c.config.SO_SNDBUF, c.config.MSS)
	if err != nil {
		c.logger.Errorf("tunnel server dialer: %v", err)

		return
	}

	// Increment active connections counter
	atomic.AddInt32(&c.poolConnections, 1)

	c.handleSession(ctx, usage, tunnelConn)
}

func (c *TcpMuxTransport) handleSession(ctx context.Context, usage *web.Usage, tunnelConn net.Conn) {
	defer func() {
		atomic.AddInt32(&c.poolConnections, -1)
	}()

	// SMUX server
	session, err := smux.Server(tunnelConn, c.smuxConfig)
	if err != nil {
		c.logger.Errorf("failed to create mux session: %v", err)
		tunnelConn.Close()
		return
	}

	// Close the session when the client restarts or shuts down
	stopClose := context.AfterFunc(ctx, func() { session.Close() })
	defer stopClose()

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			c.logger.Trace("session is closed: ", err)
			session.Close()
			return
		}

		remoteAddr, err := utils.ReceiveBinaryString(stream)
		if err != nil {
			c.logger.Errorf("unable to get port from stream connection %s: %v", tunnelConn.RemoteAddr().String(), err)
			stream.Close()
			continue
		}

		go c.localDialer(ctx, usage, stream, remoteAddr)
	}
}

func (c *TcpMuxTransport) localDialer(ctx context.Context, usage *web.Usage, stream *smux.Stream, remoteAddr string) {
	// Extract the port from the received address
	port, resolvedAddr, err := network.ResolveRemoteAddr(remoteAddr)
	if err != nil {
		c.logger.Infof("failed to resolve remote port: %v", err)
		stream.Close()
		return
	}

	var sendBuf, recvBuf int
	if strings.Contains(resolvedAddr, "127.0.0.1") {
		// Use 32 KB for localhost
		sendBuf = 32 * 1024
		recvBuf = 32 * 1024
	} else {
		// Use your custom buffer sizes
		sendBuf = c.config.SO_SNDBUF
		recvBuf = c.config.SO_RCVBUF
	}

	localConnection, err := network.TcpDialer(ctx, resolvedAddr, "", c.config.DialTimeOut, c.config.KeepAlive, true, 1, recvBuf, sendBuf, c.config.MSS)
	if err != nil {
		c.logger.Errorf("local dialer: %v", err)
		stream.Close()
		return
	}

	c.logger.Debugf("connected to local address %s successfully", remoteAddr)

	handlers.TCPConnectionHandler(ctx, false, stream, localConnection, c.logger, usage, int(port), c.config.Sniffer)
}
