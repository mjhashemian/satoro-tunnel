package transport

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/handlers"
	"github.com/musix/backhaul/internal/utils/network"
	"github.com/musix/backhaul/internal/web"

	"github.com/sirupsen/logrus"
)

type TcpTransport struct {
	config          *TcpConfig
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

type TcpConfig struct {
	RemoteAddr     string
	Token          string
	SnifferLog     string
	KeepAlive      time.Duration
	RetryInterval  time.Duration
	DialTimeOut    time.Duration
	ConnPoolSize   int
	WebPort        int
	Nodelay        bool
	Sniffer        bool
	AggressivePool bool
	MSS            int
	SO_RCVBUF      int
	SO_SNDBUF      int
}

func NewTCPClient(parentCtx context.Context, config *TcpConfig, logger *logrus.Logger) *TcpTransport {
	// Create a derived context from the parent context
	ctx, cancel := context.WithCancel(parentCtx)

	// Initialize the TcpTransport struct
	client := &TcpTransport{
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
func (c *TcpTransport) spawn(f func()) {
	utils.Go(c.wg, f)
}

func (c *TcpTransport) Start() {
	if c.config.WebPort > 0 {
		c.spawn(c.usageMonitor.Monitor)
	}

	c.usageMonitor.SetStatus("Disconnected (TCP)")

	c.spawn(c.channelDialer)
}

func (c *TcpTransport) Restart() {
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

func (c *TcpTransport) channelDialer() {
	c.logger.Info("attempting to establish a new control channel connection...")

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			//set default behaviour of control channel to nodelay, also using default buffer parameters
			tunnelTCPConn, err := network.TcpDialer(c.ctx, c.config.RemoteAddr, "", c.config.DialTimeOut, c.config.KeepAlive, true, 3, 0, 0, 0)
			if err != nil {
				c.logger.Errorf("channel dialer: %v", err)
				sleepCtx(c.ctx, c.config.RetryInterval)
				continue
			}

			// Sending security token
			err = utils.SendBinaryTransportString(tunnelTCPConn, c.config.Token, utils.SG_Chan)
			if err != nil {
				c.logger.Errorf("failed to send security token: %v", err)
				tunnelTCPConn.Close()
				continue
			}

			// Set a read deadline for the token response
			if err := tunnelTCPConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				c.logger.Errorf("failed to set read deadline: %v", err)
				tunnelTCPConn.Close()
				continue
			}
			// Receive response
			message, _, err := utils.ReceiveBinaryTransportString(tunnelTCPConn)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					c.logger.Warn("timeout while waiting for control channel response")
				} else {
					c.logger.Errorf("failed to receive control channel response: %v", err)
				}
				tunnelTCPConn.Close() // Close connection on error or timeout
				sleepCtx(c.ctx, c.config.RetryInterval)
				continue
			}
			// Resetting the deadline (removes any existing deadline)
			tunnelTCPConn.SetReadDeadline(time.Time{})

			if message == c.config.Token {
				c.controlChannel.Store(tunnelTCPConn)
				c.logger.Info("control channel established successfully")

				c.usageMonitor.SetStatus("Connected (TCP)")
				c.spawn(c.poolMaintainer)
				c.spawn(c.channelHandler)

				return
			} else {
				c.logger.Errorf("invalid token received. Expected: %s, Received: %s. Retrying...", c.config.Token, message)
				tunnelTCPConn.Close() // Close connection if the token is invalid
				sleepCtx(c.ctx, c.config.RetryInterval)
				continue
			}
		}
	}
}

func (c *TcpTransport) poolMaintainer() {
	ctx, usage := c.ctx, c.usageMonitor

	maintainPool(ctx, c.logger, c.config.ConnPoolSize, c.config.AggressivePool, &c.poolConnections, &c.loadConnections, c.controlFlow, func() {
		c.tunnelDialer(ctx, usage)
	})
}

func (c *TcpTransport) channelHandler() {
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

			case utils.SG_RTT:
				err := utils.SendBinaryByte(controlChannel, utils.SG_RTT)
				if err != nil {
					c.logger.Error("failed to send RTT signal, restarting client: ", err)
					go c.Restart()
					return
				}

			default:
				c.logger.Errorf("unexpected response from channel: %v.", msg)
				go c.Restart()
				return
			}
		}
	}
}

// Dialing to the tunnel server, chained functions, without retry.
// ctx and usage belong to the run that requested the tunnel.
func (c *TcpTransport) tunnelDialer(ctx context.Context, usage *web.Usage) {
	c.logger.Debugf("initiating new connection to tunnel server at %s", c.config.RemoteAddr)

	// Dial to the tunnel server
	tcpConn, err := network.TcpDialer(ctx, c.config.RemoteAddr, "", c.config.DialTimeOut, c.config.KeepAlive, c.config.Nodelay, 3, c.config.SO_RCVBUF, c.config.SO_SNDBUF, c.config.MSS)
	if err != nil {
		c.logger.Error("tunnel server dialer: ", err)
		return
	}

	// Close the idle pooled connection if the client restarts before it is used
	stopClose := context.AfterFunc(ctx, func() { tcpConn.Close() })

	// Increment active connections counter
	atomic.AddInt32(&c.poolConnections, 1)

	// Attempt to receive the remote address from the tunnel server
	remoteAddr, transport, err := utils.ReceiveBinaryTransportString(tcpConn)

	// Decrement active connections after successful or failed connection
	atomic.AddInt32(&c.poolConnections, -1)

	if !stopClose() || err != nil {
		if err != nil {
			c.logger.Debugf("failed to receive port from tunnel connection %s: %v", tcpConn.RemoteAddr().String(), err)
		}
		tcpConn.Close()
		return
	}

	// Extract the port from the received address
	port, resolvedAddr, err := network.ResolveRemoteAddr(remoteAddr)
	if err != nil {
		c.logger.Infof("failed to resolve remote port: %v", err)
		tcpConn.Close() // Close the connection on error
		return
	}

	switch transport {
	case utils.SG_TCP:
		// Dial local server using the received address
		c.localDialer(ctx, usage, tcpConn, resolvedAddr, port)

	case utils.SG_UDP:
		UDPDialer(tcpConn, resolvedAddr, c.logger, usage, port, c.config.Sniffer)

	default:
		c.logger.Error("undefined transport. close the connection.")
		tcpConn.Close()
	}
}

func (c *TcpTransport) localDialer(ctx context.Context, usage *web.Usage, tcpConn net.Conn, resolvedAddr string, port int) {
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
		tcpConn.Close()
		return
	}

	c.logger.Debugf("connected to local address %s successfully", resolvedAddr)

	handlers.TCPConnectionHandler(ctx, false, tcpConn, localConnection, c.logger, usage, port, c.config.Sniffer)
}

// sleepCtx sleeps for d or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
