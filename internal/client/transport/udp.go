package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mjhashemian/satoro-tunnel/internal/utils"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/network"
	"github.com/mjhashemian/satoro-tunnel/internal/web"
	"github.com/sirupsen/logrus"
)

// TCP keep-alive interval for the UDP transport's control channel
const udpControlKeepAlive = 30 * time.Second

type UdpTransport struct {
	config          *UdpConfig
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
type UdpConfig struct {
	RemoteAddr     string
	Token          string
	SnifferLog     string
	RetryInterval  time.Duration
	DialTimeOut    time.Duration
	ConnPoolSize   int
	WebPort        int
	Sniffer        bool
	AggressivePool bool
}

func NewUDPClient(parentCtx context.Context, config *UdpConfig, logger *logrus.Logger) *UdpTransport {
	// Create a derived context from the parent context
	ctx, cancel := context.WithCancel(parentCtx)

	// Initialize the TcpTransport struct
	client := &UdpTransport{
		config:       config,
		parentctx:    parentCtx,
		ctx:          ctx,
		cancel:       cancel,
		logger:       logger,
		wg:           &sync.WaitGroup{},
		usageMonitor: web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), parentCtx, config.SnifferLog, config.Sniffer, logger),
		controlFlow:  make(chan struct{}, 100),
	}

	return client
}

// spawn starts a control-plane goroutine that Restart waits for.
func (c *UdpTransport) spawn(f func()) {
	utils.Go(c.wg, f)
}

func (c *UdpTransport) Start() {
	c.usageMonitor.Start(c.config.WebPort > 0)

	c.usageMonitor.SetStatus("Disconnected (UDP)")

	c.spawn(c.channelDialer)
}

func (c *UdpTransport) Restart() {
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
	atomic.StoreInt32(&c.poolConnections, 0)
	atomic.StoreInt32(&c.loadConnections, 0)
	c.controlFlow = make(chan struct{}, 100)

	c.Start()
}

func (c *UdpTransport) channelDialer() {
	c.logger.Info("attempting to establish a new control channel connection...")

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			tunnelTCPConn, err := network.TcpDialer(c.ctx, c.config.RemoteAddr, "", c.config.DialTimeOut, udpControlKeepAlive, true, 3, 0, 0, 0)
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

				c.usageMonitor.SetStatus("Connected (UDP)")
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

func (c *UdpTransport) poolMaintainer() {
	ctx, usage := c.ctx, c.usageMonitor

	maintainPool(ctx, c.logger, c.config.ConnPoolSize, c.config.AggressivePool, &c.poolConnections, &c.loadConnections, c.controlFlow, func() {
		c.tunnelDialer(ctx, usage)
	})
}

func (c *UdpTransport) channelHandler() {
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

// tunnelDialer opens one UDP tunnel. ctx and usage belong to the run that requested it.
func (c *UdpTransport) tunnelDialer(ctx context.Context, usage *web.Usage) {
	c.logger.Debugf("initiating new connection to tunnel server at %s", c.config.RemoteAddr)

	remoteAddr, err := net.ResolveUDPAddr("udp", c.config.RemoteAddr)
	if err != nil {
		c.logger.Error("failed to resolve tunnel address:", err)
		return
	}

	tunConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		c.logger.Error("failed to connect to server:", err)
		return
	}

	defer tunConn.Close()

	done := make(chan struct{})

	// Start handleTunnelConn in a goroutine
	go func() {
		c.handleTunnelConn(usage, tunConn)
		close(done) // Signal that handleTunnelConn is done
	}()

	// Wait for either handleTunnelConn to finish or the context to be done
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (c *UdpTransport) handleTunnelConn(usage *web.Usage, tunConn *net.UDPConn) {
	// Send token message to the server
	_, err := tunConn.Write([]byte(c.config.Token))
	if err != nil {
		c.logger.Error("faliled to send token:", err)
		return
	}

	// Increment active connections counter
	atomic.AddInt32(&c.poolConnections, 1)

	// Prepare a buffer to receive the server's response
	buffer := make([]byte, 47) // maximum buffer requried for store in IPv6:Port format

	for {
		n, _, err := tunConn.ReadFromUDP(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				c.logger.Debug("tunnel connection closed")
			} else {
				c.logger.Error("failed to receive response from server:", err)
			}
			atomic.AddInt32(&c.poolConnections, -1)
			return
		}

		// Compare the received bytes with the expected SG_Ping message
		if n == 1 && buffer[0] == utils.SG_Ping {
			c.logger.Tracef("ping signal recieved for %s", tunConn.LocalAddr().String())
			continue
		}

		port, remoteAddr, err := network.ResolveRemoteAddr(string(buffer[:n]))

		// Decrement active connections after successful or failed connection
		atomic.AddInt32(&c.poolConnections, -1)

		if err != nil {
			c.logger.Error("failed to find remote address:", err)
			return
		}

		c.localDialer(usage, remoteAddr, port, tunConn)
		return
	}
}

func (c *UdpTransport) localDialer(usage *web.Usage, remoteAddr string, port int, tunConn *net.UDPConn) {
	remoteResolvedAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		c.logger.Error("failed to resolve remote address:", err)
		return
	}

	// Dial the remote UDP server
	remoteConn, err := net.DialUDP("udp", nil, remoteResolvedAddr)
	if err != nil {
		c.logger.Errorf("failed to dial remote UDP address: %v", err)
		return
	}

	defer remoteConn.Close()

	done := make(chan struct{})

	c.logger.Debugf("start to copy from tunnel %s to local %s", tunConn.LocalAddr(), remoteAddr)

	go func() {
		c.udpCopy(usage, remoteConn, tunConn, port)
		done <- struct{}{}
	}()

	c.udpCopy(usage, tunConn, remoteConn, port)

	<-done
}

func (c *UdpTransport) udpCopy(usage *web.Usage, srcConn, dstConn *net.UDPConn, port int) {
	buf := make([]byte, 16*1024)
	readTimeout := 60 * time.Second
	var deadlineSet time.Time

	for {
		// Push the 60 second idle deadline forward at most once a second, instead of resetting
		// the poller's timer on every packet
		if now := time.Now(); now.Sub(deadlineSet) >= time.Second {
			if err := srcConn.SetReadDeadline(now.Add(readTimeout)); err != nil {
				c.logger.Errorf("failed to set read deadline: %v", err)
				return
			}
			deadlineSet = now
		}

		// Read from the UDP source connection
		n, _, err := srcConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				c.logger.Debug("read from UDP timed out")
				return // Exit on timeout
			}
			if errors.Is(err, net.ErrClosed) {
				c.logger.Debug("UDP connection closed")
				return
			}
			c.logger.Errorf("failed to read from UDP: %v", err)
			return
		}

		totalWritten := 0

		// Write the read data to the destination UDP connection
		for totalWritten < n {
			w, err := dstConn.Write(buf[totalWritten:n])
			if err != nil {
				c.logger.Errorf("failed to write to UDP %s: %v", dstConn.RemoteAddr().String(), err)
				return
			}
			totalWritten += w
		}

		// Optionally update the port usage stats if sniffing is enabled
		if c.config.Sniffer {
			usage.AddOrUpdatePort(port, uint64(totalWritten))
		}

		c.logger.Debugf("forwarded %d bytes from %s to %s", n, srcConn.LocalAddr().String(), dstConn.RemoteAddr().String())
	}
}
