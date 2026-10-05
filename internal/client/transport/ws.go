package transport

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mjhashemian/satoro-tunnel/config"
	"github.com/mjhashemian/satoro-tunnel/internal/utils"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/handlers"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/network"
	"github.com/mjhashemian/satoro-tunnel/internal/web"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type WsTransport struct {
	config          *WsConfig
	parentctx       context.Context
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *logrus.Logger
	controlChannel  utils.Locked[*websocket.Conn]
	restartMutex    sync.Mutex
	wg              *sync.WaitGroup // control-plane goroutines of the current run
	usageMonitor    *web.Usage
	poolConnections int32
	loadConnections int32
	controlFlow     chan struct{}
}
type WsConfig struct {
	RemoteAddr     string
	Token          string
	SnifferLog     string
	Nodelay        bool
	Sniffer        bool
	KeepAlive      time.Duration
	RetryInterval  time.Duration
	DialTimeOut    time.Duration
	ConnPoolSize   int
	WebPort        int
	Mode           config.TransportType
	AggressivePool bool
	EdgeIP         string
}

func NewWSClient(parentCtx context.Context, config *WsConfig, logger *logrus.Logger) *WsTransport {
	// Create a derived context from the parent context
	ctx, cancel := context.WithCancel(parentCtx)

	// Initialize the TcpTransport struct
	client := &WsTransport{
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
func (c *WsTransport) spawn(f func()) {
	utils.Go(c.wg, f)
}

func (c *WsTransport) Start() {
	// for  webui
	if c.config.WebPort > 0 {
		c.spawn(c.usageMonitor.Monitor)
	}

	c.usageMonitor.SetStatus(fmt.Sprintf("Disconnected (%s)", c.config.Mode))

	c.spawn(c.channelDialer)

}
func (c *WsTransport) Restart() {
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

func (c *WsTransport) channelDialer() {
	c.logger.Info("attempting to establish a new websocket control channel connection")

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			tunnelWSConn, err := network.WebSocketDialer(c.ctx, c.config.RemoteAddr, c.config.EdgeIP, "/channel", c.config.DialTimeOut, c.config.KeepAlive, true, c.config.Token, c.config.Mode, 3, 0, 0)
			if err != nil {
				c.logger.Errorf("control channel dialer: %v", err)
				sleepCtx(c.ctx, c.config.RetryInterval)
				continue
			}
			c.controlChannel.Store(tunnelWSConn)
			c.logger.Info("control channel established successfully")

			c.usageMonitor.SetStatus(fmt.Sprintf("Connected (%s)", c.config.Mode))

			c.spawn(c.poolMaintainer)
			c.spawn(c.channelHandler)

			return
		}
	}
}

func (c *WsTransport) poolMaintainer() {
	ctx, usage := c.ctx, c.usageMonitor

	maintainPool(ctx, c.logger, c.config.ConnPoolSize, c.config.AggressivePool, &c.poolConnections, &c.loadConnections, c.controlFlow, func() {
		c.tunnelDialer(ctx, usage)
	})
}

func (c *WsTransport) channelHandler() {
	ctx, usage := c.ctx, c.usageMonitor
	controlChannel := c.controlChannel.Load()

	msgChan := make(chan byte, 1000)

	// Goroutine to handle the blocking ReceiveBinaryString
	c.spawn(func() {
		for {
			_, msg, err := controlChannel.ReadMessage()
			if err != nil {
				// A cancelled context means a restart or shutdown is already in progress
				if ctx.Err() == nil {
					c.logger.Error("failed to read from channel connection. ", err)
					go c.Restart()
				}
				return
			}
			if len(msg) == 0 {
				continue
			}

			select {
			case msgChan <- msg[0]:
			case <-ctx.Done():
				return
			}
		}
	})

	// Main loop to listen for context cancellation or received messages
	for {
		select {
		case <-ctx.Done():
			_ = controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_Closed})
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

				// send heartbeat back
				err := controlChannel.WriteMessage(websocket.BinaryMessage, []byte{utils.SG_HB})
				if err != nil {
					c.logger.Errorf("failed to send heartbeat: %v", err)
					go c.Restart()
					return
				}
				c.logger.Trace("heartbeat signal sent successfully")

			case utils.SG_Closed:
				c.logger.Warn("control channel has been closed by the server")
				go c.Restart()
				return

			default:
				c.logger.Errorf("unexpected response from channel: %v", msg)
				go c.Restart()
				return
			}
		}
	}
}

// tunnelDialer dials one pooled tunnel. ctx and usage belong to the run that requested it.
func (c *WsTransport) tunnelDialer(ctx context.Context, usage *web.Usage) {
	c.logger.Debugf("initiating new websocket tunnel connection to address %s", c.config.RemoteAddr)

	// Dial to the tunnel server
	tunnelConn, err := network.WebSocketDialer(ctx, c.config.RemoteAddr, c.config.EdgeIP, "/tunnel", c.config.DialTimeOut, c.config.KeepAlive, c.config.Nodelay, c.config.Token, c.config.Mode, 3, 1024*1024, 1024*1024)
	if err != nil {
		c.logger.Errorf("tunnel server dialer: %v", err)

		return
	}

	// Close the idle pooled connection if the client restarts before it is used
	stopClose := context.AfterFunc(ctx, func() { tunnelConn.Close() })

	// Increment active connections counter
	atomic.AddInt32(&c.poolConnections, 1)

	for {
		_, remoteAddrBytes, err := tunnelConn.ReadMessage()
		if err != nil {
			c.logger.Debugf("unable to get port from websocket connection %s: %v", tunnelConn.RemoteAddr().String(), err)
			stopClose()
			tunnelConn.Close()
			// Decrement active connections on failure
			atomic.AddInt32(&c.poolConnections, -1)
			return
		}

		if bytes.Equal(remoteAddrBytes, []byte{utils.SG_Ping}) {
			c.logger.Trace("ping received from the server")
			continue
		}

		// Decrement active connections
		atomic.AddInt32(&c.poolConnections, -1)

		if !stopClose() {
			// The client is restarting and has already closed this connection
			tunnelConn.Close()
			return
		}

		remoteAddr := string(remoteAddrBytes)

		// Extract the port from the received address
		port, resolvedAddr, err := network.ResolveRemoteAddr(remoteAddr)
		if err != nil {
			c.logger.Infof("failed to resolve remote port: %v", err)
			tunnelConn.Close() // Close the connection on error
			return
		}

		c.localDialer(ctx, usage, tunnelConn, resolvedAddr, port)
		return
	}
}

func (c *WsTransport) localDialer(ctx context.Context, usage *web.Usage, tunnelCon *websocket.Conn, remoteAddr string, port int) {
	var sendBuf, recvBuf int
	if strings.Contains(remoteAddr, "127.0.0.1") {
		// Use 32 KB for localhost
		sendBuf = 32 * 1024
		recvBuf = 32 * 1024
	} else {
		// Use your custom buffer sizes
		sendBuf = 0
		recvBuf = 0
	}

	localConnection, err := network.TcpDialer(ctx, remoteAddr, "", c.config.DialTimeOut, c.config.KeepAlive, true, 1, recvBuf, sendBuf, 0)
	if err != nil {
		c.logger.Errorf("local dialer: %v", err)
		tunnelCon.Close()
		return
	}

	c.logger.Debugf("connected to local address %s successfully", remoteAddr)

	handlers.WSConnectionHandler(ctx, tunnelCon, localConnection, c.logger, usage, int(port), c.config.Sniffer)
}
