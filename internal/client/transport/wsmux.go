package transport

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musix/backhaul/config"
	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/handlers"
	"github.com/musix/backhaul/internal/utils/network"
	"github.com/musix/backhaul/internal/web"
	"github.com/xtaci/smux"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type WsMuxTransport struct {
	config          *WsMuxConfig
	smuxConfig      *smux.Config
	parentctx       context.Context
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *logrus.Logger
	controlChannel  utils.Locked[*websocket.Conn]
	usageMonitor    *web.Usage
	restartMutex    sync.Mutex
	wg              *sync.WaitGroup // control-plane goroutines of the current run
	poolConnections int32
	loadConnections int32
	controlFlow     chan struct{}
}
type WsMuxConfig struct {
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
	Mode             config.TransportType
	AggressivePool   bool
	EdgeIP           string
}

func NewWSMuxClient(parentCtx context.Context, config *WsMuxConfig, logger *logrus.Logger) *WsMuxTransport {
	// Create a derived context from the parent context
	ctx, cancel := context.WithCancel(parentCtx)

	// Initialize the TcpTransport struct
	client := &WsMuxTransport{
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
func (c *WsMuxTransport) spawn(f func()) {
	utils.Go(c.wg, f)
}

func (c *WsMuxTransport) Start() {
	// for  webui
	if c.config.WebPort > 0 {
		c.spawn(c.usageMonitor.Monitor)
	}

	c.usageMonitor.SetStatus(fmt.Sprintf("Disconnected (%s)", c.config.Mode))

	c.spawn(c.channelDialer)
}

func (c *WsMuxTransport) Restart() {
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

func (c *WsMuxTransport) channelDialer() {
	c.logger.Infof("attempting to establish a new %s control channel connection", c.config.Mode)

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

func (c *WsMuxTransport) poolMaintainer() {
	ctx, usage := c.ctx, c.usageMonitor

	maintainPool(ctx, c.logger, c.config.ConnPoolSize, c.config.AggressivePool, &c.poolConnections, &c.loadConnections, c.controlFlow, func() {
		c.tunnelDialer(ctx, usage)
	})
}

func (c *WsMuxTransport) channelHandler() {
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
				c.logger.Debug("heartbeat received successfully")
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
				c.logger.Errorf("unexpected response from control channel: %v", msg)
				go c.Restart()
				return
			}

		}
	}
}

// tunnelDialer dials one mux session. ctx and usage belong to the run that requested it.
func (c *WsMuxTransport) tunnelDialer(ctx context.Context, usage *web.Usage) {
	c.logger.Debugf("initiating new %s tunnel connection to address %s", c.config.Mode, c.config.RemoteAddr)

	// Dial to the tunnel server
	tunnelWSConn, err := network.WebSocketDialer(ctx, c.config.RemoteAddr, c.config.EdgeIP, "/tunnel", c.config.DialTimeOut, c.config.KeepAlive, c.config.Nodelay, c.config.Token, c.config.Mode, 3, 2*1024*1024, 2*1024*1024)
	if err != nil {
		c.logger.Errorf("tunnel server dialer: %v", err)

		return
	}

	// Increment active connections counter
	atomic.AddInt32(&c.poolConnections, 1)

	c.handleSession(ctx, usage, tunnelWSConn)
}

func (c *WsMuxTransport) handleSession(ctx context.Context, usage *web.Usage, tunnelConn *websocket.Conn) {
	defer func() {
		atomic.AddInt32(&c.poolConnections, -1)
	}()

	// SMUX server
	session, err := smux.Server(tunnelConn.NetConn(), c.smuxConfig)
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
			c.logger.Debug("session is closed: ", err)
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

func (c *WsMuxTransport) localDialer(ctx context.Context, usage *web.Usage, stream *smux.Stream, remoteAddr string) {
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
		sendBuf = 0
		recvBuf = 0
	}

	localConnection, err := network.TcpDialer(ctx, resolvedAddr, "", c.config.DialTimeOut, c.config.KeepAlive, true, 1, recvBuf, sendBuf, 0)
	if err != nil {
		c.logger.Errorf("local dialer: %v", err)
		stream.Close()
		return
	}

	c.logger.Debugf("connected to local address %s successfully", remoteAddr)

	handlers.TCPConnectionHandler(ctx, false, stream, localConnection, c.logger, usage, int(port), c.config.Sniffer)
}
