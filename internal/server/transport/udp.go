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
	"github.com/mjhashemian/satoro-tunnel/internal/utils/portmap"
	"github.com/mjhashemian/satoro-tunnel/internal/web"

	"github.com/sirupsen/logrus"
)

type UdpTransport struct {
	config         *UdpConfig
	parentctx      context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	logger         *logrus.Logger
	tunnelChannel  chan *TunnelUDPConn
	tunnels        *udpConnTable // active tunnel connections, keyed by client address
	reqNewConnChan chan struct{}
	controlChannel utils.Locked[net.Conn]
	restartMutex   sync.Mutex
	wg             *sync.WaitGroup // control-plane goroutines of the current run
	usageMonitor   *web.Usage
	rtt            atomic.Int64 // for Fun!
}

// udpConnTable tracks the active tunnel connections of one run.
type udpConnTable struct {
	mu sync.Mutex
	m  map[string]*TunnelUDPConn
}

type UdpConfig struct {
	BindAddr    string
	Token       string
	SnifferLog  string
	Ports       []string
	Sniffer     bool
	Heartbeat   time.Duration // in seconds, for udp conn and control channel
	ChannelSize int
	WebPort     int
}

func NewUDPServer(parentCtx context.Context, config *UdpConfig, logger *logrus.Logger) *UdpTransport {
	// Create a derived context from the parent context
	ctx, cancel := context.WithCancel(parentCtx)

	// Initialize the TcpTransport struct
	server := &UdpTransport{
		config:         config,
		parentctx:      parentCtx,
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
		tunnelChannel:  make(chan *TunnelUDPConn, config.ChannelSize),
		tunnels:        &udpConnTable{m: map[string]*TunnelUDPConn{}},
		reqNewConnChan: make(chan struct{}, config.ChannelSize),
		wg:             &sync.WaitGroup{},
		usageMonitor:   web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), parentCtx, config.SnifferLog, config.Sniffer, logger),
	}

	return server
}

// spawn starts a control-plane goroutine that Restart waits for.
func (s *UdpTransport) spawn(f func()) {
	utils.Go(s.wg, f)
}

func (s *UdpTransport) Start() {
	s.usageMonitor.SetStatus("Disconnected (UDP)")

	s.usageMonitor.Start(s.config.WebPort > 0)

	s.spawn(s.channelHandshake)
}

func (s *UdpTransport) Restart() {
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
	s.tunnelChannel = make(chan *TunnelUDPConn, s.config.ChannelSize)
	s.reqNewConnChan = make(chan struct{}, s.config.ChannelSize)
	s.controlChannel.Store(nil)
	s.tunnels = &udpConnTable{m: map[string]*TunnelUDPConn{}}
	s.rtt.Store(0)

	s.Start()
}

func (s *UdpTransport) channelHandshake() {
	listener, ok := network.RetryListen(s.ctx, s.logger, s.config.BindAddr, func() (net.Listener, error) {
		return net.Listen("tcp", s.config.BindAddr)
	})
	if !ok {
		return
	}

	s.logger.Infof("server started successfully, listening on address: %s", listener.Addr().String())

	defer listener.Close()

	// Unblock Accept when the run stops
	stopAccept := context.AfterFunc(s.ctx, func() { listener.Close() })
	defer stopAccept()

loop:
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
				s.logger.Debugf("failed to accept control channel connection on %s: %v", listener.Addr().String(), err)
				continue
			}

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
			s.usageMonitor.SetStatus("Connected (UDP)")

			break loop
		}
	}

	s.spawn(s.tunnelListener)
	s.spawn(s.parsePortMappings)
	s.spawn(s.channelHandler)

	<-s.ctx.Done()
}

func (s *UdpTransport) channelHandler() {
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

func (s *UdpTransport) tunnelListener() {
	listener, ok := network.RetryListen(s.ctx, s.logger, "udp "+s.config.BindAddr, func() (*net.UDPConn, error) {
		tunnelUDPAddr, err := net.ResolveUDPAddr("udp", s.config.BindAddr)
		if err != nil {
			return nil, err
		}
		return net.ListenUDP("udp", tunnelUDPAddr)
	})
	if !ok {
		return
	}

	defer listener.Close()

	s.logger.Infof("UDP tunnel listener started successfully, listening on address: %s", listener.LocalAddr().String())

	s.spawn(func() { s.acceptTunnelConn(listener) })

	<-s.ctx.Done()
}

func (s *UdpTransport) acceptTunnelConn(listener *net.UDPConn) {
	tunnels := s.tunnels

	// Buffer for UDP reads
	buf := make([]byte, 16*1024)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			n, addr, err := listener.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				s.logger.Errorf("failed to read from tunnel UDP listener: %v", err)
				continue
			}

			// Create a unique identifier for the connection based on IP and port
			key := addr.String()

			tunnels.mu.Lock()
			// Check if the connection is already active
			if existingConn, exists := tunnels.m[key]; exists {
				// Send the payload to the existing connection's payload channel
				select {
				case existingConn.payload <- append([]byte(nil), buf[:n]...): // Copy the packet to avoid data overwriting
					s.logger.Tracef("buffered %d bytes for existing connection %s", n, addr.String())
				default:
					s.logger.Warnf("payload channel for connection %s is full, dropping UDP packet", addr.String())
				}
				tunnels.mu.Unlock()
				continue
			}
			tunnels.mu.Unlock()

			if string(buf[:n]) != s.config.Token { // For new connections, validate the token
				s.logger.Errorf("invalid token received from %s", addr.String())
				continue
			}

			// Initialize the payload channel for the new connection
			payloadChan := make(chan []byte, udpFlowQueueSize)

			// Create a new TunnelUDPConn
			tunnelConn := TunnelUDPConn{
				timeCreated: time.Now().UnixNano(), // Just for debugging
				payload:     payloadChan,
				addr:        addr,
				listener:    listener,
				ping:        make(chan struct{}, 1), // Initialize the ping channel
				mu:          &sync.Mutex{},
			}

			tunnels.mu.Lock()
			// Add the new connection to the active connections map
			tunnels.m[key] = &tunnelConn
			tunnels.mu.Unlock()

			// Send the new tunnel connection to the tunnel channel
			select {
			case s.tunnelChannel <- &tunnelConn:
				s.spawn(func() { s.keepAlive(&tunnelConn) })
				s.logger.Debugf("accepted tunnel connection from %s", addr.String())
			default:
				s.logger.Warn("UDP tunnel channel is full")
				// Close the newly created connection as it couldn't be added
				tunnels.mu.Lock()
				close(tunnelConn.payload)
				delete(tunnels.m, key)
				tunnels.mu.Unlock()
			}
		}
	}
}

func (s *UdpTransport) parsePortMappings() {
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

func (s *UdpTransport) localListener(localAddr, remoteAddr string) {
	listener, ok := network.RetryListen(s.ctx, s.logger, "udp "+localAddr, func() (*net.UDPConn, error) {
		localUDPAddr, err := net.ResolveUDPAddr("udp", localAddr)
		if err != nil {
			return nil, err
		}
		return net.ListenUDP("udp", localUDPAddr)
	})
	if !ok {
		return
	}

	defer listener.Close()

	s.logger.Infof("UDP listener started successfully, listening on address: %s", listener.LocalAddr().String())

	// Buffer for UDP reads
	buf := make([]byte, 16*1024)

	// Track active connections
	activeConnections := map[string]*LocalUDPConn{}

	// mutex
	mu := &sync.Mutex{}

	// make a new channel for recieve udp packets
	udpChan := make(chan *LocalUDPConn, s.config.ChannelSize)

	// handle channel
	s.spawn(func() { s.handleLoop(udpChan, &activeConnections, mu) })

	s.spawn(func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
				n, addr, err := listener.ReadFromUDP(buf)
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					s.logger.Errorf("failed to read from UDP listener: %v", err)
					continue
				}

				// Create a unique identifier for the connection based on IP and port
				key := addr.String()

				mu.Lock()
				// Check if the connection is already active
				if existingConn, exists := activeConnections[key]; exists {
					// If connection is active and not closed, send payload
					select {
					case existingConn.payload <- append([]byte(nil), buf[:n]...):
						s.logger.Tracef("buffered %d bytes for existing connection %s", n, addr.String())
					default:
						s.logger.Warnf("payload channel for connection %s is full, dropping UDP packet", addr.String())
					}
					mu.Unlock()
					continue
				}
				mu.Unlock()

				// Create a new payload channel for this connection
				payloadChan := make(chan []byte, udpFlowQueueSize)

				// Build the UDP connection object
				newUDPConn := LocalUDPConn{
					timeCreated: time.Now().UnixMilli(), // Just for debugging
					payload:     payloadChan,
					remoteAddr:  remoteAddr,
					listener:    listener,
					addr:        addr,
				}

				mu.Lock()
				// Store the new connection
				activeConnections[key] = &newUDPConn
				mu.Unlock()

				select {
				case udpChan <- &newUDPConn:
					s.logger.Debugf("accepted UDP connection from %s", addr.String())
					payloadChan <- append([]byte(nil), buf[:n]...) // Send a copy of the new payload to the channel

					// Request a new TCP connection
					select {
					case s.reqNewConnChan <- struct{}{}:
						// Successfully requested a new TCP connection
					default:
						// The channel is full, do nothing
						s.logger.Warn("channel is full, cannot request a new connection")
					}

				default:
					s.logger.Warn("UDP channel is full, dropping packet.")
					// Close the newly created connection as it couldn't be added
					mu.Lock()
					close(newUDPConn.payload)
					delete(activeConnections, key)
					mu.Unlock()
				}
			}
		}
	})

	<-s.ctx.Done()
}

func (s *UdpTransport) handleLoop(udpChan chan *LocalUDPConn, activeConnections *map[string]*LocalUDPConn, mu *sync.Mutex) {
	for {
		select {
		case <-s.ctx.Done():
			return

		case localConn := <-udpChan:
			if time.Now().UnixMilli()-localConn.timeCreated > 3000 { // 3000ms
				s.logger.Debugf("timeouted local connection: %d ms", time.Now().UnixMilli()-localConn.timeCreated)
				mu.Lock()
				close(localConn.payload)
				delete(*activeConnections, localConn.addr.String())
				mu.Unlock()
				continue
			}

		loop:
			for {
				select {
				case <-s.ctx.Done():
					return

				case tunnelConn := <-s.tunnelChannel:
					// Stop the keepalive pinger; the lock is held for the lifetime of the tunnel
					close(tunnelConn.ping)
					tunnelConn.mu.Lock()

					// Send the target addr over the connection
					if _, err := tunnelConn.listener.WriteTo([]byte(localConn.remoteAddr), tunnelConn.addr); err != nil {
						s.logger.Errorf("%v", err)
						continue loop
					}

					// Handle data exchange between connections
					go s.udpCopy(localConn, tunnelConn, activeConnections, mu, s.tunnels, s.usageMonitor)

					s.logger.Debugf("initiate new handler for connection %s with timestamp %d", localConn.addr.String(), localConn.timeCreated)
					break loop
				}
			}
		}
	}
}

func (s *UdpTransport) udpCopy(udpLocal *LocalUDPConn, udpTunnel *TunnelUDPConn, activeConnections *map[string]*LocalUDPConn, mu *sync.Mutex, tunnels *udpConnTable, usage *web.Usage) {
	done := make(chan struct{})

	// Handle data from local to tunnel
	go func() {
		defer close(done)
		s.udpLocalCopy(udpLocal, udpTunnel, usage)
	}()

	// Handle data from tunnel to local
	s.udpTunnelCopy(udpTunnel, udpLocal, usage)

	// Remove local connection from active connections and close the channel
	mu.Lock()
	close(udpLocal.payload)
	delete(*activeConnections, udpLocal.addr.String())
	mu.Unlock()

	// Wait until the local direction is done too (it exits once its payload channel is closed)
	<-done

	// Remove tunnel connection from active connections and close the channel
	tunnels.mu.Lock()
	close(udpTunnel.payload)
	delete(tunnels.m, udpTunnel.addr.String())
	tunnels.mu.Unlock()
}

func (s *UdpTransport) udpLocalCopy(from *LocalUDPConn, to *TunnelUDPConn, usage *web.Usage) {
	inactivityTimeout := 60 * time.Second // Define a 60-second inactivity timeout
	timer := time.NewTimer(inactivityTimeout)
	defer timer.Stop()

	for {
		select {
		case data, ok := <-from.payload: // Wait for data on the UDP payload channel
			if !ok {
				return
			}

			packetSize := len(data)
			totalWritten := 0

			for totalWritten < packetSize {
				// Write the packet to the tunnel
				w, err := to.listener.WriteToUDP(data[totalWritten:], to.addr)
				if err != nil {
					s.logger.Errorf("failed to write UDP payload to tunnel: %v", err)
					return
				}
				totalWritten += w
			}

			if s.config.Sniffer {
				usage.AddOrUpdatePort(from.listener.LocalAddr().(*net.UDPAddr).Port, uint64(totalWritten))
			}

			s.logger.Debugf("forwarded %d bytes from local connection %s to tunnel", packetSize, from.addr.String())

			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(inactivityTimeout)

		case <-timer.C: // Timeout after 60 seconds of inactivity
			s.logger.Debugf("connection idle for 60 seconds, closing UDP connection for %s", from.addr.String())
			return
		}
	}
}

func (s *UdpTransport) udpTunnelCopy(from *TunnelUDPConn, to *LocalUDPConn, usage *web.Usage) {
	inactivityTimeout := 60 * time.Second // Define a 60-second inactivity timeout
	timer := time.NewTimer(inactivityTimeout)
	defer timer.Stop()

	for {
		select {
		case data, ok := <-from.payload: // Wait for data on the UDP payload channel
			if !ok {
				return
			}

			packetSize := len(data)
			totalWritten := 0

			for totalWritten < packetSize {
				// Write the packet to the tunnel
				w, err := to.listener.WriteToUDP(data[totalWritten:], to.addr)
				if err != nil {
					s.logger.Errorf("failed to write UDP payload to tunnel: %v", err)
					return
				}
				totalWritten += w
			}

			if s.config.Sniffer {
				usage.AddOrUpdatePort(to.listener.LocalAddr().(*net.UDPAddr).Port, uint64(totalWritten))
			}

			s.logger.Debugf("forwarded %d bytes from tunnel to local connection %s", packetSize, to.addr.String())

			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(inactivityTimeout)

		case <-timer.C: // Timeout after 60 seconds of inactivity
			s.logger.Debugf("connection idle for 60 seconds, closing UDP connection for %s", from.addr.String())
			return
		}
	}
}

func (s *UdpTransport) keepAlive(conn *TunnelUDPConn) {
	ticker := time.NewTicker(s.config.Heartbeat) // Send periodic pings to the client
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
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
			if _, err := conn.listener.WriteTo([]byte{utils.SG_Ping}, conn.addr); err != nil {
				conn.mu.Unlock()
				return
			}
			conn.mu.Unlock()
			s.logger.Trace("ping sent to the client")
		}
	}
}

// Done is closed once the transport's usage data has been saved after shutdown.
func (s *UdpTransport) Done() <-chan struct{} {
	return s.usageMonitor.Done()
}
