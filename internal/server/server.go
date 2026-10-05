package server

import (
	"context"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/mjhashemian/satoro-tunnel/config"
	"github.com/mjhashemian/satoro-tunnel/internal/server/transport"
	"github.com/mjhashemian/satoro-tunnel/internal/utils"

	"github.com/sirupsen/logrus"
)

type Server struct {
	config *config.ServerConfig
	ctx    context.Context
	cancel context.CancelFunc
	logger *logrus.Logger
}

func NewServer(cfg *config.ServerConfig, parentCtx context.Context) *Server {
	ctx, cancel := context.WithCancel(parentCtx)
	return &Server{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
		logger: utils.NewLogger(cfg.LogLevel),
	}
}

func (s *Server) Start() {
	// for pprof and debugging
	if s.config.PPROF {
		go func() {
			s.logger.Info("pprof started at port 6060")
			http.ListenAndServe("0.0.0.0:6060", nil)
		}()
	}

	// the running transport, so shutdown can wait for its final save
	var running interface{ Done() <-chan struct{} }

	switch s.config.Transport {
	case config.TCP:
		tcpConfig := &transport.TcpConfig{
			BindAddr:      s.config.BindAddr,
			Nodelay:       s.config.Nodelay,
			KeepAlive:     time.Duration(s.config.Keepalive) * time.Second,
			Heartbeat:     time.Duration(s.config.Heartbeat) * time.Second,
			Token:         s.config.Token,
			ChannelSize:   s.config.ChannelSize,
			Ports:         s.config.Ports,
			Sniffer:       s.config.Sniffer,
			WebPort:       s.config.WebPort,
			SnifferLog:    s.config.SnifferLog,
			AcceptUDP:     s.config.AcceptUDP,
			MSS:           s.config.MSS,
			SO_RCVBUF:     s.config.SO_RCVBUF,
			SO_SNDBUF:     s.config.SO_SNDBUF,
			ProxyProtocol: s.config.ProxyProtocol,
		}

		tcpServer := transport.NewTCPServer(s.ctx, tcpConfig, s.logger)
		go tcpServer.Start()
		running = tcpServer

	case config.TCPMUX:
		tcpMuxConfig := &transport.TcpMuxConfig{
			BindAddr:         s.config.BindAddr,
			Nodelay:          s.config.Nodelay,
			KeepAlive:        time.Duration(s.config.Keepalive) * time.Second,
			Heartbeat:        time.Duration(s.config.Heartbeat) * time.Second,
			Token:            s.config.Token,
			ChannelSize:      s.config.ChannelSize,
			Ports:            s.config.Ports,
			MuxCon:           s.config.MuxCon,
			MuxVersion:       s.config.MuxVersion,
			MaxFrameSize:     s.config.MaxFrameSize,
			MaxReceiveBuffer: s.config.MaxReceiveBuffer,
			MaxStreamBuffer:  s.config.MaxStreamBuffer,
			Sniffer:          s.config.Sniffer,
			WebPort:          s.config.WebPort,
			SnifferLog:       s.config.SnifferLog,
			MSS:              s.config.MSS,
			SO_RCVBUF:        s.config.SO_RCVBUF,
			SO_SNDBUF:        s.config.SO_SNDBUF,
			ProxyProtocol:    s.config.ProxyProtocol,
		}

		tcpMuxServer := transport.NewTcpMuxServer(s.ctx, tcpMuxConfig, s.logger)
		go tcpMuxServer.Start()
		running = tcpMuxServer

	case config.WS, config.WSS:
		wsConfig := &transport.WsConfig{
			BindAddr:    s.config.BindAddr,
			Nodelay:     s.config.Nodelay,
			KeepAlive:   time.Duration(s.config.Keepalive) * time.Second,
			Heartbeat:   time.Duration(s.config.Heartbeat) * time.Second,
			Token:       s.config.Token,
			ChannelSize: s.config.ChannelSize,
			Ports:       s.config.Ports,
			Sniffer:     s.config.Sniffer,
			WebPort:     s.config.WebPort,
			SnifferLog:  s.config.SnifferLog,
			Mode:        s.config.Transport,
			TLSCertFile: s.config.TLSCertFile,
			TLSKeyFile:  s.config.TLSKeyFile,
		}

		wsServer := transport.NewWSServer(s.ctx, wsConfig, s.logger)
		go wsServer.Start()
		running = wsServer

	case config.WSMUX, config.WSSMUX:
		wsMuxConfig := &transport.WsMuxConfig{
			BindAddr:         s.config.BindAddr,
			Nodelay:          s.config.Nodelay,
			KeepAlive:        time.Duration(s.config.Keepalive) * time.Second,
			Heartbeat:        time.Duration(s.config.Heartbeat) * time.Second,
			Token:            s.config.Token,
			ChannelSize:      s.config.ChannelSize,
			Ports:            s.config.Ports,
			MuxCon:           s.config.MuxCon,
			MuxVersion:       s.config.MuxVersion,
			MaxFrameSize:     s.config.MaxFrameSize,
			MaxReceiveBuffer: s.config.MaxReceiveBuffer,
			MaxStreamBuffer:  s.config.MaxStreamBuffer,
			Sniffer:          s.config.Sniffer,
			WebPort:          s.config.WebPort,
			SnifferLog:       s.config.SnifferLog,
			Mode:             s.config.Transport,
			TLSCertFile:      s.config.TLSCertFile,
			TLSKeyFile:       s.config.TLSKeyFile,
			ProxyProtocol:    s.config.ProxyProtocol,
		}

		wsMuxServer := transport.NewWSMuxServer(s.ctx, wsMuxConfig, s.logger)
		go wsMuxServer.Start()
		running = wsMuxServer

	case config.UDP:
		udpConfig := &transport.UdpConfig{
			BindAddr:    s.config.BindAddr,
			Heartbeat:   time.Duration(s.config.Heartbeat) * time.Second,
			Token:       s.config.Token,
			ChannelSize: s.config.ChannelSize,
			Ports:       s.config.Ports,
			Sniffer:     s.config.Sniffer,
			WebPort:     s.config.WebPort,
			SnifferLog:  s.config.SnifferLog,
		}

		udpServer := transport.NewUDPServer(s.ctx, udpConfig, s.logger)
		go udpServer.Start()
		running = udpServer

	default:
		s.logger.Fatal("invalid transport type: ", s.config.Transport)
	}

	<-s.ctx.Done()

	// Wait for the transport to save its usage data before reporting it stopped
	select {
	case <-running.Done():
	case <-time.After(3 * time.Second):
		s.logger.Warn("timed out waiting for usage data to be saved")
	}

	s.logger.Info("all workers stopped successfully")

	// suppress other logs
	s.logger.SetLevel(logrus.FatalLevel)
}

// Stop shuts down the server gracefully
func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}
