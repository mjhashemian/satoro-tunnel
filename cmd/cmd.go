package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/mjhashemian/satoro-tunnel/config"
	"github.com/mjhashemian/satoro-tunnel/internal/client"

	"github.com/mjhashemian/satoro-tunnel/internal/server"
	"github.com/mjhashemian/satoro-tunnel/internal/utils"
	"github.com/mjhashemian/satoro-tunnel/internal/utils/portmap"

	"github.com/BurntSushi/toml"
)

var (
	logger = utils.NewLogger("info")
)

// Load reads, defaults and validates the configuration file.
func Load(configPath string) (*config.Config, error) {
	var cfg config.Config
	if _, err := toml.DecodeFile(configPath, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", configPath, err)
	}

	// Apply default values to the configuration
	applyDefaults(&cfg)

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func validate(cfg *config.Config) error {
	switch {
	case cfg.Server.BindAddr != "":
		if !validTransport(cfg.Server.Transport) {
			return fmt.Errorf("invalid server transport type: %q", cfg.Server.Transport)
		}

		if _, err := portmap.Parse(cfg.Server.Ports); err != nil {
			return err
		}

		if cfg.Server.Transport == config.WSS || cfg.Server.Transport == config.WSSMUX {
			if err := fileExists("tls_cert", cfg.Server.TLSCertFile); err != nil {
				return err
			}
			if err := fileExists("tls_key", cfg.Server.TLSKeyFile); err != nil {
				return err
			}
		}

	case cfg.Client.RemoteAddr != "":
		if !validTransport(cfg.Client.Transport) {
			return fmt.Errorf("invalid client transport type: %q", cfg.Client.Transport)
		}

	default:
		return errors.New("neither server nor client configuration is properly set")
	}

	return nil
}

func validTransport(t config.TransportType) bool {
	switch t {
	case config.TCP, config.TCPMUX, config.WS, config.WSS, config.WSMUX, config.WSSMUX, config.UDP:
		return true
	}
	return false
}

func fileExists(option, path string) error {
	if path == "" {
		return fmt.Errorf("%s is required for wss/wssmux transports", option)
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s: %w", option, err)
	}
	return nil
}

// Run starts a validated configuration (see Load) and blocks until ctx is done.
func Run(cfg *config.Config, ctx context.Context) {
	// Determine whether to run as a server or client
	if cfg.Server.BindAddr != "" {
		// Apply temporary TCP optimizations at startup
		if !cfg.Server.SkipOptz {
			ApplyTCPTuning()
		}

		srv := server.NewServer(&cfg.Server, ctx) // server
		go srv.Start()

		// Wait for shutdown signal
		<-ctx.Done()
		srv.Stop()
		utils.NewLogger(cfg.Server.LogLevel).Info("shutting down server...")
		return
	}

	// Apply temporary TCP optimizations at startup
	if !cfg.Client.SkipOptz {
		ApplyTCPTuning()
	}

	clnt := client.NewClient(&cfg.Client, ctx) // client
	go clnt.Start()

	// Wait for shutdown signal
	<-ctx.Done()
	clnt.Stop()
	utils.NewLogger(cfg.Client.LogLevel).Info("shutting down client...")
}
