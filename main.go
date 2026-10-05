package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/mjhashemian/satoro-tunnel/cmd"
	"github.com/mjhashemian/satoro-tunnel/config"
	"github.com/mjhashemian/satoro-tunnel/internal/utils"
)

var (
	logger     = utils.NewLogger("info")
	configPath *string
)

// Define the version of the application
const version = "v0.7.2"

// instance is the currently running server or client.
type instance struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// start runs cfg in the background.
func (i *instance) start(cfg *config.Config) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	i.mu.Lock()
	i.cancel = cancel
	i.done = done
	i.mu.Unlock()

	go func() {
		defer close(done)
		cmd.Run(cfg, ctx)
	}()
}

// stop cancels the running instance and waits for it to return, up to timeout.
func (i *instance) stop(timeout time.Duration) {
	i.mu.Lock()
	cancel, done := i.cancel, i.done
	i.mu.Unlock()

	if cancel == nil {
		return
	}

	cancel()

	select {
	case <-done:
	case <-time.After(timeout):
		logger.Warn("timed out waiting for the running instance to stop")
	}
}

func main() {
	configPath = flag.String("c", "", "path to the configuration file (TOML format)")
	showVersion := flag.Bool("v", false, "print the version and exit")

	flag.Parse()

	// If the version flag is provided, print the version and exit
	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	// Check if the configPath is provided
	if *configPath == "" {
		logger.Fatalf("Usage: %s -c /path/to/config.toml", flag.CommandLine.Name())
	}

	cfg, err := cmd.Load(*configPath)
	if err != nil {
		logger.Fatalf("failed to load configuration: %v", err)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	app := &instance{}
	app.start(cfg)

	stopReload := make(chan struct{})
	go hotReload(app, stopReload)

	<-sigChan

	close(stopReload)
	app.stop(5 * time.Second) // the transport may take up to 3s to save its usage data

	// give background workers a moment to close their connections
	time.Sleep(1 * time.Second)
}

func hotReload(app *instance, stop <-chan struct{}) {
	// Get initial modification time of the config file
	lastModTime, err := getLastModTime(*configPath)
	if err != nil {
		logger.Fatalf("Error getting modification time: %v", err)
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			modTime, err := getLastModTime(*configPath)
			if err != nil {
				logger.Errorf("Error checking file modification time: %v", err)
				continue
			}

			// If the modification time has changed, reload the app
			if modTime.After(lastModTime) {
				lastModTime = modTime

				// Validate the new configuration before touching the running instance
				cfg, err := cmd.Load(*configPath)
				if err != nil {
					logger.Errorf("config file changed but is invalid, keeping the current instance: %v", err)
					continue
				}

				logger.Info("Config file changed, reloading application")

				// Stop the old running instance, then start the new one
				app.stop(5 * time.Second)
				app.start(cfg)
			}
		}
	}
}

func getLastModTime(file string) (time.Time, error) {
	absPath, _ := filepath.Abs(file)
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		return time.Time{}, err
	}
	return fileInfo.ModTime(), nil
}
