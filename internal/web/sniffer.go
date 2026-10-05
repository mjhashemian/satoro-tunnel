package web

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	stdnet "net"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mjhashemian/satoro-tunnel/internal/utils/network"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"

	"github.com/sirupsen/logrus"
)

type Usage struct {
	dataStore    sync.Map
	listenAddr   string
	shutdownCtx  context.Context
	cancelFunc   context.CancelFunc
	server       *http.Server
	logger       *logrus.Logger
	sniffer      bool
	snifferLog   string
	mu           sync.Mutex
	totalTraffic atomic.Uint64
	tunnelStatus atomic.Pointer[string]
}

type PortUsage struct {
	Port  int
	Usage uint64
}

type SystemStats struct {
	TunnelStatus   string `json:"tunnelStatus"`
	CPUUsage       string `json:"cpuUsage"`
	RAMUsage       string `json:"ramUsage"`
	DiskUsage      string `json:"diskUsage"`
	SwapUsage      string `json:"swapUsage"`
	NetworkTraffic string `json:"networkTraffic"`
	UploadSpeed    string `json:"uploadSpeed"`
	DownloadSpeed  string `json:"downloadSpeed"`
	TunnelTraffic  string `json:"tunnelTraffic"`
	Sniffer        string `json:"sniffer"`
	AllConnections string `json:"allConnections"`

	// Raw values for the panel's gauges and charts
	CPUPercent    float64 `json:"cpuPercent"`
	RAMPercent    float64 `json:"ramPercent"`
	RAMTotal      string  `json:"ramTotal"`
	DiskPercent   float64 `json:"diskPercent"`
	DiskTotal     string  `json:"diskTotal"`
	SwapPercent   float64 `json:"swapPercent"`
	SwapTotal     string  `json:"swapTotal"`
	UploadBps     float64 `json:"uploadBps"`
	DownloadBps   float64 `json:"downloadBps"`
	SnifferOn     bool    `json:"snifferOn"`
	Hostname      string  `json:"hostname"`
	UptimeSeconds uint64  `json:"uptimeSeconds"`
}

// PortUsageView is one row of the /data response.
type PortUsageView struct {
	Port          int
	Usage         uint64
	ReadableUsage string
}

func NewDataStore(listenAddr string, shutdownCtx context.Context, snifferLog string, sniffer bool, logger *logrus.Logger) *Usage {
	ctx, cancel := context.WithCancel(shutdownCtx)
	u := &Usage{
		listenAddr:  listenAddr,
		shutdownCtx: ctx,
		cancelFunc:  cancel,
		logger:      logger,
		sniffer:     sniffer,
		snifferLog:  snifferLog,
	}
	u.SetStatus("")
	return u
}

// SetStatus sets the tunnel status shown in the web interface.
func (m *Usage) SetStatus(status string) {
	m.tunnelStatus.Store(&status)
}

func (m *Usage) Monitor() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", m.handleIndex) // handle index
	mux.HandleFunc("/stats", m.statsHandler)
	if m.sniffer {
		mux.HandleFunc("/data", m.handleData) // New route for JSON data
	}
	m.server = &http.Server{
		Addr:    m.listenAddr,
		Handler: mux,
	}

	go func() {
		<-m.shutdownCtx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Attempt to gracefully shut down the server
		if err := m.server.Shutdown(shutdownCtx); err != nil {
			m.logger.Errorf("sniffer server shutdown error: %v", err)
		}
	}()

	// start save data
	if m.sniffer {
		go func() {
			ticker := time.NewTicker(15 * time.Second) // every 15 seconds
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					m.saveUsageData()
				case <-m.shutdownCtx.Done():
					return
				}
			}
		}()
	}

	// Start the server, retrying while the port is busy (e.g. during a restart)
	listener, ok := network.RetryListen(m.shutdownCtx, m.logger, "web interface "+m.listenAddr, func() (stdnet.Listener, error) {
		return stdnet.Listen("tcp", m.listenAddr)
	})
	if !ok {
		return
	}

	m.logger.Info("sniffer service listening on port: ", m.listenAddr)
	if err := m.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		m.logger.Errorf("sniffer server error: %v", err)
	}
}

// The panel is a single self-contained page: no CDN, fonts or scripts are fetched,
// so it also works on servers that cannot reach the internet.
//
//go:embed index.html
var indexHTML []byte

func (m *Usage) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if _, err := w.Write(indexHTML); err != nil {
		m.logger.Debugf("error writing index page: %v", err)
	}
}

func (m *Usage) handleData(w http.ResponseWriter, r *http.Request) {
	usageData := m.getUsageFromFile()
	readableData := m.usageDataWithReadableUsage(usageData)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(readableData); err != nil {
		m.logger.Errorf("error encoding JSON response: %v", err)
	}
}

func (m *Usage) statsHandler(w http.ResponseWriter, r *http.Request) {
	stats, err := m.getSystemStats()
	if err != nil {
		m.logger.Error("Error fetching system stats:", err)
		http.Error(w, "failed to read system stats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		m.logger.Error("Error encoding JSON:", err)
	}
}

func (m *Usage) AddOrUpdatePort(port int, usage uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Retrieve current usage data for the port
	value, ok := m.dataStore.Load(port)
	if ok {
		// Port exists, update usage
		portUsage := value.(PortUsage)
		portUsage.Usage += usage
		m.dataStore.Store(port, portUsage)
	} else {
		// Port does not exist, create new entry
		m.dataStore.Store(port, PortUsage{Port: port, Usage: usage})
	}
}

func (m *Usage) saveUsageData() {
	// Step 1: Load existing usage data from the JSON file
	var existingUsageData []PortUsage
	file, err := os.Open(m.snifferLog)
	if err == nil {
		// If the file exists, decode the JSON data into existingUsageData
		defer file.Close()
		err = json.NewDecoder(file).Decode(&existingUsageData)
		if err != nil {
			m.logger.Errorf("error decoding JSON data: %v", err)
			return
		}
	} else if !os.IsNotExist(err) {
		// Log any error except file not existing
		m.logger.Errorf("error opening JSON file: %v", err)
		return
	}

	// Step 2: Get current usage data from sync.Map
	currentUsageData := m.collectUsageDataFromSyncMap()

	// Step 3: Merge the existing and current usage data into a map to avoid duplicates
	usageMap := make(map[int]PortUsage)

	// Add existing usage data to the map
	for _, usage := range existingUsageData {
		usageMap[usage.Port] = usage
	}

	// Append or update current usage data in the map
	for _, usage := range currentUsageData {
		if existing, exists := usageMap[usage.Port]; exists {
			// Update existing port usage
			existing.Usage += usage.Usage
			usageMap[usage.Port] = existing
		} else {
			// Add new port usage
			usageMap[usage.Port] = usage
		}
	}

	// Step 4: Convert the map back to a slice
	var mergedUsageData []PortUsage
	var totalTraffic uint64
	for _, usage := range usageMap {
		mergedUsageData = append(mergedUsageData, usage)
		totalTraffic += usage.Usage
	}
	m.totalTraffic.Store(totalTraffic)

	// Step 5: Convert merged data to JSON
	data, err := json.MarshalIndent(mergedUsageData, "", "  ")
	if err != nil {
		m.logger.Errorf("error marshalling usage data: %v", err)
		return
	}

	// Step 6: Write JSON data to file
	err = os.WriteFile(m.snifferLog, data, 0644)
	if err != nil {
		m.logger.Errorf("error writing usage data to file: %v", err)
	}
}

func (m *Usage) getUsageFromFile() []PortUsage {
	// Check if the file exists
	if _, err := os.Stat(m.snifferLog); os.IsNotExist(err) {
		// If the file does not exist, create it and write "null"
		file, err := os.OpenFile(m.snifferLog, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			m.logger.Errorf("error creating file: %v", err)
			return nil
		}

		// Write "null" to the new file
		if _, err := file.Write([]byte("null")); err != nil {
			m.logger.Errorf("error writing 'null' to the file: %v", err)
			file.Close()
			return nil
		}

		return nil
	}

	var usageData []PortUsage

	// Open the JSON file
	file, err := os.Open(m.snifferLog)
	if err != nil {
		m.logger.Errorf("error opening JSON file: %v", err)
		return nil
	}
	defer file.Close()

	// Decode the JSON file into the usageData slice
	err = json.NewDecoder(file).Decode(&usageData)
	if err != nil {
		m.logger.Errorf("error decoding JSON data: %v", err)
		return nil
	}

	// Sort usageData by Port in ascending order
	sort.Slice(usageData, func(i, j int) bool {
		return usageData[i].Port < usageData[j].Port
	})

	return usageData
}

// converts the byte usage to a human-readable format
func (m *Usage) usageDataWithReadableUsage(usageData []PortUsage) []PortUsageView {
	result := make([]PortUsageView, 0, len(usageData)) // encodes as [] rather than null

	for _, portUsage := range usageData {
		result = append(result, PortUsageView{
			Port:          portUsage.Port,
			Usage:         portUsage.Usage,
			ReadableUsage: m.convertBytesToReadable(portUsage.Usage),
		})
	}

	return result
}

// collectUsageDataFromSyncMap gathers data from sync.Map
func (m *Usage) collectUsageDataFromSyncMap() []PortUsage {
	m.mu.Lock()
	defer m.mu.Unlock()

	var usageData []PortUsage
	m.dataStore.Range(func(key, value interface{}) bool {
		if portUsage, ok := value.(PortUsage); ok {
			usageData = append(usageData, portUsage)
			m.dataStore.Delete(key)
		}
		return true
	})
	return usageData
}

// ConvertBytesToReadable converts bytes into a human-readable format (KB, MB, GB)
func (m *Usage) convertBytesToReadable(bytes uint64) string {
	const (
		KB = 1 << (10 * 1) // 1024 bytes
		MB = 1 << (10 * 2) // 1024 KB
		GB = 1 << (10 * 3) // 1024 MB
		TB = 1 << (10 * 4) // 1024 TB
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/float64(TB))
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes) // Bytes
	}
}

func (m *Usage) getSystemStats() (*SystemStats, error) {

	// Get initial network stats
	initialStats, err := m.getNetworkStats()
	if err != nil {
		return nil, err
	}

	// Wait for 1 second
	time.Sleep(1 * time.Second)

	// Get updated network stats
	finalStats, err := m.getNetworkStats()
	if err != nil {
		return nil, err
	}

	// Get CPU usage
	cpuPercent, err := cpu.Percent(0, false)
	if err != nil {
		return nil, err
	}

	// Get RAM usage
	memStats, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	// Get Disk usage
	diskStats, err := disk.Usage("/")
	if err != nil {
		return nil, err
	}

	// Get Swap usage
	swapStats, err := mem.SwapMemory()
	if err != nil {
		return nil, err
	}

	// Get Network traffic
	netStats, err := net.IOCounters(false)
	if err != nil {
		return nil, err
	}

	// Get all active network connections (TCP, UDP, etc.)
	connections, err := net.Connections("all")
	if err != nil {
		return nil, err
	}

	// Calculate upload and download speeds
	uploadSpeed := float64(finalStats.BytesSent - initialStats.BytesSent)
	downloadSpeed := float64(finalStats.BytesRecv - initialStats.BytesRecv)

	stats := &SystemStats{
		TunnelStatus:   *m.tunnelStatus.Load(),
		CPUUsage:       m.formatFloat(cpuPercent[0]),
		RAMUsage:       m.convertBytesToReadable(memStats.Used),
		DiskUsage:      m.convertBytesToReadable(diskStats.Used),
		SwapUsage:      m.convertBytesToReadable(swapStats.Used),
		NetworkTraffic: m.convertBytesToReadable(netStats[0].BytesSent + netStats[0].BytesRecv),
		DownloadSpeed:  m.formatSpeed(downloadSpeed),
		UploadSpeed:    m.formatSpeed(uploadSpeed),
		TunnelTraffic:  m.convertBytesToReadable(m.totalTraffic.Load()),
		Sniffer:        map[bool]string{true: "Running", false: "Not running"}[m.sniffer],
		AllConnections: fmt.Sprintf("%d", len(connections)),

		CPUPercent:  cpuPercent[0],
		RAMPercent:  memStats.UsedPercent,
		RAMTotal:    m.convertBytesToReadable(memStats.Total),
		DiskPercent: diskStats.UsedPercent,
		DiskTotal:   m.convertBytesToReadable(diskStats.Total),
		SwapPercent: swapStats.UsedPercent,
		SwapTotal:   m.convertBytesToReadable(swapStats.Total),
		UploadBps:   uploadSpeed,
		DownloadBps: downloadSpeed,
		SnifferOn:   m.sniffer,
	}

	// Host details are informational only, so failures are ignored
	if hostname, err := os.Hostname(); err == nil {
		stats.Hostname = hostname
	}
	if uptime, err := host.Uptime(); err == nil {
		stats.UptimeSeconds = uptime
	}

	return stats, nil
}

func (m *Usage) formatSpeed(bytesPerSec float64) string {
	if bytesPerSec >= 1e9 {
		return fmt.Sprintf("%.2f GB/s", bytesPerSec/1e9)
	} else if bytesPerSec >= 1e6 {
		return fmt.Sprintf("%.2f MB/s", bytesPerSec/1e6)
	} else if bytesPerSec >= 1e3 {
		return fmt.Sprintf("%.2f KB/s", bytesPerSec/1e3)
	}
	return fmt.Sprintf("%.2f B/s", bytesPerSec)
}

func (m *Usage) formatFloat(value float64) string {
	return fmt.Sprintf("%.2f%%", value)
}

func (m *Usage) getNetworkStats() (*net.IOCountersStat, error) {
	ioCounters, err := net.IOCounters(false)
	if err != nil {
		return nil, err
	}
	if len(ioCounters) == 0 {
		return nil, fmt.Errorf("no network IO counters found")
	}
	return &ioCounters[0], nil
}
