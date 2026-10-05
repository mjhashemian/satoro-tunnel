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
	"path/filepath"
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

const (
	saveInterval        = 15 * time.Second // how often per-port usage is merged into sniffer_log
	statsInterval       = 2 * time.Second  // how often system stats are collected for the panel
	connectionsInterval = 10 * time.Second // counting every socket is expensive, so do it less often
)

// Usage holds the per-port traffic counters, the tunnel status and the web panel.
// A transport creates one Usage for its whole lifetime, so the counters and the panel
// survive transport restarts.
type Usage struct {
	listenAddr string
	ctx        context.Context // ends when the transport shuts down
	logger     *logrus.Logger
	sniffer    bool
	snifferLog string
	startOnce  sync.Once
	done       chan struct{} // closed once the final save after shutdown has finished

	pending sync.Map // int port -> *atomic.Uint64, bytes not yet saved

	saveMu       sync.Mutex // serialises saves to snifferLog
	totalsMu     sync.RWMutex
	totals       map[int]uint64 // usage as of the last save, merged with snifferLog
	totalsLoaded bool
	totalTraffic atomic.Uint64 // sum of totals

	tunnelStatus atomic.Pointer[string]

	stats   atomic.Pointer[SystemStats] // latest collected system stats
	statsMu sync.Mutex                  // guards the collector state below
	lastNet *net.IOCountersStat
	lastAt  time.Time
	conns   int
	connsAt time.Time
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

// NewDataStore creates the usage store. ctx should live as long as the transport
// (not a single run of it), so restarts keep the panel and the counters.
func NewDataStore(listenAddr string, ctx context.Context, snifferLog string, sniffer bool, logger *logrus.Logger) *Usage {
	u := &Usage{
		listenAddr: listenAddr,
		ctx:        ctx,
		logger:     logger,
		sniffer:    sniffer,
		snifferLog: snifferLog,
		totals:     map[int]uint64{},
		done:       make(chan struct{}),
	}
	u.SetStatus("")
	return u
}

// SetStatus sets the tunnel status shown in the web interface.
func (m *Usage) SetStatus(status string) {
	m.tunnelStatus.Store(&status)
}

// PortCounter returns the counter for bytes transferred on port. Copy loops fetch it
// once per connection and call Add per write; no lock is taken.
func (m *Usage) PortCounter(port int) *atomic.Uint64 {
	if v, ok := m.pending.Load(port); ok {
		return v.(*atomic.Uint64)
	}
	v, _ := m.pending.LoadOrStore(port, new(atomic.Uint64))
	return v.(*atomic.Uint64)
}

// AddOrUpdatePort records usage bytes for port.
func (m *Usage) AddOrUpdatePort(port int, usage uint64) {
	m.PortCounter(port).Add(usage)
}

// Start runs the background work once per Usage: saving per-port usage when the sniffer
// is on, and the web panel when web is true. Later calls (e.g. after a restart) do nothing.
func (m *Usage) Start(web bool) {
	m.startOnce.Do(func() {
		if m.sniffer {
			go m.saveLoop()
		} else {
			close(m.done) // nothing to save on shutdown
		}
		if web {
			go m.serve()
		}
	})
}

// Done is closed after the Usage has stopped and saved what it counted. Callers should
// wait with a timeout: it never closes if Start was not called.
func (m *Usage) Done() <-chan struct{} {
	return m.done
}

func (m *Usage) saveLoop() {
	defer close(m.done)

	m.ensureTotals()

	ticker := time.NewTicker(saveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.saveUsageData()
		case <-m.ctx.Done():
			m.saveUsageData() // keep what was counted since the last save
			return
		}
	}
}

func (m *Usage) serve() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", m.handleIndex)
	mux.HandleFunc("/stats", m.statsHandler)
	if m.sniffer {
		mux.HandleFunc("/data", m.handleData)
	}
	server := &http.Server{
		Addr:              m.listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Collect system stats in the background, so requests never wait for them
	go func() {
		m.collectStats()

		ticker := time.NewTicker(statsInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.collectStats()
			case <-m.ctx.Done():
				return
			}
		}
	}()

	go func() {
		<-m.ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			m.logger.Errorf("web panel shutdown error: %v", err)
		}
	}()

	// Retry while the port is busy (e.g. during a hot reload)
	listener, ok := network.RetryListen(m.ctx, m.logger, "web interface "+m.listenAddr, func() (stdnet.Listener, error) {
		return stdnet.Listen("tcp", m.listenAddr)
	})
	if !ok {
		return
	}

	m.logger.Info("web panel listening on: ", m.listenAddr)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		m.logger.Errorf("web panel error: %v", err)
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
	m.ensureTotals()

	// saved totals plus whatever was counted since the last save
	usage := map[int]uint64{}
	m.totalsMu.RLock()
	for port, n := range m.totals {
		usage[port] = n
	}
	m.totalsMu.RUnlock()

	m.pending.Range(func(key, value any) bool {
		if n := value.(*atomic.Uint64).Load(); n > 0 {
			usage[key.(int)] += n
		}
		return true
	})

	rows := make([]PortUsageView, 0, len(usage)) // encodes as [] rather than null
	for port, n := range usage {
		rows = append(rows, PortUsageView{Port: port, Usage: n, ReadableUsage: m.convertBytesToReadable(n)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Port < rows[j].Port })

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rows); err != nil {
		m.logger.Errorf("error encoding JSON response: %v", err)
	}
}

func (m *Usage) statsHandler(w http.ResponseWriter, r *http.Request) {
	snapshot := m.stats.Load()
	if snapshot == nil {
		// the collector has not run yet
		m.collectStats()
		snapshot = m.stats.Load()
	}
	if snapshot == nil {
		http.Error(w, "failed to read system stats", http.StatusInternalServerError)
		return
	}

	stats := *snapshot
	stats.TunnelStatus = *m.tunnelStatus.Load()
	stats.TunnelTraffic = m.convertBytesToReadable(m.totalTraffic.Load() + m.pendingTotal())

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		m.logger.Error("Error encoding JSON:", err)
	}
}

// pendingTotal is the sum of bytes counted since the last save.
func (m *Usage) pendingTotal() uint64 {
	var total uint64
	m.pending.Range(func(_, value any) bool {
		total += value.(*atomic.Uint64).Load()
		return true
	})
	return total
}

// ensureTotals loads the saved usage from snifferLog the first time it is needed.
func (m *Usage) ensureTotals() {
	m.totalsMu.RLock()
	loaded := m.totalsLoaded
	m.totalsMu.RUnlock()
	if loaded {
		return
	}

	m.saveMu.Lock()
	defer m.saveMu.Unlock()

	usage := m.readUsageFile()
	m.setTotals(usage)
}

func (m *Usage) setTotals(usage map[int]uint64) {
	var sum uint64
	for _, n := range usage {
		sum += n
	}

	m.totalsMu.Lock()
	m.totals = usage
	m.totalsLoaded = true
	m.totalsMu.Unlock()

	m.totalTraffic.Store(sum)
}

// readUsageFile reads snifferLog. A missing file is empty; a corrupt one is moved aside
// so saving can continue.
func (m *Usage) readUsageFile() map[int]uint64 {
	usage := map[int]uint64{}

	data, err := os.ReadFile(m.snifferLog)
	if err != nil {
		if !os.IsNotExist(err) {
			m.logger.Errorf("error reading usage file: %v", err)
		}
		return usage
	}

	var saved []PortUsage
	if err := json.Unmarshal(data, &saved); err != nil {
		corrupt := m.snifferLog + ".corrupt"
		m.logger.Errorf("usage file %s is not valid JSON (%v); moving it to %s and starting over", m.snifferLog, err, corrupt)
		if err := os.Rename(m.snifferLog, corrupt); err != nil {
			m.logger.Errorf("failed to move corrupt usage file: %v", err)
		}
		return usage
	}

	for _, u := range saved {
		usage[u.Port] += u.Usage
	}
	return usage
}

// saveUsageData merges the pending counters into snifferLog. Reading the file on every
// save keeps an old and a new instance (during a hot reload) from overwriting each other.
func (m *Usage) saveUsageData() {
	m.saveMu.Lock()
	defer m.saveMu.Unlock()

	usage := m.readUsageFile()

	// take the pending bytes
	deltas := map[int]uint64{}
	m.pending.Range(func(key, value any) bool {
		if n := value.(*atomic.Uint64).Swap(0); n > 0 {
			deltas[key.(int)] = n
		}
		return true
	})

	for port, n := range deltas {
		usage[port] += n
	}

	if len(deltas) > 0 {
		if err := m.writeUsageFile(usage); err != nil {
			m.logger.Errorf("error writing usage data: %v", err)
			// keep the bytes for the next attempt
			for port, n := range deltas {
				m.PortCounter(port).Add(n)
				usage[port] -= n
			}
		}
	}

	m.setTotals(usage)
}

// writeUsageFile replaces snifferLog atomically, so a crash never leaves a half-written file.
func (m *Usage) writeUsageFile(usage map[int]uint64) error {
	rows := make([]PortUsage, 0, len(usage))
	for port, n := range usage {
		rows = append(rows, PortUsage{Port: port, Usage: n})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Port < rows[j].Port })

	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(m.snifferLog), filepath.Base(m.snifferLog)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), m.snifferLog)
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

// collectStats refreshes the cached system stats. Speeds come from the interface
// counters' change since the previous collection.
func (m *Usage) collectStats() {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()

	now := time.Now()

	netStats, err := net.IOCounters(false)
	if err != nil || len(netStats) == 0 {
		m.logger.Debugf("failed to read network counters: %v", err)
		return
	}
	current := netStats[0]

	var uploadSpeed, downloadSpeed float64
	if m.lastNet != nil {
		if elapsed := now.Sub(m.lastAt).Seconds(); elapsed > 0 {
			uploadSpeed = rate(current.BytesSent, m.lastNet.BytesSent, elapsed)
			downloadSpeed = rate(current.BytesRecv, m.lastNet.BytesRecv, elapsed)
		}
	}
	m.lastNet = &current
	m.lastAt = now

	cpuPercent, err := cpu.Percent(0, false)
	if err != nil || len(cpuPercent) == 0 {
		m.logger.Debugf("failed to read CPU usage: %v", err)
		return
	}

	memStats, err := mem.VirtualMemory()
	if err != nil {
		m.logger.Debugf("failed to read memory usage: %v", err)
		return
	}

	diskStats, err := disk.Usage("/")
	if err != nil {
		m.logger.Debugf("failed to read disk usage: %v", err)
		return
	}

	swapStats, err := mem.SwapMemory()
	if err != nil {
		m.logger.Debugf("failed to read swap usage: %v", err)
		return
	}

	if m.connsAt.IsZero() || now.Sub(m.connsAt) >= connectionsInterval {
		if connections, err := net.Connections("all"); err == nil {
			m.conns = len(connections)
			m.connsAt = now
		}
	}

	stats := &SystemStats{
		CPUUsage:       m.formatFloat(cpuPercent[0]),
		RAMUsage:       m.convertBytesToReadable(memStats.Used),
		DiskUsage:      m.convertBytesToReadable(diskStats.Used),
		SwapUsage:      m.convertBytesToReadable(swapStats.Used),
		NetworkTraffic: m.convertBytesToReadable(current.BytesSent + current.BytesRecv),
		DownloadSpeed:  m.formatSpeed(downloadSpeed),
		UploadSpeed:    m.formatSpeed(uploadSpeed),
		Sniffer:        map[bool]string{true: "Running", false: "Not running"}[m.sniffer],
		AllConnections: fmt.Sprintf("%d", m.conns),

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

	m.stats.Store(stats)
}

// rate is bytes per second between two counter readings; a counter reset gives 0.
func rate(current, previous uint64, seconds float64) float64 {
	if current < previous {
		return 0
	}
	return float64(current-previous) / seconds
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
