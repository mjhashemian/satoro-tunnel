package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func newTestUsage(t *testing.T, sniffer bool) *Usage {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return NewDataStore(":0", context.Background(), filepath.Join(t.TempDir(), "usage.json"), sniffer, logger)
}

func TestIndexIsSelfContained(t *testing.T) {
	u := newTestUsage(t, false)

	rec := httptest.NewRecorder()
	u.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "satoro") {
		t.Fatal("panel does not carry the satoro-tunnel branding")
	}

	// The panel must not load anything from the network (servers often have no internet access).
	external := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']?(https?:)?//`)
	if m := external.FindString(body); m != "" {
		t.Fatalf("panel references an external resource: %q", m)
	}
	if strings.Contains(body, "@import") {
		t.Fatal("panel uses a CSS @import")
	}
}

func TestIndexUnknownPath(t *testing.T) {
	u := newTestUsage(t, false)

	rec := httptest.NewRecorder()
	u.handleIndex(rec, httptest.NewRequest(http.MethodGet, "/data", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (the panel relies on it to detect a disabled sniffer)", rec.Code)
	}
}

func TestStats(t *testing.T) {
	u := newTestUsage(t, true)
	u.SetStatus("Connected (TCP)")

	rec := httptest.NewRecorder()
	u.statsHandler(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
	}

	var stats map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}

	if stats["tunnelStatus"] != "Connected (TCP)" {
		t.Fatalf("tunnelStatus = %v", stats["tunnelStatus"])
	}
	if stats["snifferOn"] != true {
		t.Fatalf("snifferOn = %v", stats["snifferOn"])
	}

	// the panel reads both the formatted and the raw fields
	for _, key := range []string{
		"cpuUsage", "ramUsage", "diskUsage", "swapUsage", "networkTraffic", "uploadSpeed", "downloadSpeed",
		"tunnelTraffic", "allConnections",
		"cpuPercent", "ramPercent", "ramTotal", "diskPercent", "diskTotal", "swapPercent", "swapTotal",
		"uploadBps", "downloadBps", "uptimeSeconds",
	} {
		if _, ok := stats[key]; !ok {
			t.Errorf("/stats is missing %q", key)
		}
	}
}

func TestDataEmptyAndFilled(t *testing.T) {
	u := newTestUsage(t, true)

	rec := httptest.NewRecorder()
	u.handleData(rec, httptest.NewRequest(http.MethodGet, "/data", nil))
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Fatalf("empty /data = %q, want []", got)
	}

	u.AddOrUpdatePort(443, 1024)
	u.AddOrUpdatePort(443, 1024)
	u.AddOrUpdatePort(80, 10)
	u.saveUsageData()

	rec = httptest.NewRecorder()
	u.handleData(rec, httptest.NewRequest(http.MethodGet, "/data", nil))

	var rows []PortUsageView
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Port != 80 || rows[1].Port != 443 {
		t.Fatalf("rows = %+v, want ports 80 and 443 sorted", rows)
	}
	if rows[1].Usage != 2048 || rows[1].ReadableUsage != "2.00 KB" {
		t.Fatalf("port 443 = %+v, want 2048 bytes / 2.00 KB", rows[1])
	}
	if u.totalTraffic.Load() != 2058 {
		t.Fatalf("total traffic = %d, want 2058", u.totalTraffic.Load())
	}
}

// readSaved decodes the usage file into port -> bytes.
func readSaved(t *testing.T, path string) map[int]uint64 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []PortUsage
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatalf("usage file is not valid JSON: %v\n%s", err, data)
	}
	got := map[int]uint64{}
	for _, r := range rows {
		got[r.Port] = r.Usage
	}
	return got
}

func TestConcurrentCountingWhileSaving(t *testing.T) {
	u := newTestUsage(t, true)

	const workers, adds = 16, 5000
	ports := []int{80, 443, 8080, 9000}

	stop := make(chan struct{})
	saverDone := make(chan struct{})
	go func() {
		defer close(saverDone)
		for {
			select {
			case <-stop:
				return
			default:
				u.saveUsageData()
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			counter := u.PortCounter(ports[w%len(ports)])
			for i := 0; i < adds; i++ {
				counter.Add(3)
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	<-saverDone
	u.saveUsageData()

	got := readSaved(t, u.snifferLog)
	perPort := uint64(workers/len(ports)) * adds * 3
	for _, p := range ports {
		if got[p] != perPort {
			t.Errorf("port %d saved %d bytes, want %d", p, got[p], perPort)
		}
	}
	if total := u.totalTraffic.Load(); total != perPort*uint64(len(ports)) {
		t.Errorf("total traffic = %d, want %d", total, perPort*uint64(len(ports)))
	}
}

func TestDataIncludesUnsavedUsage(t *testing.T) {
	u := newTestUsage(t, true)
	u.AddOrUpdatePort(443, 5000)

	rec := httptest.NewRecorder()
	u.handleData(rec, httptest.NewRequest(http.MethodGet, "/data", nil))

	var rows []PortUsageView
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Port != 443 || rows[0].Usage != 5000 {
		t.Fatalf("rows = %+v, want port 443 with 5000 bytes before any save", rows)
	}
}

func TestSaveMergesWithExistingFile(t *testing.T) {
	u := newTestUsage(t, true)
	if err := os.WriteFile(u.snifferLog, []byte(`[{"Port":443,"Usage":100}]`), 0644); err != nil {
		t.Fatal(err)
	}

	u.AddOrUpdatePort(443, 50)
	u.AddOrUpdatePort(22, 7)
	u.saveUsageData()

	got := readSaved(t, u.snifferLog)
	if got[443] != 150 || got[22] != 7 {
		t.Fatalf("saved %v, want 443=150 and 22=7", got)
	}
}

func TestCorruptUsageFileIsReplaced(t *testing.T) {
	u := newTestUsage(t, true)
	if err := os.WriteFile(u.snifferLog, []byte(`[{"Port":443,"Usa`), 0644); err != nil {
		t.Fatal(err)
	}

	u.AddOrUpdatePort(443, 10)
	u.saveUsageData()

	if got := readSaved(t, u.snifferLog); got[443] != 10 {
		t.Fatalf("saved %v, want 443=10", got)
	}
	if _, err := os.Stat(u.snifferLog + ".corrupt"); err != nil {
		t.Fatalf("corrupt file was not kept aside: %v", err)
	}
}

func TestStatsAreCached(t *testing.T) {
	u := newTestUsage(t, true)
	u.collectStats()
	u.AddOrUpdatePort(443, 2048)

	start := time.Now()
	rec := httptest.NewRecorder()
	u.statsHandler(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("/stats took %v with a warm cache", elapsed)
	}

	var stats SystemStats
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.TunnelTraffic != "2.00 KB" {
		t.Fatalf("tunnelTraffic = %q, want unsaved bytes included (2.00 KB)", stats.TunnelTraffic)
	}
}

func TestFinalSaveOnShutdown(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	path := filepath.Join(t.TempDir(), "usage.json")
	u := NewDataStore(":0", ctx, path, true, logger)
	u.Start(false)

	u.AddOrUpdatePort(8443, 123)
	cancel()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			if got := readSaved(t, path); got[8443] == 123 {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("usage counted before shutdown was not saved")
}
