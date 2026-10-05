package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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
