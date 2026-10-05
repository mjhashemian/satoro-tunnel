package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValid(t *testing.T) {
	path := writeConfig(t, `
[server]
bind_addr = "0.0.0.0:3080"
transport = "tcp"
ports = ["443", "443-600:5201", "127.0.0.2:443=1.1.1.1:5201"]
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// defaults are applied
	if cfg.Server.Token != defaultToken || cfg.Server.ChannelSize != defaultChannelSize {
		t.Fatalf("defaults not applied: %+v", cfg.Server)
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := map[string]struct {
		config  string
		wantErr string
	}{
		"bad toml": {
			config:  "[server\nbind_addr = ",
			wantErr: "failed to parse",
		},
		"no role": {
			config:  "[server]\ntransport = \"tcp\"\n",
			wantErr: "neither server nor client",
		},
		"bad server transport": {
			config:  "[server]\nbind_addr = \":3080\"\ntransport = \"quic\"\n",
			wantErr: "invalid server transport",
		},
		"bad client transport": {
			config:  "[client]\nremote_addr = \"1.2.3.4:3080\"\ntransport = \"\"\n",
			wantErr: "invalid client transport",
		},
		"bad port mapping": {
			config:  "[server]\nbind_addr = \":3080\"\ntransport = \"tcp\"\nports = [\"600-443\"]\n",
			wantErr: "invalid port mapping",
		},
		"wss without cert": {
			config:  "[server]\nbind_addr = \":443\"\ntransport = \"wss\"\n",
			wantErr: "tls_cert",
		},
		"wss with missing cert file": {
			config:  "[server]\nbind_addr = \":443\"\ntransport = \"wssmux\"\ntls_cert = \"/nonexistent.crt\"\ntls_key = \"/nonexistent.key\"\n",
			wantErr: "tls_cert",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.config))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}
