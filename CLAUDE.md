# CLAUDE.md

Guidance for working in this repository.

## Project

Backhaul is a high-performance **reverse tunnel** written in Go (module `github.com/musix/backhaul`, Go 1.23.1, AGPL-3.0). One binary runs as either a **server** (public side, exposes ports) or a **client** (behind NAT, dials out). The role is chosen by the TOML config: `[server].bind_addr` set → server; else `[client].remote_addr` set → client.

## Commands

```bash
go build                      # produces ./backhaul
./backhaul -c config.toml     # run (server or client, depending on config)
./backhaul -v                 # print version
go vet ./...
go test -race -count=1 ./...  # unit tests + e2e (internal/e2e, linux only); -race needs gcc
```

CI (`.github/workflows/ci.yml`) runs gofmt, vet, cross-builds for all release targets, and `go test -race` on every push/PR.

The e2e tests (`internal/e2e`) start real server/client pairs on localhost through `cmd.Load` + `cmd.Run`. They cover every transport, `accept_udp`, client replacement, server replacement, and a busy mapped port. Extend them when touching transport or restart logic.

On Windows, develop inside WSL. The code builds only for unix (see below).

Releases: pushing a `v*` tag triggers `.github/workflows/goreleaser.yml` → `.goreleaser.yaml` builds static (`CGO_ENABLED=0`) binaries for linux/darwin × amd64/arm64. Windows is **not** a target (socket code uses `syscall.SetsockoptInt(int(fd), ...)`, which doesn't compile on Windows). Bump `version` in `main.go` when releasing.

## Layout

```
main.go                     flags, signal handling, config hot-reload (polls mtime every 2s; validates the new file first, keeps the old instance if invalid)
cmd/cmd.go                  Load (decode + defaults + validate) and Run (pick server/client, block until ctx done)
cmd/defaults.go             ALL default values (token "musix", pool 8, keepalive 75s, heartbeat 40s, smux params...)
cmd/optimization.go         Linux sysctl + RLIMIT_NOFILE tuning (skipped with skip_optz = true)
config/config.go            ServerConfig / ClientConfig structs + TransportType constants
internal/server/server.go   maps ServerConfig -> per-transport config, starts transport
internal/client/client.go   same for client
internal/server/transport/  tcp, tcpmux, ws(+wss), wsmux(+wssmux), udp, accept_udp (UDP-over-TCP), shared.go (structs)
internal/client/transport/  client counterparts of the above
internal/client/transport/pool.go  shared pool-sizing loop (maintainPool) used by every client transport
internal/utils/binary.go    wire framing helpers
internal/utils/signals.go   control signal bytes
internal/utils/sync.go      Locked[T] (mutex-guarded value), Go (WaitGroup-tracked goroutine), WaitTimeout
internal/utils/portmap/     the single port-mapping parser (portmap.Parse)
internal/utils/handlers/    bidirectional copy (tcp_handler, ws_handler), PROXY protocol v2 header
internal/utils/network/     listener/dialer with SO_RCVBUF/SNDBUF, MSS, NODELAY, REUSEPORT; WebSocket dialer; addr resolver; RetryListen
internal/e2e/               end-to-end tests (linux)
internal/web/               monitoring web UI + traffic sniffer (embedded index.html, gopsutil stats)
benchmark/                  benchmark notes and charts only
```

`internal/utils/httpserver.go` and `internal/utils/runtime.go` are unused debug leftovers.

## Architecture

Every transport follows the same model:

1. **Control channel.** Client dials the server and authenticates.
   - TCP-based: client sends `[len][SG_Chan][token]`, server echoes the token (2s deadline).
   - WS-based: `Authorization: Bearer <token>` header, path `/channel`.
2. **Signals over the control channel** (`utils/signals.go`): `SG_HB` heartbeat, `SG_Chan` "dial a new tunnel", `SG_Ping`, `SG_Closed`, `SG_TCP`/`SG_UDP` (tunnel payload type), `SG_RTT`.
3. **Server.** Listens on each mapped port (`ports` config). An accepted user conn goes into `localChannel` and an `SG_Chan` is sent. Client-dialed tunnels go into `tunnelChannel`. Up to `min(NumCPU,4)` `handleLoop`s pair them. Local conns waiting >3s are dropped. The server then writes the target address onto the tunnel.
4. **Client.** Keeps a pool of pre-dialed tunnels (`poolMaintainer`, auto-resizes every 10s; `aggressive_pool` changes factors). On receiving a target address it resolves it (`network.ResolveRemoteAddr`: bare port → `127.0.0.1:port`), dials the local service and splices.
5. **Mux variants** (`tcpmux`, `wsmux`). Each tunnel conn is an smux session. **The server is the smux *Client* and opens streams; the client is the smux *Server* and accepts them.** The server requests a new session when `streams >= sessions * mux_con`.
6. **Failure handling.** Any control-channel error calls `go s.Restart()`. Always use `go`: Restart waits for the workers, so a synchronous call from a worker deadlocks. Restart is guarded by `restartMutex.TryLock()` and does:
   - cancel ctx and close the control channel
   - wait (10s timeout) on the run's `wg`
   - install a fresh `wg`, ctx, channels and `web.Usage`
   - call `Start()`

### Concurrency rules (keep these when editing transports)
- **Control-plane goroutines** (listeners, accept loops, handshake, channel handler and its reader, handle loops, mux sessions, keepalives, `Monitor`) must start via `s.spawn(...)`, so `Restart` can wait for them. They must exit when ctx is done: no unconditional blocking sends; use `select` with `<-ctx.Done()`.
- **Data-plane goroutines** (copy handlers, client pooled tunnels) are not tracked. They must not read fields that `Restart` replaces (`ctx`, `usageMonitor`, channels, `udpConnTable`). Capture those at spawn time and pass them in. Client pooled tunnels close themselves on restart via `context.AfterFunc(ctx, conn.Close)`.
- Shared mutable state uses `utils.Locked` (`controlChannel`), atomics (`rtt`, counters, `IsCongested`), or `web.Usage.SetStatus` (tunnel status shown in the web UI).
- Control readers must check `ctx.Err() == nil` before calling `Restart`, so a reader unblocked by a restart doesn't trigger another one.
- Runtime listens go through `network.RetryListen` (backoff 1s→30s). Never `Fatalf` outside startup; config problems are rejected in `cmd.Load`.

### Wire formats
- `SendBinaryString`: `[2B big-endian len][payload]` (mux streams send the target address this way).
- `SendBinaryTransportString`: `[2B len][1B type][payload]` (handshake and the TCP tunnel target address).
- UDP-over-TCP (`accept_udp`): client→server `[4B timestamp ms mod 10min][2B len][data]`, server→client `[2B len][data]`. If a packet is older than 3×RTT, the flow is marked congested and the next packets open a new tunnel.
- Native `udp` transport: control channel is TCP. Each UDP tunnel flow first sends the raw token; the server answers with the target address; `SG_Ping` single-byte keepalives.
- `proxy_protocol = true` (tcp, tcpmux, wsmux only): the server prepends a PROXY v2 header before splicing.

### Port mapping syntax (server `ports`)
`"443"`, `"443-600"`, `"443-600:5201"`, `"443-600=1.1.1.1:5201"`, `"4000=5000"`, `"127.0.0.2:443=1.1.1.1:5201"`. They are parsed only by `portmap.Parse` (table-tested in `portmap_test.go`). `cmd.Load` rejects invalid mappings at startup, and each server transport's `parsePortMappings` just loops over the result.

### Monitoring
`web.NewDataStore(...)` is created per transport. If `web_port > 0` it serves `/` (embedded template), `/stats` (system stats via gopsutil) and `/data` (per-port usage, only when `sniffer = true`). Per-port byte counts are flushed to `sniffer_log` JSON every 15s. `pprof = true` opens :6060 (server) or :6061 (client). The web UI has no authentication.

## Conventions

- Logging: `logrus` via `utils.NewLogger(level)` with a custom colored formatter. Use `Tracef`/`Debugf` for per-packet or per-connection detail, `Info` for lifecycle, `Warn`/`Error` for problems. Restart paths temporarily raise the level to Fatal to hide noise.
- Each transport is a struct with `config`, `parentctx`, `ctx`, `cancel`, `logger`, buffered channels sized by `ChannelSize`, and `Start()` / `Restart()` methods. Follow the same shape for new transports, and wire them through `config.TransportType`, `server.go`, `client.go` and `cmd/defaults.go`.
- Non-blocking channel sends with `select { case ch <- x: default: /* drop + warn */ }` are the norm. Don't introduce blocking sends on hot paths.
- Copy buffers are 16 KB. Counters shared across goroutines use `sync/atomic`.
- New config options need: a field + `toml` tag in `config/config.go`, a default in `cmd/defaults.go` (if any), plumbing in `server.go`/`client.go`, and a README entry (the README documents every option with inline comments).

## Known pitfalls (verify before relying on them)

- TCP/TCPMux data tunnels are not token-authenticated. Only the control channel is; tunnel conns are filtered only by matching the control channel's source IP.
- The WSS client uses `InsecureSkipVerify: true`. `tcp`/`tcpmux` are plaintext.
- A restart (and hot reload) drops in-flight mux sessions and UDP flows. Plain tcp/ws connections that are already spliced survive.
- The web UI has no authentication and binds all interfaces on `web_port`.
- Some code comments are inaccurate (e.g. "256KB" next to 65536). Trust the code.
