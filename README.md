# cert-monitor

> Lightweight TLS/SSL certificate expiry monitor with anomaly alerting and a built-in status API.

![Go](https://img.shields.io/badge/go-%3E%3D1.21-00ADD8?logo=go)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-stable-green.svg)

`cert-monitor` watches your TLS endpoints and alerts you before certificates expire. It connects directly to targets, inspects their certificates, and reports days remaining — with severity levels, webhook notifications, and an on-box HTTP status endpoint for integration with Prometheus, Grafana, or any monitoring stack.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Direct TLS inspection** | Connects to any host:port and reads the certificate in real time — no agent needed on the target |
| ⚡ **Fast parallel scanning** | All targets are scanned concurrently with configurable per-host timeouts |
| 🚨 **Severity classification** | CRITICAL / WARNING / OK — exits with code 1 when any cert is at risk |
| 🕐 **Daemon mode** | Runs continuously on a configurable interval with automatic rescan |
| 📡 **Webhook alerts** | POST JSON payloads to any HTTP endpoint on alert events |
| 📊 **Built-in status API** | Lightweight HTTP server exposes `/health` and `/status` for Prometheus scraping |
| 💾 **Scan history** | Persists results as JSON files with a `latest.json` symlink for quick access |
| 🔧 **YAML config + CLI overrides** | Configure once in YAML, override any flag from the command line |
| 📦 **Single binary, no dependencies** | Compiles to a static Go binary; ships as a single executable |

---

## 🏃 Quick Start

### Prerequisites

- Go 1.21 or later (to build from source)
- Linux, macOS, or any Unix-like OS

### Build & Run

```bash
git clone https://github.com/chensu1234/certExpiry.git
cd certExpiry

# Build
go build -o bin/cert-monitor ./cmd/cert-monitor

# Run once
./bin/cert-monitor --config config/cert-monitor.yml

# Run in daemon mode
./bin/cert-monitor --config config/cert-monitor.yml --daemon --interval 1h
```

### One-liner (no build step)

```bash
go run ./cmd/cert-monitor --hosts google.com,github.com
```

### Docker

```bash
docker run -p 8765:8765 \
  YOUR_HANDLE/cert-monitor \
  --hosts google.com,github.com,cloudflare.com \
  --daemon --alert-port 8765
```

---

## ⚙️ Configuration

`cert-monitor` is configured via a YAML file (default: `config/cert-monitor.yml`). Any config value can be overridden from the CLI.

### YAML reference

```yaml
# Targets — host:port or hostname (port defaults to 443)
targets:
  - google.com
  - github.com:443

# Scan interval for daemon mode (go Duration format)
check_interval: 1h

# Per-host connection timeout
timeout: 10s

# Alert threshold: warn when cert expires within N days
alert_days_threshold: 30

# Local HTTP port for status endpoint (0 = disabled)
alert_port: 8765

# Optional webhook URL for JSON alerts
alert_webhook: https://your-webhook.com/alerts

# Extra HTTP headers for webhook requests
alert_webhook_headers:
  Authorization: "Bearer your-token"

# Output mode
json_output: false

# Persist scan history to this directory
store_path: ./.cert-store

# Log file (empty = stdout only)
log_path: ./log/cert-monitor.log

# Downgrade critical to warning (exit 0)
warn_only: false

# Run in background continuously
daemon_mode: false
```

### Environment variables

| Variable | Corresponding flag |
|----------|-------------------|
| `CERT_MONITOR_HOSTS` | `--hosts` |
| `CERT_MONITOR_CONFIG` | `--config` |
| `CERT_MONITOR_INTERVAL` | `--interval` |
| `CERT_MONITOR_ALERT_PORT` | `--alert-port` |

---

## 📋 Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `config/cert-monitor.yml` | Path to YAML configuration file |
| `--hosts` | _(empty)_ | Comma-separated target list (overrides config) |
| `--interval` | _(from config)_ | Daemon scan interval (e.g., `30m`, `2h`) |
| `--alert-days` | _(from config)_ | Warning threshold in days |
| `--alert-port` | _(from config)_ | Local port for `/health` and `/status` |
| `--json` | `false` | Output results as JSON |
| `--warn-only` | `false` | Exit with code 0 even on critical alerts |
| `--daemon` | `false` | Run continuously in the background |
| `--version` | _(n/a)_ | Print version and exit |
| `--help` | _(n/a)_ | Show this help text |

---

## 📁 Project Structure

```
cert-monitor/
├── bin/
│   └── cert-monitor            # Compiled binary (gitignored)
├── cmd/
│   └── cert-monitor/
│       ├── main.go            # Entry point, scan orchestration, output
│       └── flags.go           # CLI flag definitions
├── config/
│   └── cert-monitor.yml       # Default configuration
├── internal/
│   ├── alerter/
│   │   └── alerter.go         # Webhook dispatcher + HTTP status server
│   ├── config/
│   │   └── config.go          # Config loading and validation
│   └── store/
│       └── store.go           # JSON persistence for scan history
├── log/                       # Runtime log directory
├── tests/
│   ├── config_test.go
│   └── store_test.go
├── CHANGELOG.md
├── LICENSE
├── README.md
└── go.mod
```

---

## 📝 CHANGELOG

### [1.0.0] — 2026-04-20

#### Added
- Initial release
- Direct TLS certificate inspection for any host:port
- YAML-based configuration with CLI override support
- CRITICAL / WARNING / OK severity classification
- Daemon mode with configurable scan interval
- Webhook alerting (HTTP POST JSON)
- Built-in HTTP status server (`/health`, `/status`)
- Scan history persistence to JSON
- Parallel target scanning
- `latest.json` symlink for easy integration
- Docker support

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.