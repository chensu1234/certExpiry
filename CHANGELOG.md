# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-04-20

### Added
- Initial release
- Direct TLS certificate inspection for any `host:port`
- YAML-based configuration with CLI override support
- CRITICAL / WARNING / OK severity classification
- Daemon mode with configurable scan interval
- Webhook alerting via HTTP POST JSON payloads
- Built-in HTTP status server with `/health` and `/status` endpoints
- Scan history persistence to JSON with `latest.json` symlink
- Parallel target scanning with per-host timeout
- Docker support
- Comprehensive unit tests for config and store packages