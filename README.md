<p align="center">
    <a href="https://github.com/guy-davidi/ravn/actions/workflows/daily-ci.yml" target="_blank">
        <img src="https://github.com/guy-davidi/ravn/actions/workflows/daily-ci.yml/badge.svg" alt="Daily CI"/>
    </a>
    <a href="https://github.com/guy-davidi/ravn/actions/workflows/release.yml" target="_blank">
        <img src="https://github.com/guy-davidi/ravn/actions/workflows/release.yml/badge.svg" alt="Release RAVN"/>
    </a>
    <a href="https://github.com/guy-davidi/ravn/releases" target="_blank">
        <img src="https://img.shields.io/badge/release-v20250910.2-blue" alt="Latest Release"/>
    </a>
</p>

<div align="center">
    <h1>🛡️ RAVN - Runtime Anomaly & Vulnerability Network</h1>
    <h2>Real-time security monitoring with eBPF and AI threat detection</h2>
</div>

## Quick Start

```bash
# Build
make all

# Start daemon (requires root)
sudo ./artifacts/ravn daemon

# Start dashboard
./artifacts/ravn cli
```

## Requirements

- Linux kernel 5.4+
- Redis server
- Build tools (gcc, clang, make)

## Installation

```bash
# Install Redis
sudo apt install redis-server
sudo systemctl start redis-server

# Build RAVN
make all
```

## Features

- **Real-time Monitoring**: eBPF-based system call tracking
- **AI Threat Detection**: Deep learning model with sliding window analysis
- **Professional Dashboard**: TUI interface with live updates
- **High Performance**: <10ms inference, 100+ events/second

## Docker Package

RAVN is also available as a Docker container:

```bash
# Pull from GitHub Container Registry (private)
docker pull ghcr.io/guy-davidi/ravn:latest

# Run the container
docker run -d --privileged ghcr.io/guy-davidi/ravn:latest
```

**Note**: The package is private and requires authentication to access.

## License

GPL License - see LICENSE file for details.