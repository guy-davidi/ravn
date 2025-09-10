# RAVN Security Platform

Real-time security monitoring with eBPF and AI threat detection.

## Quick Start

```bash
# Setup Python environment
./setup.sh

# Build
make all

# Start daemon (requires root)
sudo ./artifacts/ravn

# Start dashboard
./artifacts/ravn ctl
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RAVN Security Platform                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                KERNEL SPACE                            │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │ │
│  │  │   Syscall   │  │   Network   │  │   Security  │     │ │
│  │  │   Monitor   │  │   Monitor   │  │   Monitor   │     │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘     │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                USER SPACE                              │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │              ravn (Single Binary)                  │ │ │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │ │ │
│  │  │  │   eBPF      │  │   Redis     │  │     AI      │ │ │ │
│  │  │  │  Handler    │──│   Client    │◀─│   Engine    │ │ │ │
│  │  │  └─────────────┘  └─────────────┘  └─────────────┘ │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Features

- **Real-time Monitoring**: eBPF-based system call tracking
- **AI Threat Detection**: Deep learning model with sliding window analysis
- **Professional Dashboard**: TUI interface with live updates
- **High Performance**: <10ms inference, 100+ events/second

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

## Usage

### Daemon Mode
```bash
sudo ./artifacts/ravn
```

### CLI Dashboard
```bash
./artifacts/ravn ctl
```

### Help
```bash
./artifacts/ravn help
```

## Development

```bash
# Build specific components
make daemon    # C daemon
make cli       # Rust CLI

# Clean build artifacts
make clean

# Train AI model
make model
```

## Project Structure

```
ravn/
├── src/
│   ├── daemon/          # C daemon implementation
│   ├── ebpf/            # eBPF programs
│   └── cli/             # Rust CLI dashboard
├── scripts/             # Python training scripts
├── Makefile             # Build system
└── README.md           # This file
```

## Performance

- **Event Processing**: 100+ events/second
- **AI Inference**: <10ms per prediction
- **Memory Usage**: 2-8MB for AI model
- **Latency**: <100ms end-to-end

## License

GPL License - see LICENSE file for details.