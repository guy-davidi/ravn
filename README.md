# RAVN Runtime Anomaly Vulnerability Network

A professional security monitoring platform that uses eBPF for real-time system monitoring and AI for threat detection.

## Overview

RAVN is a single-binary security platform that combines:
- **eBPF-based monitoring** for kernel-space event capture
- **AI-powered threat detection** with sliding window analysis
- **Real-time dashboard** with TUI interface
- **Redis-based data storage** for high-performance event handling

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              RAVN Security Platform                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │                              KERNEL SPACE                                 │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │ │
│  │  │   Syscall   │  │   Network   │  │   Security  │  │   File I/O  │     │ │
│  │  │   Monitor   │  │   Monitor   │  │   Monitor   │  │   Monitor   │     │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘     │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │                              USER SPACE                                   │ │
│  │  ┌─────────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                            ravn (Single Binary)                        │ │ │
│  │  │  ┌─────────────────────────────────────────────────────────────────────┐ │ │ │
│  │  │  │                        Mode Selection                              │ │ │ │
│  │  │  │  if (argv[1] == "ctl") {                                          │ │ │ │
│  │  │  │      start_cli_dashboard();                                       │ │ │ │
│  │  │  │  } else {                                                         │ │ │ │
│  │  │  │      start_daemon();                                              │ │ │ │
│  │  │  │  }                                                                │ │ │ │
│  │  │  └─────────────────────────────────────────────────────────────────────┘ │ │ │
│  │  └─────────────────────────────────────────────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Features

### Real-time Monitoring
- **System Call Tracking**: Monitor all system calls (execve, open, read, write, mmap, mprotect)
- **Network Monitoring**: Track network operations (connect, bind, listen, accept, send, recv)
- **Security Events**: Monitor security-related operations (ptrace, setuid, chmod, chown, mount, umount)
- **File I/O Tracking**: Monitor file operations (open, read, write, close, unlink, rename)

### AI-Powered Threat Detection
- **Sliding Window Analysis**: 10-second analysis window, slides every 1 second
- **Deep Learning Model**: CNN + LSTM architecture for sequence analysis
- **Real-time Scoring**: Continuous threat level calculation
- **Pattern Detection**: Identifies attack patterns and suspicious behavior

### Professional Dashboard
- **TUI Interface**: Modern terminal-based dashboard
- **Real-time Updates**: Live event streaming and threat level updates
- **Multi-tab Interface**: Dashboard, Events, Threats, Settings
- **Export Capabilities**: Data export and reporting

## Quick Start

### Prerequisites
- Linux kernel 5.4+
- Redis server
- Build tools (gcc, clang, make)
- Rust toolchain
- Python 3.8+ (for model training)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ravn
   ```

2. **Install dependencies**
   ```bash
   make deps
   ```

3. **Start Redis server**
   ```bash
   make redis
   ```

4. **Build the project**
   ```bash
   make all
   ```

### Usage

1. **Start the daemon** (requires root privileges)
   ```bash
   sudo ./artifacts/ravn
   ```

2. **Start the CLI dashboard**
   ```bash
   ./artifacts/ravn ctl
   ```

3. **View help**
   ```bash
   ./artifacts/ravn help
   ```

## Development

### Project Structure
```
ravn/
├── src/
│   ├── daemon/          # C daemon implementation
│   │   ├── main.c       # Main daemon entry point
│   │   ├── ebpf_handler.c/h  # eBPF event handling
│   │   ├── redis_client.c/h  # Redis communication
│   │   └── ai_engine.c/h     # AI threat detection
│   ├── ebpf/            # eBPF programs
│   │   ├── syscall_monitor.bpf.c
│   │   ├── network_monitor.bpf.c
│   │   ├── security_monitor.bpf.c
│   │   └── file_monitor.bpf.c
│   ├── cli/             # Rust CLI dashboard
│   │   ├── src/main.rs  # TUI dashboard
│   │   └── Cargo.toml   # Rust dependencies
│   └── scripts/         # Python training scripts
│       ├── generate_data.py
│       ├── train_model.py
│       └── export_model.py
├── Makefile             # Build system
├── .cargo/config.toml   # Rust configuration
└── README.md           # This file
```

### Building Components

**Build everything**
```bash
make all
```

**Build specific components**
```bash
make daemon    # C daemon
make cli       # Rust CLI
```

**Clean build artifacts**
```bash
make clean
```

### AI Model Training

1. **Generate training data**
   ```bash
   python src/scripts/generate_data.py --output training_data.json
   ```

2. **Train the model**
   ```bash
   python src/scripts/train_model.py --data training_data.json --output ravn_model
   ```

3. **Export for C inference**
   ```bash
   python src/scripts/export_model.py --model ravn_model --output models/ravn_model
   ```

## Configuration

### Redis Configuration
- **Host**: 127.0.0.1 (default)
- **Port**: 6379 (default)
- **Data structures**:
  - `events:raw` (List): Raw events from eBPF
  - `events:live` (Pub/Sub): Real-time event stream
  - `threat:current` (String): Current threat level
  - `threat:update` (Pub/Sub): Threat level updates

### AI Model Configuration
- **Window Size**: 10 seconds
- **Slide Interval**: 1 second
- **Model Architecture**: CNN + LSTM
- **Input Features**: 10 dimensions
- **Output Classes**: 3 (Normal, Suspicious, Attack)

## API Reference

### Daemon Mode
```bash
./artifacts/ravn                    # Start daemon
./artifacts/ravn --help            # Show help
```

### CLI Mode
```bash
./artifacts/ravn ctl               # Start CLI dashboard
./artifacts/ravn ctl --redis-host 127.0.0.1 --redis-port 6379
```

### CLI Controls
- **Tab/Shift+Tab**: Switch tabs
- **R**: Refresh data
- **Q**: Quit

## Performance

### Benchmarks
- **Event Processing**: 100+ events/second
- **AI Inference**: <10ms per prediction
- **Memory Usage**: 2-8MB for AI model
- **Latency**: <100ms end-to-end

### System Requirements
- **OS**: Linux (kernel 5.4+)
- **Architecture**: ARM/x86
- **Memory**: 512MB+ RAM
- **Storage**: 100MB+ disk space

## Security Features

### Threat Detection
- **Sequence Analysis**: Analyzes event sequences for attack patterns
- **Anomaly Detection**: Identifies suspicious behavior
- **Threat Scoring**: Calculates real-time threat levels
- **Alert System**: Real-time threat notifications

### Professional Features
- **Historical Analysis**: Store and analyze threat events
- **Dashboard**: Real-time monitoring interface
- **Export**: Data export capabilities
- **Logging**: Comprehensive event logging

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the GPL License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the architecture guide

## Roadmap

### Future Enhancements
- **Multi-node support**: Distributed monitoring
- **Load balancing**: Handle high event volumes
- **Clustering**: Redis cluster support
- **Machine Learning**: Online learning capabilities
- **Threat Intelligence**: External threat feeds
- **Integration**: SIEM/SOAR platform integration
- **Compliance**: Regulatory compliance features
- **GPU acceleration**: AI inference on GPU
- **Memory optimization**: Reduced memory footprint
- **Network optimization**: Efficient data transfer
- **Caching**: Intelligent data caching

