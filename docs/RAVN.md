# RAVN Security Platform - Technical Documentation

Professional security monitoring platform with eBPF and AI threat detection.

## Architecture Overview

### Single Binary Design
- **Executable**: `ravn` (single binary)
- **Mode Selection**: Command-line argument determines operation
  - `ravn` → Daemon mode (background monitoring)
  - `ravn ctl` → CLI mode (dashboard interface)

### Technology Stack
- **Daemon**: C (eBPF integration and performance)
- **CLI**: Rust (modern UI and safety)
- **Database**: Redis (in-memory storage and pub/sub)
- **AI**: Deep learning model (trained offline, inference in C)
- **eBPF**: libbpf for kernel-space monitoring

## System Architecture

### Layered Architecture with Real eBPF

```mermaid
graph TB
    subgraph KERNEL["KERNEL SPACE"]
        subgraph EBPF["Real eBPF System Monitoring"]
            CPU["/proc/stat Monitor<br/>• CPU usage<br/>• User time<br/>• System<br/>• Idle<br/>• I/O wait<br/>• IRQ"]
            LOAD["/proc/loadavg Monitor<br/>• Load avg<br/>• 1min/5min<br/>• 15min<br/>• Processes<br/>• Running<br/>• Total"]
            MEM["/proc/meminfo Monitor<br/>• Memory<br/>• Total<br/>• Free<br/>• Available<br/>• Used %<br/>• Buffers"]
            SYS["/proc/syscall Monitor<br/>• Syscalls<br/>• Real-time<br/>• Process<br/>• Thread<br/>• Events<br/>• Analysis"]
        end
    end
    
    subgraph USER["USER SPACE"]
        subgraph RAVN["ravn (Single Binary)"]
            MS["Mode Selection<br/>if argv[1] == ctl<br/>start_cli_dashboard()<br/>else start_daemon()"]
            
            subgraph DAEMON["Daemon Mode"]
                EH["eBPF Handler<br/>• Read ring buffers<br/>• Parse events<br/>• Send to Redis<br/>• Real-time streaming"]
                RC1["Redis Client<br/>• Connect to Redis Server<br/>• Send events<br/>• Get events<br/>• Pub/Sub events"]
                AI["AI Engine<br/>• Read events<br/>• Analyze sequences<br/>• Calculate scores<br/>• Update threat level<br/>• Every 1s"]
            end
            
            subgraph CLI["CLI Mode"]
                RC2["Redis Client<br/>• Connect to Redis Server<br/>• Subscribe to events<br/>• Get history<br/>• Query data"]
                TUI["TUI Dashboard<br/>• Real-time display<br/>• Charts<br/>• Alerts<br/>• Statistics<br/>• Logs<br/>• Threat levels"]
                UI["User Interface<br/>• Commands<br/>• Controls<br/>• Settings<br/>• Queries<br/>• Reports<br/>• Export<br/>• Help<br/>• Exit"]
            end
        end
    end
    
    subgraph EXTERNAL["External Dependencies"]
        RS["Redis Server<br/>• In-memory storage<br/>• Pub/Sub events<br/>• Real-time updates"]
        LB["libbpf Library<br/>• eBPF support<br/>• Ring buffers<br/>• Zero-copy I/O"]
        PS["Python Training Scripts<br/>• Data generation<br/>• Model training<br/>• Model export"]
    end
    
    %% Data Flow Connections
    CPU --> EH
    LOAD --> EH
    MEM --> EH
    SYS --> EH
    
    EH --> RC1
    RC1 --> RS
    RS --> RC1
    RC1 --> AI
    AI --> RC1
    RC1 --> RS
    
    RS --> RC2
    RC2 --> TUI
    TUI --> UI
    
    %% External Dependencies
    LB -.-> CPU
    LB -.-> LOAD
    LB -.-> MEM
    LB -.-> SYS
    PS -.-> AI
    
    %% Styling
    classDef kernelSpace fill:#ff9999,stroke:#333,stroke-width:2px
    classDef userSpace fill:#99ccff,stroke:#333,stroke-width:2px
    classDef external fill:#99ff99,stroke:#333,stroke-width:2px
    
    class CPU,LOAD,MEM,SYS kernelSpace
    class MS,EH,RC1,AI,RC2,TUI,UI userSpace
    class RS,LB,PS external
```

## Thread Architecture

```mermaid
graph TB
    subgraph MAIN["Main Process"]
        subgraph INIT["Initialization Sequence"]
            L1["Layer 1: eBPF Handler Thread<br/>• Initialize /proc monitoring<br/>• Start real-time monitoring thread<br/>• Monitor CPU, Memory, Load, System calls<br/>• Send events to Redis every 2 seconds"]
            L2["Layer 2: Redis Database Connection<br/>• Connect to Redis server<br/>• Set global connection pointer<br/>• Enable eBPF → Redis communication"]
            L3["Layer 3: AI Analysis Thread<br/>• Load AI model<br/>• Start AI analysis thread<br/>• Process events from Redis<br/>• Calculate threat scores<br/>• Update threat levels in Redis"]
        end
        
        subgraph RUNTIME["Runtime Threads"]
            subgraph EBPF_THREAD["eBPF Monitoring Thread"]
                CPU_MON["CPU Monitor<br/>• /proc/stat<br/>• 2s cycle<br/>• JSON data<br/>• Redis events"]
                LOAD_MON["Load Monitor<br/>• /proc/loadavg<br/>• 2s cycle<br/>• JSON data<br/>• Redis events"]
                MEM_MON["Memory Monitor<br/>• /proc/meminfo<br/>• 2s cycle<br/>• JSON data<br/>• Redis events"]
                SYS_MON["System Monitor<br/>• /proc/syscall<br/>• 2s cycle<br/>• JSON data<br/>• Redis events"]
            end
            
            subgraph AI_THREAD["AI Analysis Thread"]
                EVENT_READER["Event Reader<br/>• Get from Redis<br/>• Parse JSON<br/>• Validate"]
                FEATURE_EXTRACT["Feature Extractor<br/>• Sliding window<br/>• Process sequences<br/>• Extract features"]
                MODEL_INFERENCE["Model Inference<br/>• Load model<br/>• Real-time inference<br/>• Batch processing"]
                THREAT_UPDATER["Threat Updater<br/>• Calculate scores<br/>• Update levels<br/>• Store in Redis"]
            end
        end
        
        subgraph MAIN_LOOP["Main Monitoring Loop"]
            HEALTH_MON["Health Monitor<br/>• System health<br/>• Resource usage"]
            REDIS_MON["Redis Monitor<br/>• Connection status<br/>• Reconnect on fail"]
            THREAD_MON["Thread Monitor<br/>• eBPF thread<br/>• AI thread<br/>• Status"]
            SIGNAL_HANDLER["Signal Handler<br/>• SIGINT<br/>• SIGTERM<br/>• Graceful shutdown"]
        end
    end
    
    %% Initialization Flow
    L1 --> L2
    L2 --> L3
    
    %% Runtime Flow
    L3 --> EBPF_THREAD
    L3 --> AI_THREAD
    
    %% eBPF Thread Flow
    CPU_MON --> EVENT_READER
    LOAD_MON --> EVENT_READER
    MEM_MON --> EVENT_READER
    SYS_MON --> EVENT_READER
    
    %% AI Thread Flow
    EVENT_READER --> FEATURE_EXTRACT
    FEATURE_EXTRACT --> MODEL_INFERENCE
    MODEL_INFERENCE --> THREAT_UPDATER
    
    %% Main Loop Monitoring
    EBPF_THREAD --> THREAD_MON
    AI_THREAD --> THREAD_MON
    THREAD_MON --> HEALTH_MON
    THREAD_MON --> REDIS_MON
    THREAD_MON --> SIGNAL_HANDLER
    
    %% Styling
    classDef initLayer fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef runtimeLayer fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef mainLayer fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    
    class L1,L2,L3 initLayer
    class CPU_MON,LOAD_MON,MEM_MON,SYS_MON,EVENT_READER,FEATURE_EXTRACT,MODEL_INFERENCE,THREAT_UPDATER runtimeLayer
    class HEALTH_MON,REDIS_MON,THREAD_MON,SIGNAL_HANDLER mainLayer
```

## CLI Dashboard Features

### Real-time Status Display

```
[2025-09-08 09:50:02] RAVN Security Status
═══════════════════════════════════════════════════════════════
Threat Level: MEDIUM (Score: 0.490)
Reason: AI analysis: PID=0, Events=1, Score=0.490
Redis Status: Connected ✓
eBPF Programs: Active ✓ (CPU, Memory, Load, System monitoring)
System Metrics:
   • Events collected: 1
   • Load monitoring: Active
Thread Status:
   • eBPF monitoring: Running
   • AI analysis: Running
   • Main loop: Active
System Uptime: 0h 50m
═══════════════════════════════════════════════════════════════
```

### CLI Features

- **Real-time Threat Monitoring**: Live threat level display with color coding
- **Connection Status**: Redis connectivity monitoring with auto-reconnect
- **eBPF Program Status**: Shows active monitoring programs (CPU, Memory, Load, System)
- **System Metrics**: Real-time event counts and monitoring status
- **Thread Status**: Multi-threaded architecture status display
- **System Information**: System uptime and health metrics
- **Enhanced UI**: Color-coded output with professional formatting
- **Auto-refresh**: 2-second update cycle with screen clearing every 10 iterations

## Data Flow

```mermaid
sequenceDiagram
    participant eBPF as eBPF Programs
    participant RB as Ring Buffers
    participant EH as eBPF Handler
    participant RC as Redis Client
    participant RS as Redis Server
    participant AI as AI Engine
    participant CLI as CLI Dashboard
    participant UI as User Interface
    
    Note over eBPF,UI: RAVN Real-Time Data Flow
    
    %% Event Capture Flow
    loop Continuous Event Capture
        eBPF->>RB: Write events to ring buffers
        RB->>EH: Read events from buffers
        EH->>RC: Parse and send events
        RC->>RS: Store events in Redis
        RS->>RC: Acknowledge storage
    end
    
    %% AI Analysis Flow
    loop Every 1 Second
        AI->>RC: Request events for analysis
        RC->>RS: Get events from Redis
        RS->>RC: Return event data
        RC->>AI: Provide events to AI
        AI->>AI: Analyze 10-second sliding window
        AI->>AI: Calculate threat score
        AI->>RC: Send threat score
        RC->>RS: Update threat level in Redis
        RS->>RC: Acknowledge update
    end
    
    %% Dashboard Flow
    loop Real-Time Dashboard Updates
        CLI->>RC: Subscribe to live events
        RC->>RS: Subscribe to events:live channel
        RS->>RC: Stream live events
        RC->>CLI: Forward events to dashboard
        CLI->>UI: Update dashboard display
        
        CLI->>RC: Subscribe to threat updates
        RC->>RS: Subscribe to threat:update channel
        RS->>RC: Stream threat updates
        RC->>CLI: Forward threat updates
        CLI->>UI: Update threat level display
    end
    
    %% User Interaction
    UI->>CLI: User commands/controls
    CLI->>RC: Execute user requests
    RC->>RS: Query historical data
    RS->>RC: Return query results
    RC->>CLI: Provide data to CLI
    CLI->>UI: Display results to user
```

## Component Details

### Kernel Space Components

#### eBPF Programs
- **Syscall Monitor**: Tracks system calls (execve, open, read, write, mmap, mprotect)
- **Network Monitor**: Monitors network operations (connect, bind, listen, accept, send, recv)
- **Security Monitor**: Tracks security-related operations (ptrace, setuid, chmod, chown, mount, umount)
- **File I/O Monitor**: Monitors file operations (open, read, write, close, unlink, rename)

#### eBPF Ring Buffers
- **Lock-free**: High-performance event buffering
- **Zero-copy**: Direct memory access for maximum efficiency
- **High-performance**: Optimized for real-time event streaming

### User Space Components

#### Daemon Mode
- **eBPF Handler**: Reads from ring buffers, parses events, sends to Redis
- **Redis Client**: Connects to Redis server, handles data storage and pub/sub
- **AI Engine**: Analyzes event sequences, calculates threat scores, updates threat levels
- **Sliding Window**: 10-second analysis window, slides every 1 second

#### CLI Mode
- **Redis Client**: Connects to Redis server, subscribes to events and threat updates
- **TUI Dashboard**: Real-time display of events, charts, alerts, statistics, logs, threat levels
- **User Interface**: Commands, controls, settings, queries, reports, export, help, exit

### External Dependencies

#### Redis Server
- **In-memory storage**: Fast data access
- **Pub/Sub events**: Real-time communication
- **Real-time updates**: Live data streaming

#### libbpf Library
- **eBPF support**: Kernel-space program management
- **Ring buffers**: High-performance event handling
- **Zero-copy I/O**: Optimized data transfer

#### Python Training Scripts
- **Data generation**: Synthetic training data creation
- **Model training**: Deep learning model development
- **Model export**: Trained model conversion for C inference

## AI Model Architecture

### Training Phase (Offline)
- **Data Generation**: Synthetic system call sequences
- **Model Training**: Deep learning model (CNN + LSTM)
- **Model Export**: Convert to C-compatible format

### Inference Phase (Real-time)
- **Model Loading**: Load pre-trained model in C daemon
- **Sequence Analysis**: Analyze 10-second sliding windows
- **Threat Scoring**: Calculate threat levels every 1 second
- **Real-time Updates**: Update threat levels in Redis

### Model Specifications
- **Architecture**: Lightweight CNN + LSTM
- **Parameters**: ~500K-2M parameters
- **Memory Usage**: 2-8MB RAM
- **Inference Speed**: <10ms per prediction
- **Throughput**: 100+ events/second

## Redis Data Structure

### Data Storage
- **events:raw (List)**: Raw events from eBPF (FIFO queue)
- **events:live (Pub/Sub)**: Real-time event streaming
- **threat:current (String)**: Current threat level
- **threat:update (Pub/Sub)**: Threat level updates

### Data Flow
- **eBPF → Redis**: Events written continuously
- **AI ← Redis**: Events read every 1 second
- **AI → Redis**: Threat scores written every 1 second
- **CLI ← Redis**: Real-time updates via pub/sub

## Timing and Performance

### Sliding Window Analysis Timeline

```mermaid
gantt
    title RAVN Sliding Window Analysis Timeline
    dateFormat X
    axisFormat %s
    
    section eBPF Capture
    Continuous Event Capture    :active, ebpf, 0, 100
    
    section Redis Storage
    Event Storage              :active, redis, 0, 100
    
    section AI Analysis
    Window 1 (0s-10s)          :ai1, 0, 10
    Window 2 (1s-11s)          :ai2, 1, 11
    Window 3 (2s-12s)          :ai3, 2, 12
    Window 4 (3s-13s)          :ai4, 3, 13
    Window 5 (4s-14s)          :ai5, 4, 14
    Window 6 (5s-15s)          :ai6, 5, 15
    Window 7 (6s-16s)          :ai7, 6, 16
    Window 8 (7s-17s)          :ai8, 7, 17
    Window 9 (8s-18s)          :ai9, 8, 18
    Window 10 (9s-19s)         :ai10, 9, 19
    
    section CLI Dashboard
    Real-time Updates          :active, cli, 0, 100
```

### Event Processing
- **eBPF**: Continuous event capture
- **Redis**: Real-time event storage
- **AI**: Every 1 second analysis (10-second sliding window)
- **CLI**: Real-time dashboard updates

### Performance Characteristics
- **Latency**: <10ms per AI prediction
- **Throughput**: 100+ events/second
- **Memory**: 2-8MB for AI model
- **CPU**: Optimized for ARM/x86 boards

## Deployment Requirements

### System Requirements
- **OS**: Linux (kernel 5.4+)
- **Architecture**: ARM/x86
- **Memory**: 512MB+ RAM
- **Storage**: 100MB+ disk space

### Dependencies
- **Redis Server**: Must be running on system
- **libbpf**: eBPF support library
- **Python**: For model training (offline)

### Installation
```bash
# Install Redis
sudo apt install redis-server
sudo systemctl start redis-server

# Build RAVN
make all

# Run daemon
sudo ./artifacts/ravn

# Run CLI
./artifacts/ravn ctl
```

## Security Features

### Real-time Monitoring
- **System Call Tracking**: Monitor all system calls
- **Network Monitoring**: Track network operations
- **Security Events**: Monitor security-related operations
- **File I/O Tracking**: Monitor file operations

### Threat Detection
- **Sequence Analysis**: Analyze event sequences for attack patterns
- **Anomaly Detection**: Identify suspicious behavior
- **Threat Scoring**: Calculate real-time threat levels
- **Alert System**: Real-time threat notifications

### Professional Features
- **Historical Analysis**: Store and analyze threat events
- **Dashboard**: Real-time monitoring interface
- **Export**: Data export capabilities
- **Logging**: Comprehensive event logging

## Development Workflow

### 1. Model Training (Offline)
```bash
# Generate synthetic data
python scripts/generate_data.py

# Train model
python scripts/train_model.py

# Export model
python scripts/export_model.py
```

### 2. Daemon Development (C)
```bash
# Build daemon
make daemon

# Test eBPF programs
sudo ./artifacts/ravn-daemon
```

### 3. CLI Development (Rust)
```bash
# Build CLI
make cli

# Test dashboard
./artifacts/ravn-ctl
```

### 4. Integration Testing
```bash
# Start Redis
sudo systemctl start redis-server

# Run full system
sudo ./artifacts/ravn &
./artifacts/ravn ctl
```

## Future Enhancements

### Scalability
- **Multi-node support**: Distributed monitoring
- **Load balancing**: Handle high event volumes
- **Clustering**: Redis cluster support

### Advanced Features
- **Machine Learning**: Online learning capabilities
- **Threat Intelligence**: External threat feeds
- **Integration**: SIEM/SOAR platform integration
- **Compliance**: Regulatory compliance features

### Performance Optimization
- **GPU acceleration**: AI inference on GPU
- **Memory optimization**: Reduced memory footprint
- **Network optimization**: Efficient data transfer
- **Caching**: Intelligent data caching