# RAVN Security Dashboard

A cutting-edge web dashboard for real-time eBPF monitoring and AI threat analysis.

## Features

- **Real-time eBPF Event Monitoring**: Live stream of memory, process, kernel, and performance events
- **AI Analysis Logs**: Detailed threat analysis with scoring and recommendations
- **Interactive Charts**: Event rates, threat trends, and system statistics
- **WebSocket Integration**: Real-time updates without page refresh
- **Modern UI**: Built with Next.js, TypeScript, and Tailwind CSS
- **Redis Integration**: Efficient data storage and retrieval

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   eBPF Programs │───▶│   Redis Store   │───▶│  FastAPI Backend│
│  (Kernel Space) │    │   (Data Layer)  │    │   (API Layer)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │  Next.js Frontend│
                                               │   (UI Layer)    │
                                               └─────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.8+
- Node.js 18+
- Redis server
- RAVN eBPF monitoring system running

### Installation

1. **Clone and setup**:
   ```bash
   cd ravn-dashboard
   chmod +x start.sh
   ./start.sh
   ```

2. **Manual setup** (if needed):
   ```bash
   # Backend
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python main.py

   # Frontend (in another terminal)
   cd frontend
   npm install
   npm run dev
   ```

### Access

- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## API Endpoints

### REST API

- `GET /api/health` - Health check
- `GET /api/events/recent?limit=100` - Recent eBPF events
- `GET /api/ai/analyses?limit=50` - AI analysis results
- `GET /api/stats` - System statistics

### WebSocket

- `WS /ws` - Real-time updates for events, analyses, and stats

## Dashboard Components

### 1. Stats Cards
- Total events count
- Events per second rate
- AI analyses count
- Average threat score

### 2. Event Stream
- Live feed of eBPF events
- Color-coded by event type
- Expandable event details
- Real-time updates

### 3. AI Analysis Log
- Threat analysis results
- Threat score indicators
- Detailed recommendations
- Expandable analysis details

### 4. Interactive Charts
- Event rate over time
- Threat score trends
- Event type distribution
- System overview

## Data Flow

1. **eBPF Programs** collect system events
2. **RAVN Daemon** processes and stores events in Redis
3. **FastAPI Backend** serves data via REST API and WebSocket
4. **Next.js Frontend** displays real-time dashboard
5. **AI Engine** analyzes events and provides threat scores

## Redis Data Structure

```
ravn:events:memory     - List of memory events
ravn:events:process    - List of process events  
ravn:events:kernel     - List of kernel events
ravn:events:performance - List of performance events
ravn:ai:analyses       - List of AI analysis results
```

## Development

### Backend Development
```bash
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Frontend Development
```bash
cd frontend
npm install
npm run dev
```

### Adding New Features

1. **New Event Types**: Update `src/types/index.ts` and add handlers in `main.py`
2. **New Charts**: Create components in `src/components/Charts.tsx`
3. **New API Endpoints**: Add routes in `main.py`

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**:
   ```bash
   sudo systemctl start redis-server
   # or
   redis-server
   ```

2. **Port Already in Use**:
   - Backend: Change port in `main.py` (line 280)
   - Frontend: Change port in `package.json` scripts

3. **No Data Showing**:
   - Ensure RAVN daemon is running
   - Check Redis has data: `redis-cli llen ravn:events:memory`
   - Verify eBPF programs are attached

### Debug Mode

Enable debug logging:
```bash
# Backend
export LOG_LEVEL=DEBUG
python main.py

# Frontend
npm run dev -- --verbose
```

## Security Considerations

- Dashboard binds to localhost only (127.0.0.1) [[memory:8780391]]
- No authentication implemented (add for production)
- CORS enabled for development (restrict for production)
- WebSocket connections are not rate-limited

## Performance

- WebSocket connections auto-reconnect
- Event history limited to prevent memory issues
- Charts use efficient rendering with Recharts
- Redis provides fast data access

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is part of the RAVN Security Platform.
