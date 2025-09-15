#!/bin/bash

# RAVN Dashboard Startup Script
echo "🚀 Starting RAVN Dashboard..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install Python dependencies
echo "📥 Installing Python dependencies..."
pip install -r requirements.txt

# Check if Redis is running
echo "🔍 Checking Redis connection..."
if ! redis-cli ping > /dev/null 2>&1; then
    echo "⚠️  Redis is not running. Please start Redis first:"
    echo "   sudo systemctl start redis-server"
    echo "   or"
    echo "   redis-server"
    exit 1
fi

# Check if Node.js is installed
echo "🔍 Checking Node.js installation..."
if ! command -v node &> /dev/null || ! command -v npm &> /dev/null; then
    echo "📦 Node.js not found. Installing Node.js and npm..."
    
    # Update package list
    sudo apt update
    
    # Install Node.js and npm
    sudo apt install -y nodejs npm
    
    # Verify installation
    if ! command -v node &> /dev/null || ! command -v npm &> /dev/null; then
        echo "❌ Failed to install Node.js. Please install manually:"
        echo "   sudo apt update && sudo apt install -y nodejs npm"
        exit 1
    fi
    
    echo "✅ Node.js installed successfully"
    echo "   Node version: $(node --version)"
    echo "   NPM version: $(npm --version)"
else
    echo "✅ Node.js already installed"
    echo "   Node version: $(node --version)"
    echo "   NPM version: $(npm --version)"
fi

# Check if RAVN daemon is running (optional)
echo "🔍 Checking RAVN daemon status..."
if pgrep -f "ravn.*daemon" > /dev/null; then
    echo "✅ RAVN daemon is running (generating eBPF data)"
else
    echo "⚠️  RAVN daemon is not running. Dashboard will show no data."
    echo "   To start RAVN daemon: sudo ./artifacts/ravn --daemon"
    echo "   (This is optional - dashboard will work without it)"
fi

# Start FastAPI backend
echo "🌐 Starting FastAPI backend..."
python main.py &
BACKEND_PID=$!

# Wait for backend to start
sleep 3

# Check if frontend dependencies are installed
if [ ! -d "frontend/node_modules" ]; then
    echo "📦 Installing frontend dependencies..."
    cd frontend
    npm install --force
    cd ..
else
    echo "✅ Frontend dependencies already installed"
fi

# Start Next.js frontend
echo "🎨 Starting Next.js frontend..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo "✅ RAVN Dashboard is starting up!"
echo "📊 Backend API: http://localhost:8000"
echo "🎨 Frontend: http://localhost:3000"
echo ""
echo "Press Ctrl+C to stop all services"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down RAVN Dashboard..."
    
    # Kill backend process
    if [ ! -z "$BACKEND_PID" ]; then
        echo "   Stopping FastAPI backend (PID: $BACKEND_PID)..."
        kill -TERM $BACKEND_PID 2>/dev/null
        sleep 2
        kill -KILL $BACKEND_PID 2>/dev/null
    fi
    
    # Kill frontend process
    if [ ! -z "$FRONTEND_PID" ]; then
        echo "   Stopping Next.js frontend (PID: $FRONTEND_PID)..."
        kill -TERM $FRONTEND_PID 2>/dev/null
        sleep 2
        kill -KILL $FRONTEND_PID 2>/dev/null
    fi
    
    # Kill any remaining node processes
    pkill -f "next dev" 2>/dev/null
    pkill -f "uvicorn" 2>/dev/null
    
    echo "✅ All services stopped"
    exit 0
}

# Trap Ctrl+C and other signals
trap cleanup SIGINT SIGTERM EXIT

# Wait for processes
wait
