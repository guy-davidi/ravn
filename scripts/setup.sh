#!/bin/bash
# RAVN Setup Script
# Automated setup for RAVN Security Platform

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root. This is required for eBPF access."
    else
        log_warning "Not running as root. Some features may not work."
    fi
}

# Check system requirements
check_system() {
    log_info "Checking system requirements..."
    
    # Check kernel version
    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    REQUIRED_VERSION="5.4"
    
    if [[ $(echo "$KERNEL_VERSION >= $REQUIRED_VERSION" | bc -l) -eq 1 ]]; then
        log_success "Kernel version $KERNEL_VERSION is supported"
    else
        log_error "Kernel version $KERNEL_VERSION is not supported. Required: $REQUIRED_VERSION+"
        exit 1
    fi
    
    # Check architecture
    ARCH=$(uname -m)
    if [[ "$ARCH" == "x86_64" || "$ARCH" == "aarch64" ]]; then
        log_success "Architecture $ARCH is supported"
    else
        log_error "Architecture $ARCH is not supported"
        exit 1
    fi
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get"
        UPDATE_CMD="apt-get update"
        INSTALL_CMD="apt-get install -y"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        UPDATE_CMD="yum update -y"
        INSTALL_CMD="yum install -y"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        UPDATE_CMD="dnf update -y"
        INSTALL_CMD="dnf install -y"
    else
        log_error "Unsupported package manager"
        exit 1
    fi
    
    # Update package list
    log_info "Updating package list..."
    sudo $UPDATE_CMD
    
    # Install dependencies
    log_info "Installing build dependencies..."
    sudo $INSTALL_CMD \
        build-essential \
        clang \
        llvm \
        libbpf-dev \
        libelf-dev \
        zlib1g-dev \
        libssl-dev \
        pkg-config \
        cmake \
        git \
        curl \
        wget
    
    # Install Redis
    log_info "Installing Redis..."
    sudo $INSTALL_CMD redis-server
    
    # Install Python dependencies
    log_info "Installing Python dependencies..."
    if command -v python3 &> /dev/null; then
        sudo $INSTALL_CMD python3 python3-pip python3-venv
    else
        log_error "Python3 not found"
        exit 1
    fi
    
    log_success "System dependencies installed"
}

# Install Rust
install_rust() {
    log_info "Installing Rust toolchain..."
    
    if command -v cargo &> /dev/null; then
        log_success "Rust is already installed"
        return
    fi
    
    # Install Rust
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
    
    # Add Rust to PATH
    echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
    export PATH="$HOME/.cargo/bin:$PATH"
    
    log_success "Rust installed successfully"
}

# Setup Python environment
setup_python() {
    log_info "Setting up Python environment..."
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install Python dependencies
    pip install --upgrade pip
    pip install -r requirements.txt
    
    log_success "Python environment setup completed"
}

# Configure Redis
configure_redis() {
    log_info "Configuring Redis..."
    
    # Start Redis service
    sudo systemctl start redis-server
    sudo systemctl enable redis-server
    
    # Test Redis connection
    if redis-cli ping | grep -q "PONG"; then
        log_success "Redis is running"
    else
        log_error "Redis connection failed"
        exit 1
    fi
}

# Build the project
build_project() {
    log_info "Building RAVN project..."
    
    # Build everything
    make all
    
    if [[ $? -eq 0 ]]; then
        log_success "Project built successfully"
    else
        log_error "Build failed"
        exit 1
    fi
}

# Generate training data and train model
setup_ai_model() {
    log_info "Setting up AI model..."
    
    # Activate Python environment
    source venv/bin/activate
    
    # Create models directory
    mkdir -p models
    
    # Generate training data
    log_info "Generating training data..."
    python src/scripts/generate_data.py --output training_data.json --normal 1000 --suspicious 500 --attack 200
    
    # Train model
    log_info "Training AI model..."
    python src/scripts/train_model.py --data training_data.json --output ravn_model --epochs 50
    
    # Export model for C
    log_info "Exporting model for C inference..."
    python src/scripts/export_model.py --model ravn_model --output models/ravn_model
    
    log_success "AI model setup completed"
}

# Create systemd service
create_service() {
    log_info "Creating systemd service..."
    
    # Get current directory
    CURRENT_DIR=$(pwd)
    
    # Create service file
    sudo tee /etc/systemd/system/ravn.service > /dev/null <<EOF
[Unit]
Description=RAVN Security Platform
After=network.target redis.service
Requires=redis.service

[Service]
Type=simple
User=root
WorkingDirectory=$CURRENT_DIR
ExecStart=$CURRENT_DIR/artifacts/ravn
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    sudo systemctl daemon-reload
    
    log_success "Systemd service created"
}

# Main setup function
main() {
    log_info "Starting RAVN setup..."
    
    check_root
    check_system
    install_dependencies
    install_rust
    setup_python
    configure_redis
    build_project
    setup_ai_model
    create_service
    
    log_success "RAVN setup completed successfully!"
    
    echo ""
    echo "Next steps:"
    echo "1. Start the daemon: sudo systemctl start ravn"
    echo "2. Start the CLI: ./artifacts/ravn ctl"
    echo "3. Check status: sudo systemctl status ravn"
    echo ""
    echo "For more information, see README.md"
}

# Run main function
main "$@"
