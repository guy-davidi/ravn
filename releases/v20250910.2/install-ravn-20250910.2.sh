#!/bin/bash
# RAVN Security Platform Installation Script

set -e

echo "RAVN Security Platform v20250910.2 Installation"
echo "=============================================="

# Check if running as root
if [ "$EUID" -eq 0 ]; then
  echo "Please do not run this script as root"
  exit 1
fi

# Check dependencies
echo "Checking dependencies..."

if ! command -v gcc &> /dev/null; then
  echo "Error: gcc is required but not installed"
  echo "Please install: sudo apt-get install build-essential"
  exit 1
fi

if ! command -v redis-server &> /dev/null; then
  echo "Error: Redis is required but not installed"
  echo "Please install: sudo apt-get install redis-server"
  exit 1
fi

# Install binary
echo "Installing RAVN binary..."
sudo cp ravn-20250910.2-linux-x86_64 /usr/local/bin/ravn
sudo chmod +x /usr/local/bin/ravn

# Verify installation
if /usr/local/bin/ravn --version; then
  echo ""
  echo "Installation successful!"
  echo "RAVN Security Platform v20250910.2 is now installed"
  echo ""
  echo "Usage:"
  echo "  sudo ravn daemon    # Start monitoring daemon"
  echo "  ravn cli           # Start CLI dashboard"
  echo "  ravn --version     # Show version information"
  echo "  ravn --help        # Show help"
else
  echo "Error: Installation verification failed"
  exit 1
fi
