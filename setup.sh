#!/bin/bash

# RAVN Development Setup Script
# Sets up Python virtual environment and installs dependencies

set -e

echo "RAVN Development Setup"
echo "======================"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed"
    echo "Please install Python 3 and try again"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
    echo "Virtual environment created"
else
    echo "Virtual environment already exists"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Verify installation
echo "Verifying installation..."
python -c "import numpy; print(f'✓ NumPy {numpy.__version__}')"
python -c "import tensorflow as tf; print(f'✓ TensorFlow {tf.__version__}')"
python -c "import sklearn; print(f'✓ Scikit-learn {sklearn.__version__}')"

echo ""
echo "Setup complete!"
echo ""
echo "To activate the virtual environment in the future, run:"
echo "  source venv/bin/activate"
echo ""
echo "To build RAVN:"
echo "  make all"
echo ""
echo "To deactivate the virtual environment:"
echo "  deactivate"
