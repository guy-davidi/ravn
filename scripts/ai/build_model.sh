#!/bin/bash
# RAVN Model Build Script
# Generates training data, trains model, and creates C code

set -e  # Exit on any error

echo "RAVN Model Build Process"
echo "=========================="

# Check if we're in the right directory
if [ ! -f "train_model.py" ]; then
    echo "Error: Run this script from the scripts/ai directory"
    exit 1
fi

# Step 1: Generate training data
echo "Step 1: Generating training data..."
python3 generate_data.py --output training_data.json
echo "Training data generated"

# Step 2: Train model
echo "Step 2: Training AI model..."
python3 train_model.py --data training_data.json --output ../../artifacts/ravn_model.h5 --epochs 50
echo "Model trained"

# Step 3: Generate C header
echo "Step 3: Generating C code..."
python3 generate_c_model.py --weights ../../artifacts/ravn_model.h5_weights.bin --output ../../src/daemon/codegen/model_weights.h
echo "C header generated"

# Step 4: Clean up intermediate files (optional)
echo "Step 4: Cleaning up..."
# Uncomment the next line if you want to remove intermediate files
# rm -f training_data.json ravn_model.h5 ravn_model.h5_weights.bin ravn_model.h5_weights_info.json

echo ""
echo "Build completed successfully!"
echo ""
echo "Generated files:"
echo "   - src/daemon/codegen/model_weights.h (C header with weights)"
echo "   - artifacts/ravn_model.h5 (TensorFlow model)"
echo "   - artifacts/training_history.png (training chart)"
echo ""
echo "Next steps:"
echo "   1. Update src/daemon/ai_engine.c to use model_weights.h"
echo "   2. Run 'make' to compile with embedded weights"
echo "   3. No more runtime model loading needed!"
