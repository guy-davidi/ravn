# RAVN AI Model Build Process

This document explains how to build and integrate the AI model into the RAVN security platform.

## Quick Start

**Single command to build everything:**
```bash
make model
```

This will:
1. Generate synthetic training data
2. Train the AI model
3. Generate C header file with weights
4. Ready for compilation

## Manual Process

If you prefer to run steps manually:

### 1. Generate Training Data
```bash
cd scripts/ai
python3 generate_data.py --output training_data.json
```

### 2. Train Model
```bash
python3 train_model.py --data training_data.json --output ravn_model.h5 --epochs 50
```

### 3. Generate C Code
```bash
python3 generate_c_model.py --weights ravn_model.h5_weights.bin --output ../../src/daemon/model_weights.h
```

### 4. Compile Application
```bash
cd ../..
make
```

## What Gets Generated

### Files Created:
- `src/daemon/model_weights.h` - C header with compiled weights
- `scripts/ai/best_model.h5` - TensorFlow model (for reference)
- `scripts/ai/training_history.png` - Training progress chart

### C Header Structure:
```c
#define MODEL_WEIGHT_COUNT 100
static const float model_weights[MODEL_WEIGHT_COUNT] = {
    0.123456f, 0.789012f, ...
};
```

## Benefits of Compiled Weights

- **No runtime file loading** - Weights compiled into binary  
- **Faster startup** - No file I/O during initialization  
- **Better security** - No external model files to tamper with  
- **Simpler deployment** - Single binary with embedded AI  
- **Version control** - Model version tracked in C code  

## Model Configuration

The model uses:
- **Input**: 20-event sequences with 10 features each
- **Architecture**: Dense + LSTM + Dense layers
- **Output**: 3 classes (Normal, Suspicious, Attack)
- **Weights**: 100 float values (simplified for C inference)

## Troubleshooting

### Missing Dependencies
```bash
# Install Python packages
pip install -r requirements.txt
```

### Permission Issues
```bash
chmod +x build_model.sh
```

### Model Not Loading
- Check that `model_weights.h` exists in `src/daemon/`
- Verify the header is included in `ai_engine.c`
- Run `make clean && make` to rebuild

## Customization

### Change Model Parameters
Edit `scripts/ai/train_model.py`:
- `--epochs` - Training iterations
- `--sequence-length` - Event sequence length
- `--feature-dim` - Features per event

### Modify Training Data
Edit `scripts/ai/generate_data.py`:
- Add new attack patterns
- Adjust normal behavior patterns
- Change data distribution

### Update C Integration
The C code automatically uses the generated weights. No changes needed unless you modify the model architecture.
