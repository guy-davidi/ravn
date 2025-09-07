# RAVN AI Models Directory

This directory contains all AI model-related files organized by purpose:

## Directory Structure

### `trained/`
- **Purpose**: Contains trained TensorFlow/Keras models
- **Files**:
  - `ravn_model.h5` - Main trained model
  - `best_model.h5` - Best performing model (highest validation accuracy)

### `exported/`
- **Purpose**: Contains C-compatible model exports for daemon inference
- **Files**:
  - `ravn_model.c` - C implementation of the neural network
  - `ravn_model.h` - Header file with model definitions
  - `ravn_model_architecture.json` - Model architecture specification
  - `ravn_model_weights.bin` - Binary weights file
  - `ravn_model_weights_info.json` - Weights metadata
  - `ravn_model.h5_*` - Original export files from TensorFlow

### `data/`
- **Purpose**: Contains training and validation datasets
- **Files**:
  - `training_data.json` - Synthetic training data generated for model training

### `plots/`
- **Purpose**: Contains training visualization and analysis plots
- **Files**:
  - `training_history.png` - Training/validation loss and accuracy curves

## Model Information

- **Architecture**: CNN + LSTM hybrid model
- **Input**: 10-second sliding window of system events
- **Output**: Threat score (0.0 - 1.0)
- **Parameters**: ~50K parameters (optimized for embedded systems)
- **Training**: Synthetic data with realistic attack patterns

## Usage

The exported C model files in `exported/` are used by the RAVN daemon for real-time threat detection. The daemon loads the model weights and performs inference on incoming eBPF events using a sliding window approach.
