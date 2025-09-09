#!/bin/bash

# RAVN Smart Build System - Network Change Detection Script

ARTIFACTS_DIR="artifacts"
SRC_DIR="src"
MODEL_HEADER="$SRC_DIR/daemon/codegen/model_weights.h"
NETWORK_HASH_FILE="$ARTIFACTS_DIR/.network_hash"

# Network-related files that require model retraining
NETWORK_FILES="$SRC_DIR/daemon/ai_engine.c \
               $SRC_DIR/daemon/ai_engine.h \
               $SRC_DIR/daemon/ravn_lstm.h \
               $SRC_DIR/daemon/ravn_rnn_lstm.c \
               $SRC_DIR/daemon/codegen/model_weights.h \
               scripts/ai/train_model.py \
               scripts/ai/build_model.sh"

mkdir -p "$ARTIFACTS_DIR"

# Check if we have a previous hash
if [ ! -f "$NETWORK_HASH_FILE" ]; then
    echo "[SMART] No previous network hash found - will train model"
    echo "NEW" > "$NETWORK_HASH_FILE"
fi

# Calculate current hash of network files
CURRENT_HASH=$(find $NETWORK_FILES -type f -exec md5sum {} \; 2>/dev/null | sort | md5sum | cut -d' ' -f1)
STORED_HASH=$(cat "$NETWORK_HASH_FILE" 2>/dev/null || echo "NEW")

# Check if model file exists and has correct dimensions
if [ -f "$MODEL_HEADER" ]; then
    MODEL_FEATURES=$(grep "INPUT_FEATURE_DIM" "$MODEL_HEADER" | head -1 | sed 's/.*INPUT_FEATURE_DIM \([0-9]*\).*/\1/')
    HEADER_FEATURES=$(grep "INPUT_FEATURE_DIM" "$SRC_DIR/daemon/ravn_lstm.h" | head -1 | sed 's/.*INPUT_FEATURE_DIM \([0-9]*\).*/\1/')
    
    if [ "$MODEL_FEATURES" != "$HEADER_FEATURES" ]; then
        echo "[SMART] Model dimension mismatch detected!"
        echo "Model has $MODEL_FEATURES features, header expects $HEADER_FEATURES features"
        echo "$CURRENT_HASH" > "$NETWORK_HASH_FILE"
        echo "NETWORK_CHANGED=1" > "$ARTIFACTS_DIR/.network_changed"
    elif [ "$CURRENT_HASH" != "$STORED_HASH" ]; then
        echo "[SMART] Network code changes detected!"
        echo "Current hash: $CURRENT_HASH"
        echo "Stored hash: $STORED_HASH"
        echo "$CURRENT_HASH" > "$NETWORK_HASH_FILE"
        echo "NETWORK_CHANGED=1" > "$ARTIFACTS_DIR/.network_changed"
    else
        echo "[SMART] No network changes detected - skipping model training"
        echo "NETWORK_CHANGED=0" > "$ARTIFACTS_DIR/.network_changed"
    fi
else
    echo "[SMART] No model file found - will train model"
    echo "$CURRENT_HASH" > "$NETWORK_HASH_FILE"
    echo "NETWORK_CHANGED=1" > "$ARTIFACTS_DIR/.network_changed"
fi
