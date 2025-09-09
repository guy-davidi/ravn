#!/bin/bash

# RAVN Smart Build System - Ask User Before Model Training

ARTIFACTS_DIR="artifacts"

if [ -f "$ARTIFACTS_DIR/.network_changed" ]; then
    NETWORK_CHANGED=$(cat "$ARTIFACTS_DIR/.network_changed" | cut -d'=' -f2)
    if [ "$NETWORK_CHANGED" = "1" ]; then
        echo ""
        echo "🤖 NETWORK TRAINING REQUIRED"
        echo "================================"
        echo "Network-related code has changed and requires model retraining."
        echo "This process may take several minutes."
        echo ""
        read -p "Do you want to retrain the AI model now? [y/N]: " confirm
        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            echo "[MODEL] User confirmed - proceeding with model training..."
            echo "TRAIN_MODEL=1" > "$ARTIFACTS_DIR/.train_model"
        else
            echo "[MODEL] User declined - skipping model training"
            echo "TRAIN_MODEL=0" > "$ARTIFACTS_DIR/.train_model"
        fi
    else
        echo "TRAIN_MODEL=0" > "$ARTIFACTS_DIR/.train_model"
    fi
else
    echo "TRAIN_MODEL=1" > "$ARTIFACTS_DIR/.train_model"
fi
