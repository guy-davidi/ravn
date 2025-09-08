#!/usr/bin/env python3
"""
Generate C header file with model weights for compilation
This creates a C header that can be compiled directly into the binary
"""

import numpy as np
import json
import argparse
import os
from typing import List

def generate_c_header(weights_file: str, output_header: str):
    """Generate C header file with model weights organized by layer"""
    
    # Read weights from binary file
    all_weights = np.fromfile(weights_file, dtype=np.float32)
    
    # Model architecture (from training output):
    # Dense(10->64): 704 params, LSTM(64->128): 98,816 params, LSTM(128->64): 49,408 params
    # Dense(64->32): 2,080 params, Dense(32->3): 99 params
    # Total: 151,107 params
    
    # Define layer boundaries
    layer_boundaries = [
        ("dense1", 0, 704),           # Dense layer 1: 10*64 + 64 = 704
        ("lstm1", 704, 704 + 98816),  # LSTM layer 1: 98,816 params
        ("lstm2", 704 + 98816, 704 + 98816 + 49408),  # LSTM layer 2: 49,408 params
        ("dense2", 704 + 98816 + 49408, 704 + 98816 + 49408 + 2080),  # Dense layer 2: 2,080 params
        ("dense3", 704 + 98816 + 49408 + 2080, 704 + 98816 + 49408 + 2080 + 99)  # Dense layer 3: 99 params
    ]
    
    # Generate C header content
    header_content = f"""// Auto-generated model weights for RAVN AI Engine
// Generated from: {weights_file}
// Total weights: {len(all_weights)}

#ifndef RAVN_MODEL_WEIGHTS_H
#define RAVN_MODEL_WEIGHTS_H

#include <stdint.h>

// Model architecture constants
#define INPUT_SEQUENCE_LENGTH 20
#define INPUT_FEATURE_DIM 10
#define DENSE1_OUTPUT_SIZE 64
#define LSTM1_HIDDEN_SIZE 128
#define LSTM2_HIDDEN_SIZE 64
#define DENSE2_OUTPUT_SIZE 32
#define OUTPUT_CLASSES 3

// Layer weight counts
#define DENSE1_WEIGHT_COUNT 704
#define LSTM1_WEIGHT_COUNT 98816
#define LSTM2_WEIGHT_COUNT 49408
#define DENSE2_WEIGHT_COUNT 2080
#define DENSE3_WEIGHT_COUNT 99
#define TOTAL_WEIGHT_COUNT {len(all_weights)}

// All model weights (float32) - organized by layer
static const float all_model_weights[TOTAL_WEIGHT_COUNT] = {{
"""
    
    # Add all weights in groups of 10 for readability
    for i in range(0, len(all_weights), 10):
        weight_group = all_weights[i:i+10]
        weight_strs = [f"{w:.6f}f" for w in weight_group]
        header_content += "    " + ", ".join(weight_strs)
        if i + 10 < len(all_weights):
            header_content += ","
        header_content += "\n"
    
    header_content += """};

// Layer weight pointers for easy access
static const float* dense1_weights = &all_model_weights[0];
static const float* lstm1_weights = &all_model_weights[704];
static const float* lstm2_weights = &all_model_weights[99520];
static const float* dense2_weights = &all_model_weights[148928];
static const float* dense3_weights = &all_model_weights[151008];

// Model metadata
static const char* model_info = "RAVN AI Model - Full LSTM Implementation";
static const int model_version = 2;
static const int total_parameters = TOTAL_WEIGHT_COUNT;

#endif // RAVN_MODEL_WEIGHTS_H
"""
    
    # Write header file
    with open(output_header, 'w') as f:
        f.write(header_content)
    
    print(f"✅ Generated C header: {output_header}")
    print(f"   Total weights: {len(all_weights)}")
    print(f"   File size: {os.path.getsize(output_header)} bytes")
    print(f"   Architecture: Dense(704) → LSTM(98816) → LSTM(49408) → Dense(2080) → Dense(99)")
    
    return output_header

def main():
    parser = argparse.ArgumentParser(description='Generate C header from model weights')
    parser.add_argument('--weights', '-w', required=True, help='Input weights binary file')
    parser.add_argument('--output', '-o', default='../../src/daemon/model_weights.h', help='Output C header file')
    
    args = parser.parse_args()
    
    # Generate C header
    generate_c_header(args.weights, args.output)
    
    print(f"\n📝 Next steps:")
    print(f"1. Include '{args.output}' in your C code")
    print(f"2. Replace file loading with direct weight access")
    print(f"3. Recompile the application")

if __name__ == '__main__':
    main()
