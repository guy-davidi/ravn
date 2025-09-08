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
    """Generate C header file with model weights"""
    
    # Read weights from binary file
    weights = np.fromfile(weights_file, dtype=np.float32)
    
    # For now, take first 100 weights (simplified inference)
    # TODO: Implement proper LSTM inference in C
    weights = weights[:100]
    
    # Generate C header content
    header_content = f"""// Auto-generated model weights for RAVN AI Engine
// Generated from: {weights_file}
// Number of weights: {len(weights)}

#ifndef RAVN_MODEL_WEIGHTS_H
#define RAVN_MODEL_WEIGHTS_H

#include <stdint.h>

// Model configuration
#define MODEL_WEIGHT_COUNT {len(weights)}
#define MODEL_FEATURE_COUNT 100

// Model weights (float32)
static const float model_weights[MODEL_WEIGHT_COUNT] = {{
"""
    
    # Add weights in groups of 10 for readability
    for i in range(0, len(weights), 10):
        weight_group = weights[i:i+10]
        weight_strs = [f"{w:.6f}f" for w in weight_group]
        header_content += "    " + ", ".join(weight_strs)
        if i + 10 < len(weights):
            header_content += ","
        header_content += "\n"
    
    header_content += """};

// Model metadata
static const char* model_info = "RAVN AI Model - Generated from TensorFlow";
static const int model_version = 1;

#endif // RAVN_MODEL_WEIGHTS_H
"""
    
    # Write header file
    with open(output_header, 'w') as f:
        f.write(header_content)
    
    print(f"✅ Generated C header: {output_header}")
    print(f"   Weights: {len(weights)}")
    print(f"   File size: {os.path.getsize(output_header)} bytes")
    
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
