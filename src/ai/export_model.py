#!/usr/bin/env python3
"""
RAVN Model Export Script
Exports trained model for C inference
"""

import numpy as np
import json
import argparse
import os
import tensorflow as tf
from typing import Dict, Any

class ModelExporter:
    def __init__(self, model_path: str):
        """Initialize the model exporter"""
        self.model_path = model_path
        self.model = None
        self.metadata = None
        
    def load_model(self):
        """Load the trained model"""
        print(f"Loading model from {self.model_path}...")
        self.model = tf.keras.models.load_model(self.model_path)
        
        # Load metadata
        metadata_path = f"{self.model_path}_metadata.json"
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                self.metadata = json.load(f)
        else:
            print("Warning: No metadata file found")
            self.metadata = {}
        
        print("Model loaded successfully")
        print(f"Input shape: {self.model.input_shape}")
        print(f"Output shape: {self.model.output_shape}")
    
    def export_weights(self, output_path: str):
        """Export model weights to binary format"""
        if self.model is None:
            raise ValueError("No model loaded. Call load_model() first.")
        
        print("Exporting model weights...")
        
        # Get all layer weights
        weights = self.model.get_weights()
        
        # Create weight structure for C
        weight_data = {
            'num_layers': len(weights),
            'weights': [],
            'layer_info': []
        }
        
        total_weights = 0
        for i, layer_weights in enumerate(weights):
            layer_info = {
                'layer_index': i,
                'shape': list(layer_weights.shape),
                'size': layer_weights.size,
                'offset': total_weights,
                'dtype': str(layer_weights.dtype)
            }
            
            weight_data['layer_info'].append(layer_info)
            weight_data['weights'].extend(layer_weights.flatten().tolist())
            total_weights += layer_weights.size
        
        # Save weights as binary file
        weights_array = np.array(weight_data['weights'], dtype=np.float32)
        weights_bin_path = f"{output_path}_weights.bin"
        weights_array.tofile(weights_bin_path)
        
        # Save weight metadata
        weight_info_path = f"{output_path}_weights_info.json"
        with open(weight_info_path, 'w') as f:
            json.dump(weight_data, f, indent=2)
        
        print(f"Weights exported to {weights_bin_path}")
        print(f"Weight info saved to {weight_info_path}")
        print(f"Total weights: {total_weights}")
    
    def export_architecture(self, output_path: str):
        """Export model architecture for C"""
        if self.model is None:
            raise ValueError("No model loaded. Call load_model() first.")
        
        print("Exporting model architecture...")
        
        architecture = {
            'input_shape': list(self.model.input_shape[1:]),  # Remove batch dimension
            'output_shape': list(self.model.output_shape[1:]),  # Remove batch dimension
            'layers': [],
            'total_parameters': self.model.count_params()
        }
        
        # Extract layer information
        for i, layer in enumerate(self.model.layers):
            layer_info = {
                'index': i,
                'name': layer.name,
                'type': layer.__class__.__name__,
                'input_shape': list(layer.input_shape[1:]) if hasattr(layer, 'input_shape') and layer.input_shape else None,
                'output_shape': list(layer.output_shape[1:]) if hasattr(layer, 'output_shape') and layer.output_shape else None,
                'parameters': layer.count_params()
            }
            
            # Add layer-specific parameters
            if hasattr(layer, 'units'):
                layer_info['units'] = layer.units
            if hasattr(layer, 'activation'):
                layer_info['activation'] = layer.activation.__name__ if hasattr(layer.activation, '__name__') else str(layer.activation)
            if hasattr(layer, 'dropout'):
                layer_info['dropout'] = layer.dropout
            if hasattr(layer, 'return_sequences'):
                layer_info['return_sequences'] = layer.return_sequences
            
            architecture['layers'].append(layer_info)
        
        # Save architecture
        arch_path = f"{output_path}_architecture.json"
        with open(arch_path, 'w') as f:
            json.dump(architecture, f, indent=2)
        
        print(f"Architecture exported to {arch_path}")
    
    def generate_c_header(self, output_path: str):
        """Generate C header file for model inference"""
        if self.model is None:
            raise ValueError("No model loaded. Call load_model() first.")
        
        print("Generating C header file...")
        
        # Load weight info
        weight_info_path = f"{output_path}_weights_info.json"
        if not os.path.exists(weight_info_path):
            raise FileNotFoundError(f"Weight info file not found: {weight_info_path}")
        
        with open(weight_info_path, 'r') as f:
            weight_data = json.load(f)
        
        # Generate C header
        header_content = f"""// RAVN AI Model Header
// Auto-generated from trained model

#ifndef RAVN_MODEL_H
#define RAVN_MODEL_H

#include <stdint.h>
#include <stddef.h>

// Model configuration
#define MODEL_INPUT_SIZE {self.model.input_shape[1] * self.model.input_shape[2]}
#define MODEL_OUTPUT_SIZE {self.model.output_shape[1]}
#define MODEL_NUM_LAYERS {len(self.model.layers)}
#define MODEL_TOTAL_WEIGHTS {weight_data['num_layers']}

// Model weights
extern const float model_weights[{weight_data['num_layers']}];

// Model functions
int model_init(void);
float model_predict(const float* input, float* output);
void model_cleanup(void);

// Utility functions
const char* get_threat_level_name(float score);
float sigmoid(float x);
float relu(float x);

#endif // RAVN_MODEL_H
"""
        
        header_path = f"{output_path}.h"
        with open(header_path, 'w') as f:
            f.write(header_content)
        
        print(f"C header generated: {header_path}")
    
    def generate_c_source(self, output_path: str):
        """Generate C source file for model inference"""
        if self.model is None:
            raise ValueError("No model loaded. Call load_model() first.")
        
        print("Generating C source file...")
        
        # Load weight info
        weight_info_path = f"{output_path}_weights_info.json"
        if not os.path.exists(weight_info_path):
            raise FileNotFoundError(f"Weight info file not found: {weight_info_path}")
        
        with open(weight_info_path, 'r') as f:
            weight_data = json.load(f)
        
        # Load weights
        weights_bin_path = f"{output_path}_weights.bin"
        if not os.path.exists(weights_bin_path):
            raise FileNotFoundError(f"Weights file not found: {weights_bin_path}")
        
        weights = np.fromfile(weights_bin_path, dtype=np.float32)
        
        # Generate C source
        source_content = f"""// RAVN AI Model Implementation
// Auto-generated from trained model

#include "{os.path.basename(output_path)}.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// Model weights
const float model_weights[{len(weights)}] = {{
"""
        
        # Add weights (formatted for readability)
        for i, weight in enumerate(weights):
            if i % 10 == 0:
                source_content += "    "
            source_content += f"{weight:.6f}f"
            if i < len(weights) - 1:
                source_content += ", "
            if i % 10 == 9:
                source_content += "\\n"
        
        source_content += """
};

// Model state
static int model_initialized = 0;

// Initialize model
int model_init(void) {
    if (model_initialized) {
        return 0;
    }
    
    printf("[Model] Initializing RAVN AI model...\\n");
    printf("[Model] Input size: %d\\n", MODEL_INPUT_SIZE);
    printf("[Model] Output size: %d\\n", MODEL_OUTPUT_SIZE);
    printf("[Model] Total weights: %d\\n", MODEL_TOTAL_WEIGHTS);
    
    model_initialized = 1;
    printf("[Model] Model initialized successfully\\n");
    return 0;
}

// Predict using model (simplified implementation)
float model_predict(const float* input, float* output) {
    if (!model_initialized || !input || !output) {
        return -1.0f;
    }
    
    // Simplified prediction (in real implementation, would use full neural network)
    float sum = 0.0f;
    for (int i = 0; i < MODEL_INPUT_SIZE; i++) {
        sum += input[i] * model_weights[i % MODEL_TOTAL_WEIGHTS];
    }
    
    // Apply sigmoid activation
    float prediction = sigmoid(sum);
    
    // Set output (simplified - would be full softmax in real implementation)
    output[0] = 1.0f - prediction;  // Normal probability
    output[1] = prediction * 0.5f;  // Suspicious probability
    output[2] = prediction * 0.5f;  // Attack probability
    
    return prediction;
}

// Cleanup model
void model_cleanup(void) {
    if (!model_initialized) {
        return;
    }
    
    printf("[Model] Cleaning up RAVN AI model...\\n");
    model_initialized = 0;
    printf("[Model] Model cleanup completed\\n");
}

// Get threat level name
const char* get_threat_level_name(float score) {
    if (score >= 0.9f) {
        return "CRITICAL";
    } else if (score >= 0.7f) {
        return "HIGH";
    } else if (score >= 0.3f) {
        return "MEDIUM";
    } else {
        return "LOW";
    }
}

// Sigmoid activation function
float sigmoid(float x) {
    return 1.0f / (1.0f + expf(-x));
}

// ReLU activation function
float relu(float x) {
    return (x > 0.0f) ? x : 0.0f;
}
"""
        
        source_path = f"{output_path}.c"
        with open(source_path, 'w') as f:
            f.write(source_content)
        
        print(f"C source generated: {source_path}")
    
    def export_all(self, output_path: str):
        """Export everything for C inference"""
        self.load_model()
        self.export_weights(output_path)
        self.export_architecture(output_path)
        self.generate_c_header(output_path)
        self.generate_c_source(output_path)
        
        print("\\nModel export completed!")
        print(f"Generated files:")
        print(f"  - {output_path}_weights.bin (binary weights)")
        print(f"  - {output_path}_weights_info.json (weight metadata)")
        print(f"  - {output_path}_architecture.json (model architecture)")
        print(f"  - {output_path}.h (C header)")
        print(f"  - {output_path}.c (C source)")

def main():
    parser = argparse.ArgumentParser(description='Export RAVN AI model for C inference')
    parser.add_argument('--model', '-m', required=True, help='Path to trained model')
    parser.add_argument('--output', '-o', default='ravn_model', help='Output path prefix')
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else '.', exist_ok=True)
    
    # Export model
    exporter = ModelExporter(args.model)
    exporter.export_all(args.output)

if __name__ == '__main__':
    main()
