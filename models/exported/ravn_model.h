// RAVN AI Model Header
// Auto-generated from trained model

#ifndef RAVN_MODEL_H
#define RAVN_MODEL_H

#include <stdint.h>
#include <stddef.h>

// Model configuration
#define MODEL_INPUT_SIZE 200
#define MODEL_OUTPUT_SIZE 3
#define MODEL_NUM_LAYERS 9
#define MODEL_TOTAL_WEIGHTS 12

// Model weights
extern const float model_weights[12];

// Model functions
int model_init(void);
float model_predict(const float* input, float* output);
void model_cleanup(void);

// Utility functions
const char* get_threat_level_name(float score);
float sigmoid(float x);
float relu(float x);

#endif // RAVN_MODEL_H
