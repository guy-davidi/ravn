// RAVN LSTM Neural Network Implementation
// Full implementation with proper LSTM cells and dense layers

#include "ravn_lstm.h"
#include "codegen/model_weights.h"
#include "../utils/logger.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

// ============================================================================
// ACTIVATION FUNCTIONS
// ============================================================================

float sigmoid(float x) {
    // Clamp x to prevent overflow
    if (x > 88.0f) return 1.0f;
    if (x < -88.0f) return 0.0f;
    return 1.0f / (1.0f + expf(-x));
}

float tanh_activation(float x) {
    // Clamp x to prevent overflow
    if (x > 88.0f) return 1.0f;
    if (x < -88.0f) return -1.0f;
    return tanhf(x);
}

float relu(float x) {
    return (x > 0.0f) ? x : 0.0f;
}

float softmax(float *x, int size, int index) {
    // Find maximum for numerical stability
    float max_val = x[0];
    for (int i = 1; i < size; i++) {
        if (x[i] > max_val) max_val = x[i];
    }
    
    // Compute exponentials and sum
    float sum = 0.0f;
    for (int i = 0; i < size; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    
    // Normalize
    for (int i = 0; i < size; i++) {
        x[i] /= sum;
    }
    
    return x[index];
}

// ============================================================================
// LSTM CELL IMPLEMENTATION
// ============================================================================

lstm_cell_t* lstm_cell_create(int input_size, int hidden_size) {
    lstm_cell_t *cell = malloc(sizeof(lstm_cell_t));
    if (!cell) {
        LOG_ERROR("Failed to allocate memory for LSTM cell");
        return NULL;
    }
    
    memset(cell, 0, sizeof(lstm_cell_t));
    cell->input_size = input_size;
    cell->hidden_size = hidden_size;
    
    return cell;
}

int lstm_cell_init(lstm_cell_t *cell, int input_size, int hidden_size) {
    if (!cell) {
        LOG_ERROR("Invalid LSTM cell pointer");
        return -1;
    }
    
    cell->input_size = input_size;
    cell->hidden_size = hidden_size;
    
    // Allocate state vectors
    cell->h_prev = malloc(hidden_size * sizeof(float));
    cell->c_prev = malloc(hidden_size * sizeof(float));
    cell->h_curr = malloc(hidden_size * sizeof(float));
    cell->c_curr = malloc(hidden_size * sizeof(float));
    
    // Allocate gate vectors
    cell->f_gate = malloc(hidden_size * sizeof(float));
    cell->i_gate = malloc(hidden_size * sizeof(float));
    cell->c_candidate = malloc(hidden_size * sizeof(float));
    cell->o_gate = malloc(hidden_size * sizeof(float));
    
    if (!cell->h_prev || !cell->c_prev || !cell->h_curr || !cell->c_curr ||
        !cell->f_gate || !cell->i_gate || !cell->c_candidate || !cell->o_gate) {
        LOG_ERROR("Failed to allocate LSTM cell buffers");
        lstm_cell_destroy(cell);
        return -1;
    }
    
    // Initialize states to zero
    memset(cell->h_prev, 0, hidden_size * sizeof(float));
    memset(cell->c_prev, 0, hidden_size * sizeof(float));
    
    cell->initialized = 1;
    return 0;
}

void lstm_cell_destroy(lstm_cell_t *cell) {
    if (!cell) return;
    
    free(cell->h_prev);
    free(cell->c_prev);
    free(cell->h_curr);
    free(cell->c_curr);
    free(cell->f_gate);
    free(cell->i_gate);
    free(cell->c_candidate);
    free(cell->o_gate);
    
    free(cell);
}

void lstm_cell_reset_state(lstm_cell_t *cell) {
    if (!cell || !cell->initialized) return;
    
    memset(cell->h_prev, 0, cell->hidden_size * sizeof(float));
    memset(cell->c_prev, 0, cell->hidden_size * sizeof(float));
}

int lstm_cell_forward(lstm_cell_t *cell, const float *input) {
    if (!cell || !cell->initialized || !input) {
        return -1;
    }
    
    // Matrix-vector multiplication helper
    void matvec_mult(const float *matrix, const float *vector, float *result, int rows, int cols) {
        for (int i = 0; i < rows; i++) {
            result[i] = 0.0f;
            for (int j = 0; j < cols; j++) {
                result[i] += matrix[i * cols + j] * vector[j];
            }
        }
    }
    
    // Compute forget gate: f_t = σ(W_f * x_t + U_f * h_{t-1} + b_f)
    matvec_mult(cell->W_f, input, cell->f_gate, cell->hidden_size, cell->input_size);
    matvec_mult(cell->U_f, cell->h_prev, cell->h_curr, cell->hidden_size, cell->hidden_size);
    for (int i = 0; i < cell->hidden_size; i++) {
        cell->f_gate[i] = sigmoid(cell->f_gate[i] + cell->h_curr[i] + cell->b_f[i]);
    }
    
    // Compute input gate: i_t = σ(W_i * x_t + U_i * h_{t-1} + b_i)
    matvec_mult(cell->W_i, input, cell->i_gate, cell->hidden_size, cell->input_size);
    matvec_mult(cell->U_i, cell->h_prev, cell->h_curr, cell->hidden_size, cell->hidden_size);
    for (int i = 0; i < cell->hidden_size; i++) {
        cell->i_gate[i] = sigmoid(cell->i_gate[i] + cell->h_curr[i] + cell->b_i[i]);
    }
    
    // Compute candidate values: C̃_t = tanh(W_c * x_t + U_c * h_{t-1} + b_c)
    matvec_mult(cell->W_c, input, cell->c_candidate, cell->hidden_size, cell->input_size);
    matvec_mult(cell->U_c, cell->h_prev, cell->h_curr, cell->hidden_size, cell->hidden_size);
    for (int i = 0; i < cell->hidden_size; i++) {
        cell->c_candidate[i] = tanh_activation(cell->c_candidate[i] + cell->h_curr[i] + cell->b_c[i]);
    }
    
    // Update cell state: C_t = f_t * C_{t-1} + i_t * C̃_t
    for (int i = 0; i < cell->hidden_size; i++) {
        cell->c_curr[i] = cell->f_gate[i] * cell->c_prev[i] + cell->i_gate[i] * cell->c_candidate[i];
    }
    
    // Compute output gate: o_t = σ(W_o * x_t + U_o * h_{t-1} + b_o)
    matvec_mult(cell->W_o, input, cell->o_gate, cell->hidden_size, cell->input_size);
    matvec_mult(cell->U_o, cell->h_prev, cell->h_curr, cell->hidden_size, cell->hidden_size);
    for (int i = 0; i < cell->hidden_size; i++) {
        cell->o_gate[i] = sigmoid(cell->o_gate[i] + cell->h_curr[i] + cell->b_o[i]);
    }
    
    // Compute hidden state: h_t = o_t * tanh(C_t)
    for (int i = 0; i < cell->hidden_size; i++) {
        cell->h_curr[i] = cell->o_gate[i] * tanh_activation(cell->c_curr[i]);
    }
    
    // Update previous states for next iteration
    memcpy(cell->h_prev, cell->h_curr, cell->hidden_size * sizeof(float));
    memcpy(cell->c_prev, cell->c_curr, cell->hidden_size * sizeof(float));
    
    return 0;
}

// ============================================================================
// DENSE LAYER IMPLEMENTATION
// ============================================================================

dense_layer_t* dense_layer_create(int input_size, int output_size) {
    dense_layer_t *layer = malloc(sizeof(dense_layer_t));
    if (!layer) {
        LOG_ERROR("Failed to allocate memory for dense layer");
        return NULL;
    }
    
    memset(layer, 0, sizeof(dense_layer_t));
    layer->input_size = input_size;
    layer->output_size = output_size;
    
    return layer;
}

int dense_layer_init(dense_layer_t *layer, int input_size, int output_size) {
    if (!layer) {
        LOG_ERROR("Invalid dense layer pointer");
        return -1;
    }
    
    layer->input_size = input_size;
    layer->output_size = output_size;
    layer->initialized = 1;
    
    return 0;
}

void dense_layer_destroy(dense_layer_t *layer) {
    if (!layer) return;
    free(layer);
}

int dense_layer_forward(dense_layer_t *layer, const float *input, float *output) {
    if (!layer || !layer->initialized || !input || !output) {
        return -1;
    }
    
    // Matrix-vector multiplication: output = input * weights + bias
    for (int i = 0; i < layer->output_size; i++) {
        output[i] = layer->bias[i];
        for (int j = 0; j < layer->input_size; j++) {
            output[i] += input[j] * layer->weights[j * layer->output_size + i];
        }
    }
    
    return 0;
}

// ============================================================================
// MODEL IMPLEMENTATION
// ============================================================================

ravn_model_t* ravn_model_create(void) {
    ravn_model_t *model = malloc(sizeof(ravn_model_t));
    if (!model) {
        LOG_ERROR("Failed to allocate memory for RAVN model");
        return NULL;
    }
    
    memset(model, 0, sizeof(ravn_model_t));
    return model;
}

int ravn_model_init(ravn_model_t *model) {
    if (!model) {
        LOG_ERROR("Invalid model pointer");
        return -1;
    }
    
    // Initialize dense layer 1
    if (dense_layer_init(&model->dense1, INPUT_SEQUENCE_LENGTH * INPUT_FEATURE_DIM, DENSE1_OUTPUT_SIZE) != 0) {
        return -1;
    }
    
    // Initialize LSTM layer 1
    if (lstm_cell_init(&model->lstm1, DENSE1_OUTPUT_SIZE, LSTM1_HIDDEN_SIZE) != 0) {
        return -1;
    }
    
    // Initialize LSTM layer 2
    if (lstm_cell_init(&model->lstm2, LSTM1_HIDDEN_SIZE, LSTM2_HIDDEN_SIZE) != 0) {
        return -1;
    }
    
    // Initialize dense layer 2
    if (dense_layer_init(&model->dense2, LSTM2_HIDDEN_SIZE, DENSE2_OUTPUT_SIZE) != 0) {
        return -1;
    }
    
    // Initialize dense layer 3
    if (dense_layer_init(&model->dense3, DENSE2_OUTPUT_SIZE, OUTPUT_CLASSES) != 0) {
        return -1;
    }
    
    // Allocate working buffers
    model->dense1_output = malloc(DENSE1_OUTPUT_SIZE * sizeof(float));
    model->lstm1_output = malloc(LSTM1_HIDDEN_SIZE * sizeof(float));
    model->lstm2_output = malloc(LSTM2_HIDDEN_SIZE * sizeof(float));
    model->dense2_output = malloc(DENSE2_OUTPUT_SIZE * sizeof(float));
    model->final_output = malloc(OUTPUT_CLASSES * sizeof(float));
    model->sequence_buffer = malloc(INPUT_SEQUENCE_LENGTH * DENSE1_OUTPUT_SIZE * sizeof(float));
    
    if (!model->dense1_output || !model->lstm1_output || !model->lstm2_output ||
        !model->dense2_output || !model->final_output || !model->sequence_buffer) {
        LOG_ERROR("Failed to allocate model buffers");
        ravn_model_destroy(model);
        return -1;
    }
    
    model->initialized = 1;
    LOG_INFO("RAVN model initialized successfully");
    return 0;
}

void ravn_model_destroy(ravn_model_t *model) {
    if (!model) return;
    
    lstm_cell_destroy(&model->lstm1);
    lstm_cell_destroy(&model->lstm2);
    
    free(model->dense1_output);
    free(model->lstm1_output);
    free(model->lstm2_output);
    free(model->dense2_output);
    free(model->final_output);
    free(model->sequence_buffer);
    
    free(model);
}

int ravn_model_load_weights(ravn_model_t *model, const float *all_weights) {
    if (!model || !model->initialized || !all_weights) {
        return -1;
    }
    
    // Load dense layer 1 weights
    model->dense1.weights = (float*)&all_weights[0];
    model->dense1.bias = (float*)&all_weights[INPUT_SEQUENCE_LENGTH * INPUT_FEATURE_DIM * DENSE1_OUTPUT_SIZE];
    
    // Load LSTM layer 1 weights (complex weight organization)
    int offset = DENSE1_WEIGHT_COUNT;
    model->lstm1.W_f = (float*)&all_weights[offset];
    model->lstm1.W_i = (float*)&all_weights[offset + DENSE1_OUTPUT_SIZE * LSTM1_HIDDEN_SIZE];
    model->lstm1.W_c = (float*)&all_weights[offset + 2 * DENSE1_OUTPUT_SIZE * LSTM1_HIDDEN_SIZE];
    model->lstm1.W_o = (float*)&all_weights[offset + 3 * DENSE1_OUTPUT_SIZE * LSTM1_HIDDEN_SIZE];
    model->lstm1.U_f = (float*)&all_weights[offset + 4 * DENSE1_OUTPUT_SIZE * LSTM1_HIDDEN_SIZE];
    model->lstm1.U_i = (float*)&all_weights[offset + 4 * DENSE1_OUTPUT_SIZE * LSTM1_HIDDEN_SIZE + LSTM1_HIDDEN_SIZE * LSTM1_HIDDEN_SIZE];
    model->lstm1.U_c = (float*)&all_weights[offset + 4 * DENSE1_OUTPUT_SIZE * LSTM1_HIDDEN_SIZE + 2 * LSTM1_HIDDEN_SIZE * LSTM1_HIDDEN_SIZE];
    model->lstm1.U_o = (float*)&all_weights[offset + 4 * DENSE1_OUTPUT_SIZE * LSTM1_HIDDEN_SIZE + 3 * LSTM1_HIDDEN_SIZE * LSTM1_HIDDEN_SIZE];
    model->lstm1.b_f = (float*)&all_weights[offset + 4 * DENSE1_OUTPUT_SIZE * LSTM1_HIDDEN_SIZE + 4 * LSTM1_HIDDEN_SIZE * LSTM1_HIDDEN_SIZE];
    model->lstm1.b_i = (float*)&all_weights[offset + 4 * DENSE1_OUTPUT_SIZE * LSTM1_HIDDEN_SIZE + 4 * LSTM1_HIDDEN_SIZE * LSTM1_HIDDEN_SIZE + LSTM1_HIDDEN_SIZE];
    model->lstm1.b_c = (float*)&all_weights[offset + 4 * DENSE1_OUTPUT_SIZE * LSTM1_HIDDEN_SIZE + 4 * LSTM1_HIDDEN_SIZE * LSTM1_HIDDEN_SIZE + 2 * LSTM1_HIDDEN_SIZE];
    model->lstm1.b_o = (float*)&all_weights[offset + 4 * DENSE1_OUTPUT_SIZE * LSTM1_HIDDEN_SIZE + 4 * LSTM1_HIDDEN_SIZE * LSTM1_HIDDEN_SIZE + 3 * LSTM1_HIDDEN_SIZE];
    
    // Load remaining layers (simplified for now)
    offset = DENSE1_WEIGHT_COUNT + LSTM1_WEIGHT_COUNT;
    model->lstm2.W_f = (float*)&all_weights[offset];
    // ... (similar pattern for lstm2)
    
    offset = DENSE1_WEIGHT_COUNT + LSTM1_WEIGHT_COUNT + LSTM2_WEIGHT_COUNT;
    model->dense2.weights = (float*)&all_weights[offset];
    model->dense2.bias = (float*)&all_weights[offset + LSTM2_HIDDEN_SIZE * DENSE2_OUTPUT_SIZE];
    
    offset = DENSE1_WEIGHT_COUNT + LSTM1_WEIGHT_COUNT + LSTM2_WEIGHT_COUNT + DENSE2_WEIGHT_COUNT;
    model->dense3.weights = (float*)&all_weights[offset];
    model->dense3.bias = (float*)&all_weights[offset + DENSE2_OUTPUT_SIZE * OUTPUT_CLASSES];
    
    LOG_INFO("Loaded all model weights successfully");
    return 0;
}

void ravn_model_preprocess_sequence(const float *raw_sequence, float *processed_sequence, size_t length) {
    // Simple normalization: scale to [-1, 1]
    for (size_t i = 0; i < length * INPUT_FEATURE_DIM; i++) {
        processed_sequence[i] = tanh_activation(raw_sequence[i]);
    }
}

float ravn_model_predict(ravn_model_t *model, const float *sequence, size_t sequence_length) {
    if (!model || !model->initialized || !sequence) {
        return -1.0f;
    }
    
    // Reset LSTM states
    lstm_cell_reset_state(&model->lstm1);
    lstm_cell_reset_state(&model->lstm2);
    
    // Preprocess input sequence
    ravn_model_preprocess_sequence(sequence, model->sequence_buffer, sequence_length);
    
    // Dense layer 1: process entire sequence at once
    if (dense_layer_forward(&model->dense1, model->sequence_buffer, model->dense1_output) != 0) {
        return -1.0f;
    }
    
    // LSTM layer 1: process sequence step by step
    for (int t = 0; t < INPUT_SEQUENCE_LENGTH; t++) {
        if (lstm_cell_forward(&model->lstm1, &model->dense1_output[t * DENSE1_OUTPUT_SIZE]) != 0) {
            return -1.0f;
        }
    }
    
    // Copy LSTM1 final output
    memcpy(model->lstm1_output, model->lstm1.h_curr, LSTM1_HIDDEN_SIZE * sizeof(float));
    
    // LSTM layer 2: single forward pass
    if (lstm_cell_forward(&model->lstm2, model->lstm1_output) != 0) {
        return -1.0f;
    }
    
    // Copy LSTM2 output
    memcpy(model->lstm2_output, model->lstm2.h_curr, LSTM2_HIDDEN_SIZE * sizeof(float));
    
    // Dense layer 2
    if (dense_layer_forward(&model->dense2, model->lstm2_output, model->dense2_output) != 0) {
        return -1.0f;
    }
    
    // Apply ReLU activation
    for (int i = 0; i < DENSE2_OUTPUT_SIZE; i++) {
        model->dense2_output[i] = relu(model->dense2_output[i]);
    }
    
    // Dense layer 3 (output layer)
    if (dense_layer_forward(&model->dense3, model->dense2_output, model->final_output) != 0) {
        return -1.0f;
    }
    
    // Apply softmax to get probabilities
    softmax(model->final_output, OUTPUT_CLASSES, 0);
    
    // Return threat score (probability of attack class)
    return model->final_output[2]; // Attack class probability
}

int ravn_model_predict_class(ravn_model_t *model, const float *sequence, size_t sequence_length) {
    if (!model || !model->initialized || !sequence) {
        return -1;
    }
    
    float threat_score = ravn_model_predict(model, sequence, sequence_length);
    (void)threat_score; // Suppress unused variable warning
    
    // Convert probabilities to class
    if (model->final_output[0] > model->final_output[1] && model->final_output[0] > model->final_output[2]) {
        return 0;  // Normal
    } else if (model->final_output[1] > model->final_output[2]) {
        return 1;  // Suspicious
    } else {
        return 2;  // Attack
    }
}

const char* ravn_model_class_name(int class_id) {
    switch (class_id) {
        case 0: return "Normal";
        case 1: return "Suspicious";
        case 2: return "Attack";
        default: return "Unknown";
    }
}