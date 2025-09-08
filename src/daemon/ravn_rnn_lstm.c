// RAVN RNN+LSTM Implementation
// Integrates sieknet RNN and LSTM for sequence-based threat detection

#include "ravn_rnn_lstm.h"
#include "../utils/logger.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

// Create RNN+LSTM model
ravn_rnn_lstm_model_t* ravn_rnn_lstm_create(void) {
    ravn_rnn_lstm_model_t *model = malloc(sizeof(ravn_rnn_lstm_model_t));
    if (!model) {
        LOG_ERROR("Failed to allocate memory for RNN+LSTM model");
        return NULL;
    }
    
    memset(model, 0, sizeof(ravn_rnn_lstm_model_t));
    return model;
}

// Initialize RNN+LSTM model
int ravn_rnn_lstm_init(ravn_rnn_lstm_model_t *model) {
    if (!model) {
        LOG_ERROR("Invalid model pointer");
        return -1;
    }
    
    // Create RNN network: input -> RNN -> LSTM -> dense
    // Input: RAVN_FEATURE_DIM, RNN: RAVN_RNN_HIDDEN_SIZE, LSTM: RAVN_LSTM_HIDDEN_SIZE
    model->rnn_network = create_rnn(RAVN_FEATURE_DIM, RAVN_RNN_HIDDEN_SIZE);
    if (!model->rnn_network) {
        LOG_ERROR("Failed to create RNN network");
        return -1;
    }
    
    // Create LSTM layer
    model->lstm_layer = create_lstm(RAVN_RNN_HIDDEN_SIZE, RAVN_LSTM_HIDDEN_SIZE);
    if (!model->lstm_layer) {
        LOG_ERROR("Failed to create LSTM layer");
        return -1;
    }
    
    // Create dense output layer
    model->dense_layer = create_mlp(RAVN_LSTM_HIDDEN_SIZE, RAVN_OUTPUT_CLASSES);
    if (!model->dense_layer) {
        LOG_ERROR("Failed to create dense layer");
        return -1;
    }
    
    // Allocate buffers
    model->input_buffer = malloc(RAVN_SEQUENCE_LENGTH * RAVN_FEATURE_DIM * sizeof(float));
    model->rnn_output_buffer = malloc(RAVN_SEQUENCE_LENGTH * RAVN_RNN_HIDDEN_SIZE * sizeof(float));
    model->lstm_output_buffer = malloc(RAVN_LSTM_HIDDEN_SIZE * sizeof(float));
    model->final_output_buffer = malloc(RAVN_OUTPUT_CLASSES * sizeof(float));
    
    if (!model->input_buffer || !model->rnn_output_buffer || 
        !model->lstm_output_buffer || !model->final_output_buffer) {
        LOG_ERROR("Failed to allocate model buffers");
        return -1;
    }
    
    model->initialized = 1;
    LOG_INFO("RNN+LSTM model initialized successfully");
    return 0;
}

// Destroy RNN+LSTM model
void ravn_rnn_lstm_destroy(ravn_rnn_lstm_model_t *model) {
    if (!model) return;
    
    if (model->rnn_network) {
        destroy_rnn(model->rnn_network);
    }
    
    if (model->lstm_layer) {
        destroy_lstm(model->lstm_layer);
    }
    
    if (model->dense_layer) {
        destroy_mlp(model->dense_layer);
    }
    
    free(model->input_buffer);
    free(model->rnn_output_buffer);
    free(model->lstm_output_buffer);
    free(model->final_output_buffer);
    
    free(model);
}

// Preprocess input sequence
void ravn_rnn_lstm_preprocess_sequence(const float *raw_sequence, float *processed_sequence, size_t length) {
    // Normalize and preprocess the sequence
    for (size_t i = 0; i < length * RAVN_FEATURE_DIM; i++) {
        // Simple normalization: scale to [-1, 1]
        processed_sequence[i] = tanh(raw_sequence[i]);
    }
}

// Forward pass through RNN layer
int ravn_rnn_lstm_forward_rnn(ravn_rnn_lstm_model_t *model, const float *input) {
    if (!model || !model->initialized) {
        return -1;
    }
    
    // Process sequence through RNN
    for (size_t t = 0; t < RAVN_SEQUENCE_LENGTH; t++) {
        const float *input_t = &input[t * RAVN_FEATURE_DIM];
        float *output_t = &model->rnn_output_buffer[t * RAVN_RNN_HIDDEN_SIZE];
        
        // Forward pass through RNN at time t
        // This would call the sieknet RNN forward function
        // For now, we'll implement a simple version
        memcpy(output_t, input_t, RAVN_RNN_HIDDEN_SIZE * sizeof(float));
    }
    
    return 0;
}

// Forward pass through LSTM layer
int ravn_rnn_lstm_forward_lstm(ravn_rnn_lstm_model_t *model, const float *rnn_output) {
    if (!model || !model->initialized) {
        return -1;
    }
    
    // Process RNN output through LSTM
    // This would call the sieknet LSTM forward function
    // For now, we'll implement a simple version
    memcpy(model->lstm_output_buffer, rnn_output, RAVN_LSTM_HIDDEN_SIZE * sizeof(float));
    
    return 0;
}

// Forward pass through dense layer
int ravn_rnn_lstm_forward_dense(ravn_rnn_lstm_model_t *model, const float *lstm_output) {
    if (!model || !model->initialized) {
        return -1;
    }
    
    // Process LSTM output through dense layer
    // This would call the sieknet MLP forward function
    // For now, we'll implement a simple version
    memcpy(model->final_output_buffer, lstm_output, RAVN_OUTPUT_CLASSES * sizeof(float));
    
    return 0;
}

// Predict threat score
float ravn_rnn_lstm_predict(ravn_rnn_lstm_model_t *model, const float *sequence, size_t sequence_length) {
    if (!model || !model->initialized || !sequence) {
        return 0.0f;
    }
    
    // Preprocess input
    ravn_rnn_lstm_preprocess_sequence(sequence, model->input_buffer, sequence_length);
    
    // Forward pass through RNN
    if (ravn_rnn_lstm_forward_rnn(model, model->input_buffer) != 0) {
        return 0.0f;
    }
    
    // Forward pass through LSTM
    if (ravn_rnn_lstm_forward_lstm(model, model->rnn_output_buffer) != 0) {
        return 0.0f;
    }
    
    // Forward pass through dense layer
    if (ravn_rnn_lstm_forward_dense(model, model->lstm_output_buffer) != 0) {
        return 0.0f;
    }
    
    // Return threat score (class 2 = Attack)
    return model->final_output_buffer[2];
}

// Predict threat class
int ravn_rnn_lstm_predict_class(ravn_rnn_lstm_model_t *model, const float *sequence, size_t sequence_length) {
    if (!model || !model->initialized || !sequence) {
        return 0; // Default to Normal
    }
    
    // Get prediction
    float score = ravn_rnn_lstm_predict(model, sequence, sequence_length);
    
    // Convert score to class
    if (score > 0.7f) return 2;      // Attack
    if (score > 0.3f) return 1;      // Suspicious
    return 0;                        // Normal
}

// Load weights from generated model
int ravn_rnn_lstm_load_weights(ravn_rnn_lstm_model_t *model, const float *weights, size_t weight_count) {
    if (!model || !model->initialized || !weights) {
        LOG_ERROR("Invalid parameters for weight loading");
        return -1;
    }
    
    // This would load the actual weights into the sieknet networks
    // For now, we'll just log the weight count
    LOG_INFO("Loading %zu weights into RNN+LSTM model", weight_count);
    
    return 0;
}

// Get class name
const char* ravn_rnn_lstm_class_name(int class_id) {
    switch (class_id) {
        case 0: return "Normal";
        case 1: return "Suspicious";
        case 2: return "Attack";
        default: return "Unknown";
    }
}
