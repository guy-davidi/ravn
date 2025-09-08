// RAVN RNN+LSTM Wrapper
// Integrates sieknet RNN and LSTM for sequence-based threat detection

#ifndef RAVN_RNN_LSTM_H
#define RAVN_RNN_LSTM_H

#include <stdint.h>
#include <stddef.h>
#include "sieknet/include/rnn.h"
#include "sieknet/include/lstm.h"
#include "sieknet/include/mlp.h"

// RAVN RNN+LSTM Configuration
#define RAVN_SEQUENCE_LENGTH 20    // 20 events per sequence
#define RAVN_FEATURE_DIM 10        // 10 features per event
#define RAVN_RNN_HIDDEN_SIZE 64    // RNN hidden units
#define RAVN_LSTM_HIDDEN_SIZE 128  // LSTM hidden units
#define RAVN_OUTPUT_CLASSES 3      // Normal, Suspicious, Attack

// RAVN RNN+LSTM Model Structure
typedef struct {
    rnn *rnn_network;              // sieknet RNN network (first layer)
    lstm_layer_t *lstm_layer;      // sieknet LSTM layer (second layer)
    mlp_layer_t *dense_layer;      // Output dense layer
    float *input_buffer;           // Input sequence buffer
    float *rnn_output_buffer;      // RNN output buffer
    float *lstm_output_buffer;     // LSTM output buffer
    float *final_output_buffer;    // Final predictions
    int initialized;               // Initialization flag
} ravn_rnn_lstm_model_t;

// Function prototypes
ravn_rnn_lstm_model_t* ravn_rnn_lstm_create(void);
int ravn_rnn_lstm_init(ravn_rnn_lstm_model_t *model);
void ravn_rnn_lstm_destroy(ravn_rnn_lstm_model_t *model);

// Prediction functions
float ravn_rnn_lstm_predict(ravn_rnn_lstm_model_t *model, const float *sequence, size_t sequence_length);
int ravn_rnn_lstm_predict_class(ravn_rnn_lstm_model_t *model, const float *sequence, size_t sequence_length);

// Model loading (from generated weights)
int ravn_rnn_lstm_load_weights(ravn_rnn_lstm_model_t *model, const float *weights, size_t weight_count);

// Utility functions
void ravn_rnn_lstm_preprocess_sequence(const float *raw_sequence, float *processed_sequence, size_t length);
const char* ravn_rnn_lstm_class_name(int class_id);

// Layer-specific functions
int ravn_rnn_lstm_forward_rnn(ravn_rnn_lstm_model_t *model, const float *input);
int ravn_rnn_lstm_forward_lstm(ravn_rnn_lstm_model_t *model, const float *rnn_output);
int ravn_rnn_lstm_forward_dense(ravn_rnn_lstm_model_t *model, const float *lstm_output);

#endif // RAVN_RNN_LSTM_H
