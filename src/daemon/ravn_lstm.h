// RAVN LSTM Neural Network Implementation
// Full implementation with proper LSTM cells and dense layers

#ifndef RAVN_LSTM_H
#define RAVN_LSTM_H

#include <stdint.h>
#include <stddef.h>

// Model architecture constants (must match generated weights)
#define INPUT_SEQUENCE_LENGTH 20
#define INPUT_FEATURE_DIM 10
#define DENSE1_OUTPUT_SIZE 64
#define LSTM1_HIDDEN_SIZE 128
#define LSTM2_HIDDEN_SIZE 64
#define DENSE2_OUTPUT_SIZE 32
#define OUTPUT_CLASSES 3

// LSTM cell structure
typedef struct {
    // Weight matrices (for input)
    float *W_f, *W_i, *W_c, *W_o;  // Input weights [input_size x hidden_size]
    float *U_f, *U_i, *U_c, *U_o;  // Recurrent weights [hidden_size x hidden_size]
    float *b_f, *b_i, *b_c, *b_o;  // Bias vectors [hidden_size]
    
    // State vectors
    float *h_prev, *c_prev;        // Previous hidden and cell states
    float *h_curr, *c_curr;        // Current hidden and cell states
    
    // Gate vectors (temporary storage)
    float *f_gate, *i_gate, *c_candidate, *o_gate;
    
    int input_size;
    int hidden_size;
    int initialized;
} lstm_cell_t;

// Dense layer structure
typedef struct {
    float *weights;     // Weight matrix [input_size x output_size]
    float *bias;        // Bias vector [output_size]
    int input_size;
    int output_size;
    int initialized;
} dense_layer_t;

// Complete RAVN model structure
typedef struct {
    // Dense layer 1: input(200) -> output(64)
    dense_layer_t dense1;
    
    // LSTM layer 1: input(64) -> output(128)
    lstm_cell_t lstm1;
    
    // LSTM layer 2: input(128) -> output(64)
    lstm_cell_t lstm2;
    
    // Dense layer 2: input(64) -> output(32)
    dense_layer_t dense2;
    
    // Dense layer 3: input(32) -> output(3)
    dense_layer_t dense3;
    
    // Working buffers
    float *dense1_output;      // [DENSE1_OUTPUT_SIZE]
    float *lstm1_output;       // [LSTM1_HIDDEN_SIZE]
    float *lstm2_output;       // [LSTM2_HIDDEN_SIZE]
    float *dense2_output;      // [DENSE2_OUTPUT_SIZE]
    float *final_output;       // [OUTPUT_CLASSES]
    
    // Sequence processing buffer
    float *sequence_buffer;    // [INPUT_SEQUENCE_LENGTH * DENSE1_OUTPUT_SIZE]
    
    int initialized;
} ravn_model_t;

// Activation functions
float sigmoid(float x);
float tanh_activation(float x);
float relu(float x);
float softmax(float *x, int size, int index);

// LSTM cell functions
lstm_cell_t* lstm_cell_create(int input_size, int hidden_size);
int lstm_cell_init(lstm_cell_t *cell, int input_size, int hidden_size);
void lstm_cell_destroy(lstm_cell_t *cell);
int lstm_cell_forward(lstm_cell_t *cell, const float *input);
void lstm_cell_reset_state(lstm_cell_t *cell);

// Dense layer functions
dense_layer_t* dense_layer_create(int input_size, int output_size);
int dense_layer_init(dense_layer_t *layer, int input_size, int output_size);
void dense_layer_destroy(dense_layer_t *layer);
int dense_layer_forward(dense_layer_t *layer, const float *input, float *output);

// Model functions
ravn_model_t* ravn_model_create(void);
int ravn_model_init(ravn_model_t *model);
void ravn_model_destroy(ravn_model_t *model);

// Prediction functions
float ravn_model_predict(ravn_model_t *model, const float *sequence, size_t sequence_length);
int ravn_model_predict_class(ravn_model_t *model, const float *sequence, size_t sequence_length);

// Weight loading functions
int ravn_model_load_weights(ravn_model_t *model, const float *all_weights);

// Utility functions
void ravn_model_preprocess_sequence(const float *raw_sequence, float *processed_sequence, size_t length);
const char* ravn_model_class_name(int class_id);

// Legacy compatibility (for existing code)
typedef ravn_model_t ravn_rnn_lstm_model_t;
#define ravn_rnn_lstm_create ravn_model_create
#define ravn_rnn_lstm_init ravn_model_init
#define ravn_rnn_lstm_destroy ravn_model_destroy
#define ravn_rnn_lstm_predict ravn_model_predict
#define ravn_rnn_lstm_predict_class ravn_model_predict_class
#define ravn_rnn_lstm_load_weights ravn_model_load_weights
#define ravn_rnn_lstm_class_name ravn_model_class_name

#endif // RAVN_LSTM_H