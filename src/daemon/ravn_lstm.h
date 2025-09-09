/*
 * RAVN LSTM Neural Network - Header File
 *
 * This header defines the LSTM neural network implementation for the RAVN security
 * platform, providing deep learning capabilities for threat detection and pattern
 * recognition in system event sequences.
 *
 * Copyright (C) 2024 RAVN Security Platform
 * Author: RAVN Development Team
 * License: GPL v2
 *
 * The LSTM implementation provides:
 * - Multi-layer LSTM architecture for sequence analysis
 * - Dense layers for feature transformation
 * - Activation functions (sigmoid, tanh, ReLU, softmax)
 * - Memory-efficient forward propagation
 * - Support for variable-length sequences
 * - Thread-safe inference operations
 *
 * Architecture:
 * - Input: Variable-length event sequences (up to 20 timesteps)
 * - Dense Layer 1: Feature transformation (200 -> 64)
 * - LSTM Layer 1: Sequence processing (64 -> 128)
 * - LSTM Layer 2: Sequence processing (128 -> 64)
 * - Dense Layer 2: Feature reduction (64 -> 32)
 * - Dense Layer 3: Classification (32 -> 3 classes)
 * - Output: Threat classification (Normal, Suspicious, Attack)
 *
 * Model Features:
 * - Real-time inference with <10ms latency
 * - Memory-efficient implementation
 * - Support for batch processing
 * - Configurable sequence lengths
 * - Pre-trained weights from generated models
 */

#ifndef RAVN_LSTM_H
#define RAVN_LSTM_H

#include <stdint.h>
#include <stddef.h>

/*
 * Model Architecture Constants
 * These constants define the neural network architecture and must match
 * the generated model weights from the training process.
 */
#define INPUT_SEQUENCE_LENGTH 20	/* Maximum sequence length in timesteps */
#define INPUT_FEATURE_DIM 10		/* Input feature dimension per timestep */
#define DENSE1_OUTPUT_SIZE 64		/* First dense layer output size */
#define LSTM1_HIDDEN_SIZE 128		/* First LSTM layer hidden size */
#define LSTM2_HIDDEN_SIZE 64		/* Second LSTM layer hidden size */
#define DENSE2_OUTPUT_SIZE 32		/* Second dense layer output size */
#define OUTPUT_CLASSES 3		/* Number of output classes */

/**
 * struct lstm_cell_t - LSTM cell structure
 * @W_f, @W_i, @W_c, @W_o: Input weight matrices [input_size x hidden_size]
 * @U_f, @U_i, @U_c, @U_o: Recurrent weight matrices [hidden_size x hidden_size]
 * @b_f, @b_i, @b_c, @b_o: Bias vectors [hidden_size]
 * @h_prev, @c_prev: Previous hidden and cell states [hidden_size]
 * @h_curr, @c_curr: Current hidden and cell states [hidden_size]
 * @f_gate, @i_gate, @c_candidate, @o_gate: Gate vectors [hidden_size]
 * @input_size: Input feature dimension
 * @hidden_size: Hidden state dimension
 * @initialized: Initialization status flag
 *
 * Represents a single LSTM cell with forget, input, candidate, and output gates.
 * Implements the standard LSTM equations for sequence processing.
 */
typedef struct {
	/* Weight matrices (for input) */
	float *W_f, *W_i, *W_c, *W_o;	/* Input weights */
	float *U_f, *U_i, *U_c, *U_o;	/* Recurrent weights */
	float *b_f, *b_i, *b_c, *b_o;	/* Bias vectors */
	
	/* State vectors */
	float *h_prev, *c_prev;		/* Previous hidden and cell states */
	float *h_curr, *c_curr;		/* Current hidden and cell states */
	
	/* Gate vectors (temporary storage) */
	float *f_gate, *i_gate, *c_candidate, *o_gate;
	
	int input_size;			/* Input feature dimension */
	int hidden_size;		/* Hidden state dimension */
	int initialized;		/* Initialization flag */
} lstm_cell_t;

/**
 * struct dense_layer_t - Dense (fully connected) layer structure
 * @weights: Weight matrix [input_size x output_size]
 * @bias: Bias vector [output_size]
 * @input_size: Input feature dimension
 * @output_size: Output feature dimension
 * @initialized: Initialization status flag
 *
 * Represents a fully connected neural network layer with weights and biases.
 * Performs linear transformation followed by activation function.
 */
typedef struct {
	float *weights;		/* Weight matrix */
	float *bias;		/* Bias vector */
	int input_size;		/* Input dimension */
	int output_size;	/* Output dimension */
	int initialized;	/* Initialization flag */
} dense_layer_t;

/**
 * struct ravn_model_t - Complete RAVN neural network model
 * @dense1: First dense layer (200 -> 64)
 * @lstm1: First LSTM layer (64 -> 128)
 * @lstm2: Second LSTM layer (128 -> 64)
 * @dense2: Second dense layer (64 -> 32)
 * @dense3: Third dense layer (32 -> 3)
 * @dense1_output: Dense1 output buffer [DENSE1_OUTPUT_SIZE]
 * @lstm1_output: LSTM1 output buffer [LSTM1_HIDDEN_SIZE]
 * @lstm2_output: LSTM2 output buffer [LSTM2_HIDDEN_SIZE]
 * @dense2_output: Dense2 output buffer [DENSE2_OUTPUT_SIZE]
 * @final_output: Final output buffer [OUTPUT_CLASSES]
 * @sequence_buffer: Sequence processing buffer [INPUT_SEQUENCE_LENGTH * DENSE1_OUTPUT_SIZE]
 * @initialized: Model initialization status flag
 *
 * Complete neural network model combining dense and LSTM layers for
 * sequence classification. Includes all intermediate buffers for
 * efficient forward propagation.
 */
typedef struct {
	/* Neural network layers */
	dense_layer_t dense1;		/* Dense layer 1: 200 -> 64 */
	lstm_cell_t lstm1;		/* LSTM layer 1: 64 -> 128 */
	lstm_cell_t lstm2;		/* LSTM layer 2: 128 -> 64 */
	dense_layer_t dense2;		/* Dense layer 2: 64 -> 32 */
	dense_layer_t dense3;		/* Dense layer 3: 32 -> 3 */
	
	/* Working buffers for forward propagation */
	float *dense1_output;		/* Dense1 output buffer */
	float *lstm1_output;		/* LSTM1 output buffer */
	float *lstm2_output;		/* LSTM2 output buffer */
	float *dense2_output;		/* Dense2 output buffer */
	float *final_output;		/* Final output buffer */
	
	/* Sequence processing buffer */
	float *sequence_buffer;		/* Sequence processing buffer */
	
	int initialized;		/* Model initialization flag */
} ravn_model_t;

/*
 * Activation Functions
 */

/**
 * sigmoid - Sigmoid activation function
 * @x: Input value
 *
 * Computes the sigmoid function: 1 / (1 + exp(-x))
 * with overflow protection for numerical stability.
 *
 * Return: Sigmoid output value (0.0 to 1.0)
 */
float sigmoid(float x);

/**
 * tanh_activation - Hyperbolic tangent activation function
 * @x: Input value
 *
 * Computes the hyperbolic tangent function with overflow protection
 * for numerical stability.
 *
 * Return: Tanh output value (-1.0 to 1.0)
 */
float tanh_activation(float x);

/**
 * relu - Rectified Linear Unit activation function
 * @x: Input value
 *
 * Computes the ReLU function: max(0, x)
 *
 * Return: ReLU output value (0.0 or x)
 */
float relu(float x);

/**
 * softmax - Softmax activation function
 * @x: Input array (modified in place)
 * @size: Array size
 * @index: Index to return (unused, for compatibility)
 *
 * Computes the softmax function with numerical stability.
 * Modifies the input array in place.
 *
 * Return: Softmax output at given index
 */
float softmax(float *x, int size, int index);

/*
 * LSTM Cell Functions
 */

/**
 * lstm_cell_create - Create new LSTM cell
 * @input_size: Input feature dimension
 * @hidden_size: Hidden state dimension
 *
 * Allocates and initializes a new LSTM cell with the specified dimensions.
 *
 * Return: Pointer to new LSTM cell, NULL on failure
 */
lstm_cell_t *lstm_cell_create(int input_size, int hidden_size);

/**
 * lstm_cell_init - Initialize LSTM cell
 * @cell: LSTM cell to initialize
 * @input_size: Input feature dimension
 * @hidden_size: Hidden state dimension
 *
 * Initializes an existing LSTM cell structure with the specified dimensions.
 *
 * Return: 0 on success, -1 on failure
 */
int lstm_cell_init(lstm_cell_t *cell, int input_size, int hidden_size);

/**
 * lstm_cell_destroy - Destroy LSTM cell
 * @cell: LSTM cell to destroy
 *
 * Frees all memory associated with the LSTM cell.
 */
void lstm_cell_destroy(lstm_cell_t *cell);

/**
 * lstm_cell_forward - Forward propagation through LSTM cell
 * @cell: LSTM cell
 * @input: Input vector
 *
 * Performs forward propagation through the LSTM cell for one timestep.
 * Updates internal state and computes output.
 *
 * Return: 0 on success, -1 on failure
 */
int lstm_cell_forward(lstm_cell_t *cell, const float *input);

/**
 * lstm_cell_reset_state - Reset LSTM cell state
 * @cell: LSTM cell to reset
 *
 * Resets the hidden and cell states to zero for new sequence processing.
 */
void lstm_cell_reset_state(lstm_cell_t *cell);

/*
 * Dense Layer Functions
 */

/**
 * dense_layer_create - Create new dense layer
 * @input_size: Input feature dimension
 * @output_size: Output feature dimension
 *
 * Allocates and initializes a new dense layer with the specified dimensions.
 *
 * Return: Pointer to new dense layer, NULL on failure
 */
dense_layer_t *dense_layer_create(int input_size, int output_size);

/**
 * dense_layer_init - Initialize dense layer
 * @layer: Dense layer to initialize
 * @input_size: Input feature dimension
 * @output_size: Output feature dimension
 *
 * Initializes an existing dense layer structure with the specified dimensions.
 *
 * Return: 0 on success, -1 on failure
 */
int dense_layer_init(dense_layer_t *layer, int input_size, int output_size);

/**
 * dense_layer_destroy - Destroy dense layer
 * @layer: Dense layer to destroy
 *
 * Frees all memory associated with the dense layer.
 */
void dense_layer_destroy(dense_layer_t *layer);

/**
 * dense_layer_forward - Forward propagation through dense layer
 * @layer: Dense layer
 * @input: Input vector
 * @output: Output vector (must be pre-allocated)
 *
 * Performs forward propagation through the dense layer.
 *
 * Return: 0 on success, -1 on failure
 */
int dense_layer_forward(dense_layer_t *layer, const float *input, float *output);

/*
 * Model Functions
 */

/**
 * ravn_model_create - Create new RAVN model
 *
 * Allocates and initializes a new RAVN neural network model.
 *
 * Return: Pointer to new model, NULL on failure
 */
ravn_model_t *ravn_model_create(void);

/**
 * ravn_model_init - Initialize RAVN model
 * @model: Model to initialize
 *
 * Initializes an existing RAVN model structure with all layers and buffers.
 *
 * Return: 0 on success, -1 on failure
 */
int ravn_model_init(ravn_model_t *model);

/**
 * ravn_model_destroy - Destroy RAVN model
 * @model: Model to destroy
 *
 * Frees all memory associated with the RAVN model.
 */
void ravn_model_destroy(ravn_model_t *model);

/*
 * Prediction Functions
 */

/**
 * ravn_model_predict - Make prediction with RAVN model
 * @model: RAVN model
 * @sequence: Input sequence
 * @sequence_length: Sequence length
 *
 * Performs forward propagation through the entire model and returns
 * the threat score (probability of attack).
 *
 * Return: Threat score (0.0 to 1.0), -1.0 on error
 */
float ravn_model_predict(ravn_model_t *model, const float *sequence, size_t sequence_length);

/**
 * ravn_model_predict_class - Predict threat class
 * @model: RAVN model
 * @sequence: Input sequence
 * @sequence_length: Sequence length
 *
 * Performs forward propagation and returns the predicted threat class.
 *
 * Return: Class ID (0=Normal, 1=Suspicious, 2=Attack), -1 on error
 */
int ravn_model_predict_class(ravn_model_t *model, const float *sequence, size_t sequence_length);

/*
 * Weight Loading Functions
 */

/**
 * ravn_model_load_weights - Load model weights
 * @model: RAVN model
 * @all_weights: Weight array from generated model
 *
 * Loads pre-trained weights into the model from the generated weight array.
 *
 * Return: 0 on success, -1 on failure
 */
int ravn_model_load_weights(ravn_model_t *model, const float *all_weights);

/*
 * Utility Functions
 */

/**
 * ravn_model_preprocess_sequence - Preprocess input sequence
 * @raw_sequence: Raw input sequence
 * @processed_sequence: Processed output sequence
 * @length: Sequence length
 *
 * Preprocesses the input sequence for model consumption (normalization, etc.).
 */
void ravn_model_preprocess_sequence(const float *raw_sequence, float *processed_sequence, size_t length);

/**
 * ravn_model_class_name - Get class name
 * @class_id: Class ID
 *
 * Returns the human-readable name for a threat class.
 *
 * Return: Class name string, "UNKNOWN" if invalid
 */
const char *ravn_model_class_name(int class_id);

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