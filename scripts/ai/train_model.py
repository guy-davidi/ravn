#!/usr/bin/env python3
"""
RAVN Model Training Script
Trains a deep learning model for threat detection
"""

import numpy as np
import json
import pickle
import argparse
import os
from typing import List, Dict, Any, Tuple
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM, Dropout, Embedding, Conv1D, MaxPooling1D, Flatten
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
import matplotlib.pyplot as plt

class RAVNModelTrainer:
    def __init__(self, sequence_length: int = 20, feature_dim: int = 10):
        """Initialize the model trainer"""
        self.sequence_length = sequence_length
        self.feature_dim = feature_dim
        self.scaler = StandardScaler()
        self.model = None
        
    def extract_features(self, sequence: List[Dict[str, Any]]) -> np.ndarray:
        """Extract features from a sequence of events"""
        features = []
        
        # Pad or truncate sequence to fixed length
        if len(sequence) > self.sequence_length:
            sequence = sequence[:self.sequence_length]
        else:
            # Pad with zeros
            while len(sequence) < self.sequence_length:
                sequence.append({
                    'event_type': 0,
                    'pid': 0,
                    'tid': 0,
                    'timestamp': 0
                })
        
        for event in sequence:
            # Extract numerical features
            event_features = [
                event.get('event_type', 0),
                event.get('pid', 0) / 10000.0,  # Normalize PID
                event.get('tid', 0) / 10000.0,  # Normalize TID
                event.get('timestamp', 0) / 1e9,  # Convert to seconds
            ]
            
            # Add more features based on event data
            try:
                data = json.loads(event.get('data', '{}'))
                if 'syscall' in data:
                    # Map syscall name to number
                    syscall_map = {
                        'execve': 59, 'open': 2, 'read': 0, 'write': 1,
                        'mmap': 9, 'mprotect': 10, 'close': 3, 'unlink': 87,
                        'rename': 82, 'ptrace': 101, 'setuid': 105, 'chmod': 90,
                        'chown': 92, 'mount': 165, 'umount': 166
                    }
                    event_features.append(syscall_map.get(data['syscall'], 0))
                else:
                    event_features.append(0)
                    
                # Add return value
                event_features.append(data.get('ret', 0))
                
                # Add filename length (as a feature)
                filename = data.get('filename', '')
                event_features.append(len(filename) / 100.0)  # Normalize
                
                # Add more features
                event_features.extend([0, 0, 0])  # Padding to reach feature_dim
                
            except (json.JSONDecodeError, KeyError):
                event_features.extend([0] * 6)  # Default values
            
            # Ensure we have exactly feature_dim features
            while len(event_features) < self.feature_dim:
                event_features.append(0)
            event_features = event_features[:self.feature_dim]
            
            features.append(event_features)
        
        return np.array(features)
    
    def prepare_data(self, dataset: Dict[str, List[Dict[str, Any]]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data from dataset"""
        X = []
        y = []
        
        # Process normal sequences
        for item in dataset['normal_sequences']:
            features = self.extract_features(item['sequence'])
            X.append(features)
            y.append(0)  # Normal
        
        # Process suspicious sequences
        for item in dataset['suspicious_sequences']:
            features = self.extract_features(item['sequence'])
            X.append(features)
            y.append(1)  # Suspicious
        
        # Process attack sequences
        for item in dataset['attack_sequences']:
            features = self.extract_features(item['sequence'])
            X.append(features)
            y.append(2)  # Attack
        
        X = np.array(X)
        y = np.array(y)
        
        print(f"Data shape: X={X.shape}, y={y.shape}")
        print(f"Class distribution: {np.bincount(y)}")
        
        return X, y
    
    def build_model(self, input_shape: Tuple[int, int]) -> tf.keras.Model:
        """Build the neural network model"""
        model = Sequential([
            # Input layer
            Dense(64, activation='relu', input_shape=input_shape),
            Dropout(0.2),
            
            # LSTM layer for sequence processing
            LSTM(128, return_sequences=True),
            Dropout(0.2),
            
            # Another LSTM layer
            LSTM(64, return_sequences=False),
            Dropout(0.2),
            
            # Dense layers
            Dense(32, activation='relu'),
            Dropout(0.2),
            
            # Output layer (3 classes: normal, suspicious, attack)
            Dense(3, activation='softmax')
        ])
        
        # Compile model
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def train(self, X: np.ndarray, y: np.ndarray, epochs: int = 100, batch_size: int = 32) -> tf.keras.Model:
        """Train the model"""
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training set: {X_train.shape[0]} samples")
        print(f"Test set: {X_test.shape[0]} samples")
        
        # Build model
        self.model = self.build_model((X_train.shape[1], X_train.shape[2]))
        
        # Print model summary
        self.model.summary()
        
        # Callbacks
        callbacks = [
            EarlyStopping(patience=10, restore_best_weights=True),
            ModelCheckpoint('../../artifacts/best_model.h5', save_best_only=True)
        ]
        
        # Train model
        history = self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_data=(X_test, y_test),
            callbacks=callbacks,
            verbose=1
        )
        
        # Evaluate model
        test_loss, test_accuracy = self.model.evaluate(X_test, y_test, verbose=0)
        print(f"Test accuracy: {test_accuracy:.4f}")
        
        # Predictions
        y_pred = self.model.predict(X_test)
        y_pred_classes = np.argmax(y_pred, axis=1)
        
        # Classification report
        class_names = ['Normal', 'Suspicious', 'Attack']
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred_classes, target_names=class_names))
        
        # Confusion matrix
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred_classes))
        
        # Plot training history
        self.plot_training_history(history)
        
        return self.model
    
    def plot_training_history(self, history: tf.keras.callbacks.History):
        """Plot training history"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
        
        # Plot accuracy
        ax1.plot(history.history['accuracy'], label='Training Accuracy')
        ax1.plot(history.history['val_accuracy'], label='Validation Accuracy')
        ax1.set_title('Model Accuracy')
        ax1.set_xlabel('Epoch')
        ax1.set_ylabel('Accuracy')
        ax1.legend()
        
        # Plot loss
        ax2.plot(history.history['loss'], label='Training Loss')
        ax2.plot(history.history['val_loss'], label='Validation Loss')
        ax2.set_title('Model Loss')
        ax2.set_xlabel('Epoch')
        ax2.set_ylabel('Loss')
        ax2.legend()
        
        plt.tight_layout()
        plt.savefig('../../artifacts/training_history.png')
        plt.show()
    
    def save_model(self, model_path: str):
        """Save the trained model"""
        if self.model is None:
            raise ValueError("No model to save. Train the model first.")
        
        # Save TensorFlow model
        self.model.save(model_path)
        
        # Save model metadata
        metadata = {
            'sequence_length': self.sequence_length,
            'feature_dim': self.feature_dim,
            'input_shape': self.model.input_shape,
            'output_shape': self.model.output_shape,
            'class_names': ['Normal', 'Suspicious', 'Attack']
        }
        
        with open(f"{model_path}_metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"Model saved to {model_path}")
        print(f"Metadata saved to {model_path}_metadata.json")
    
    def export_for_c(self, model_path: str):
        """Export model weights for C inference"""
        if self.model is None:
            raise ValueError("No model to export. Train the model first.")
        
        # Get model weights
        weights = self.model.get_weights()
        
        # Flatten weights for C
        flattened_weights = []
        for layer_weights in weights:
            flattened_weights.extend(layer_weights.flatten())
        
        # Save as binary file
        weights_array = np.array(flattened_weights, dtype=np.float32)
        weights_array.tofile(f"{model_path}_weights.bin")
        
        # Save weight info
        weight_info = {
            'num_weights': len(flattened_weights),
            'weight_shapes': [w.shape for w in weights],
            'weight_sizes': [w.size for w in weights]
        }
        
        with open(f"{model_path}_weights_info.json", 'w') as f:
            json.dump(weight_info, f, indent=2)
        
        print(f"Model weights exported to {model_path}_weights.bin")
        print(f"Weight info saved to {model_path}_weights_info.json")

def main():
    parser = argparse.ArgumentParser(description='Train RAVN AI model')
    parser.add_argument('--data', '-d', default='training_data.json', help='Training data file')
    parser.add_argument('--output', '-o', default='ravn_model', help='Output model path')
    parser.add_argument('--epochs', type=int, default=100, help='Number of training epochs')
    parser.add_argument('--batch-size', type=int, default=32, help='Batch size')
    parser.add_argument('--sequence-length', type=int, default=20, help='Sequence length')
    parser.add_argument('--feature-dim', type=int, default=10, help='Feature dimension')
    
    args = parser.parse_args()
    
    # Load training data
    print(f"Loading training data from {args.data}...")
    with open(args.data, 'r') as f:
        dataset = json.load(f)
    
    # Initialize trainer
    trainer = RAVNModelTrainer(
        sequence_length=args.sequence_length,
        feature_dim=args.feature_dim
    )
    
    # Prepare data
    print("Preparing training data...")
    X, y = trainer.prepare_data(dataset)
    
    # Train model
    print("Training model...")
    model = trainer.train(X, y, epochs=args.epochs, batch_size=args.batch_size)
    
    # Save model
    print("Saving model...")
    trainer.save_model(args.output)
    
    # Export for C
    print("Exporting model for C inference...")
    trainer.export_for_c(args.output)
    
    print("Training completed!")

if __name__ == '__main__':
    main()
