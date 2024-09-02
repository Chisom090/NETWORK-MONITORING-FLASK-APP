# -*- coding: utf-8 -*-
"""
Created on Fri Aug 30 13:44:30 2024

@author: chisom
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.optimizers import Adam
import joblib
import os

# Parameters for synthetic data
num_samples = 1000
num_features = 39  # Number of features

# Generating random data
np.random.seed(42)  # For reproducibility
data = np.random.rand(num_samples, num_features)

# Creating a DataFrame with synthetic data
columns = ['FlowDuration', 'BwdPacketLenMax', 'BwdPacketLenMin', 'BwdPacketLenMean', 'BwdPacketLenStd',
           'FlowIATMean', 'FlowIATStd', 'FlowIATMax', 'FlowIATMin', 'FwdIATTotal', 'FwdIATMean', 
           'FwdIATStd', 'FwdIATMax', 'FwdIATMin', 'BwdIATTotal', 'BwdIATMean', 'BwdIATStd', 
           'BwdIATMax', 'BwdIATMin', 'FwdPSHFlags', 'FwdPackets_s', 'MaxPacketLen', 'PacketLenMean', 
           'PacketLenStd', 'PacketLenVar', 'FINFlagCount', 'SYNFlagCount', 'PSHFlagCount', 
           'ACKFlagCount', 'URGFlagCount', 'AvgPacketSize', 'AvgBwdSegmentSize', 'InitWinBytesFwd', 
           'InitWinBytesBwd', 'ActiveMin', 'IdleMean', 'IdleStd', 'IdleMax', 'IdleMin']
df = pd.DataFrame(data, columns=columns)

# Add a synthetic target column for the classifier
df['Class'] = np.random.randint(0, 2, size=num_samples)

# Save synthetic data to CSV
df.to_csv('synthetic_data.csv', index=False)

# Load synthetic dataset
data = pd.read_csv('synthetic_data.csv')

# Define features and target
features = ['FlowDuration', 'BwdPacketLenMax', 'BwdPacketLenMin', 'BwdPacketLenMean', 'BwdPacketLenStd',
            'FlowIATMean', 'FlowIATStd', 'FlowIATMax', 'FlowIATMin', 'FwdIATTotal', 'FwdIATMean', 
            'FwdIATStd', 'FwdIATMax', 'FwdIATMin', 'BwdIATTotal', 'BwdIATMean', 'BwdIATStd', 
            'BwdIATMax', 'BwdIATMin', 'FwdPSHFlags', 'FwdPackets_s', 'MaxPacketLen', 'PacketLenMean', 
            'PacketLenStd', 'PacketLenVar', 'FINFlagCount', 'SYNFlagCount', 'PSHFlagCount', 
            'ACKFlagCount', 'URGFlagCount', 'AvgPacketSize', 'AvgBwdSegmentSize', 'InitWinBytesFwd', 
            'InitWinBytesBwd', 'ActiveMin', 'IdleMean', 'IdleStd', 'IdleMax', 'IdleMin']

X = data[features]
y = data['Class']

# Preprocess the data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Define the autoencoder model
input_dim = X_train.shape[1]
encoding_dim = 32  # Adjust as needed

# Define the input layer
input_layer = Input(shape=(input_dim,))
encoded = Dense(encoding_dim, activation='relu')(input_layer)
decoded = Dense(input_dim, activation='sigmoid')(encoded)

# Create the autoencoder model
autoencoder = Model(inputs=input_layer, outputs=decoded)

# Compile the model
autoencoder.compile(optimizer=Adam(), loss='mean_squared_error')

# Train the autoencoder model
autoencoder.fit(X_train, X_train, epochs=50, batch_size=256, validation_split=0.2, shuffle=True)

# Save the autoencoder model
os.makedirs('models', exist_ok=True)
autoencoder.save('models/autoencoder_39ft.keras')

# Save the scaler for preprocessing
joblib.dump(scaler, 'models/preprocess_pipeline_AE_39ft.save')

# Define and train the classifier
classifier = RandomForestClassifier(n_estimators=100, random_state=42)
classifier.fit(X_train, y_train)

# Save the classifier model
joblib.dump(classifier, 'models/classifier.pkl')

# Explainer function for the autoencoder
def explain_autoencoder(input_data):
    autoencoder = load_model('models/autoencoder_39ft.keras')
    scaler = joblib.load('models/preprocess_pipeline_AE_39ft.save')
    input_scaled = scaler.transform(input_data)
    reconstructed = autoencoder.predict(input_scaled)
    reconstruction_error = np.mean(np.abs(input_scaled - reconstructed), axis=1)
    return reconstruction_error

# Explainer function for the classifier
def explain_classifier(input_data):
    classifier = joblib.load('models/classifier.pkl')
    scaler = joblib.load('models/preprocess_pipeline_AE_39ft.save')
    input_scaled = scaler.transform(input_data)
    predictions = classifier.predict(input_scaled)
    return predictions

# Example usage:
# Load a sample from your data
sample_data = X_test[:5]

# Get autoencoder reconstruction errors
errors = explain_autoencoder(sample_data)
print("Autoencoder reconstruction errors:", errors)

# Get classifier predictions
predictions = explain_classifier(sample_data)
print("Classifier predictions:", predictions)
