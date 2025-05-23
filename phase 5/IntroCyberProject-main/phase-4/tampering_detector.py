import numpy as np
import pandas as pd
import pickle
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os
from integrity_checker import IntegrityChecker

class TamperingDetector:
    """AI-based model for detecting tampering in encrypted data."""
    
    def __init__(self, model_path=None):
        """Initialize the tampering detector model."""
        if model_path and os.path.exists(model_path):
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(model_path.replace('model', 'scaler'))
        else:
            self.model = IsolationForest(contamination=0.05, random_state=42)
            self.scaler = StandardScaler()
    
    def extract_features(self, encrypted_data):
        """Extract statistical features from encrypted data for anomaly detection."""
        if isinstance(encrypted_data, str):
            # If it's a filepath, read the file
            with open(encrypted_data, 'rb') as f:
                data = f.read()
        else:
            data = encrypted_data
            
        # Convert bytes to array of integers
        byte_array = np.frombuffer(data, dtype=np.uint8)
        
        # Extract statistical features
        features = {
            'mean': byte_array.mean(),
            'std': byte_array.std(),
            'min': byte_array.min(),
            'max': byte_array.max(),
            'median': np.median(byte_array),
            'entropy': self._calculate_entropy(byte_array),
            'byte_distribution_skew': self._calculate_distribution_skew(byte_array),
            'byte_distribution_kurtosis': self._calculate_distribution_kurtosis(byte_array),
            'chunks_hash_variance': self._calculate_hash_variance(data)
        }
        
        return np.array(list(features.values())).reshape(1, -1)
    
    def _calculate_entropy(self, byte_array):
        """Calculate Shannon entropy of the data."""
        _, counts = np.unique(byte_array, return_counts=True)
        probs = counts / len(byte_array)
        return -np.sum(probs * np.log2(probs))
    
    def _calculate_distribution_skew(self, byte_array):
        """Calculate the skewness of the byte distribution."""
        mean = byte_array.mean()
        std = byte_array.std()
        if std == 0:
            return 0
        skew = np.sum(((byte_array - mean) / std) ** 3) / len(byte_array)
        return skew
    
    def _calculate_distribution_kurtosis(self, byte_array):
        """Calculate the kurtosis of the byte distribution."""
        mean = byte_array.mean()
        std = byte_array.std()
        if std == 0:
            return 0
        kurt = np.sum(((byte_array - mean) / std) ** 4) / len(byte_array) - 3
        return kurt
    
    def _calculate_hash_variance(self, data):
        """Calculate variance in hash values of data chunks."""
        chunk_size = 1024  # 1KB chunks
        hashes = []
        
        # Skip if data is too small
        if len(data) < chunk_size * 5:
            return 0
            
        for i in range(0, len(data) - chunk_size, chunk_size):
            chunk = data[i:i+chunk_size]
            hash_hex = IntegrityChecker.calculate_hash(chunk, 'sha256')
            # Convert hex to int for numerical analysis
            hash_int = int(hash_hex, 16) % 10**10  # Use modulo to keep the number manageable
            hashes.append(hash_int)
            
        return np.var(hashes) if hashes else 0
    
    def train(self, data_paths, labels=None):
        """Train the model on a list of file paths to encrypted data.
        
        Args:
            data_paths: List of file paths to encrypted data
            labels: Optional binary labels (0 for normal, 1 for tampered)
        """
        features = []
        for path in data_paths:
            features.append(self.extract_features(path)[0])
        
        X = np.array(features)
        X_scaled = self.scaler.fit_transform(X)
        
        if labels is None:
            # Unsupervised learning
            self.model.fit(X_scaled)
        else:
            # Convert labels for IsolationForest format (-1 for outliers, 1 for inliers)
            y = np.array([-1 if l == 1 else 1 for l in labels])
            self.model.fit(X_scaled, y)
    
    def predict(self, encrypted_data):
        """Predict if encrypted data has been tampered with.
        
        Returns:
            True if tampered, False otherwise
        """
        features = self.extract_features(encrypted_data)
        features_scaled = self.scaler.transform(features)
        prediction = self.model.predict(features_scaled)
        
        # IsolationForest: -1 for anomalies (tampered), 1 for normal
        return True if prediction[0] == -1 else False
    
    def save_model(self, model_path):
        """Save the trained model."""
        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, model_path.replace('model', 'scaler'))

def generate_tampered_data(original_data, tampering_level=0.05):
    """Generate tampered version of data for training purposes.
    
    Args:
        original_data: Original encrypted data (bytes)
        tampering_level: Percentage of bytes to modify (0.0-1.0)
    
    Returns:
        Tampered data
    """
    tampered_data = bytearray(original_data)
    n_bytes = len(tampered_data)
    n_bytes_to_tamper = int(n_bytes * tampering_level)
    
    # Randomly select bytes to tamper
    indices = np.random.choice(n_bytes, n_bytes_to_tamper, replace=False)
    
    # Modify selected bytes
    for idx in indices:
        # Change byte value by a random amount
        tampered_data[idx] = (tampered_data[idx] + np.random.randint(1, 256)) % 256
        
    return bytes(tampered_data)
