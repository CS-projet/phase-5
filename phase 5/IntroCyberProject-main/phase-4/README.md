# Phase 4: AI-Assisted Encrypted Data Integrity & Authentication

This phase implements AI-based integrity checks for encrypted data, focusing on detecting tampering, corruption, or unauthorized modifications.

## Components

1. **integrity_checker.py**
   - Base classes for integrity verification using hashing and digital signatures
   - Supports SHA-256, SHA-512, and SHA3-256 hash algorithms
   - Implements HMAC functionality for authentication
   - Digital signature support using RSA

2. **tampering_detector.py**
   - AI-based model for detecting tampering in encrypted data
   - Uses an Isolation Forest algorithm to detect anomalies
   - Extracts statistical features from encrypted data for analysis
   - Includes tools to generate tampered data for training purposes

3. **train_tampering_detector.py**
   - Script to create training datasets and train the AI model
   - Generates normal and tampered encrypted samples
   - Trains and evaluates the tampering detection model

4. **file_integrity_app.py**
   - Complete application for file integrity verification
   - Supports multiple integrity verification methods:
     - Hash verification
     - HMAC authentication
     - Digital signature verification
     - AI-based tampering detection
   - Command-line interface for easy use

## Usage

### Training the AI Model

```bash
python train_tampering_detector.py --dataset_dir training_data --samples 200 --model_output tampering_model.joblib
```

### Protecting Files

```bash
# Basic hash protection
python file_integrity_app.py protect myfile.txt

# With HMAC
python file_integrity_app.py protect myfile.txt --key mysecretkey

# With digital signature
python file_integrity_app.py protect myfile.txt --sign key.private
```

### Verifying Files

```bash
# Basic hash verification
python file_integrity_app.py verify myfile.txt

# With HMAC verification
python file_integrity_app.py verify myfile.txt --key mysecretkey

# With digital signature verification
python file_integrity_app.py verify myfile.txt --pubkey key.public

# With AI tampering detection
python file_integrity_app.py verify myfile.txt --model tampering_model.joblib
```

### Generating Key Pairs

```bash
python file_integrity_app.py generate-keys --prefix mykeys
```

## Dependencies

- numpy
- pandas
- scikit-learn
- cryptography
- joblib
