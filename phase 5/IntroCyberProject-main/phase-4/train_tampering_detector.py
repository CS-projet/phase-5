import os
import numpy as np
from tampering_detector import TamperingDetector, generate_tampered_data
import argparse
from cryptography.fernet import Fernet

def encrypt_sample_file(input_file, output_file):
    """Encrypt a file using Fernet symmetric encryption for testing."""
    key = Fernet.generate_key()
    f = Fernet(key)
    
    with open(input_file, 'rb') as file:
        file_data = file.read()
    
    encrypted_data = f.encrypt(file_data)
    
    with open(output_file, 'wb') as file:
        file.write(encrypted_data)
    
    return key

def create_training_dataset(base_dir, num_samples=100):
    """Create a training dataset of encrypted and tampered files."""
    # Create directories
    os.makedirs(os.path.join(base_dir, 'normal'), exist_ok=True)
    os.makedirs(os.path.join(base_dir, 'tampered'), exist_ok=True)
    
    # Generate sample text for encryption
    sample_texts = []
    for i in range(num_samples):
        # Generate different sizes of text data
        size = np.random.randint(1000, 10000)
        text = ''.join(np.random.choice(list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'), size))
        sample_texts.append(text.encode())
    
    # Create encrypted samples
    normal_files = []
    tampered_files = []
    
    for i, text in enumerate(sample_texts):
        # Create normal encrypted file
        normal_path = os.path.join(base_dir, 'normal', f'sample_{i}.enc')
        with open(normal_path, 'wb') as f:
            key = Fernet.generate_key()
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(text)
            f.write(encrypted_data)
        normal_files.append(normal_path)
        
        # Create tampered version with varying tampering levels
        tampered_path = os.path.join(base_dir, 'tampered', f'sample_{i}.enc')
        tampering_level = np.random.uniform(0.01, 0.1)  # Vary tampering levels
        tampered_data = generate_tampered_data(encrypted_data, tampering_level)
        with open(tampered_path, 'wb') as f:
            f.write(tampered_data)
        tampered_files.append(tampered_path)
    
    return normal_files, tampered_files

def main():
    parser = argparse.ArgumentParser(description='Train AI tampering detector')
    parser.add_argument('--dataset_dir', default='training_data', help='Directory to store training dataset')
    parser.add_argument('--samples', type=int, default=100, help='Number of training samples to generate')
    parser.add_argument('--model_output', default='tampering_detector_model.joblib', help='Output model file')
    args = parser.parse_args()
    
    print(f"Creating training dataset in {args.dataset_dir} with {args.samples} samples...")
    normal_files, tampered_files = create_training_dataset(args.dataset_dir, args.samples)
    
    print(f"Created {len(normal_files)} normal samples and {len(tampered_files)} tampered samples")
    
    # Prepare data for training
    all_files = normal_files + tampered_files
    labels = [0] * len(normal_files) + [1] * len(tampered_files)  # 0 for normal, 1 for tampered
    
    # Train the model
    print("Training the tampering detection model...")
    detector = TamperingDetector()
    detector.train(all_files, labels)
    
    # Save the model
    detector.save_model(args.model_output)
    print(f"Model saved to {args.model_output}")
    
    # Test the model
    print("\nTesting the model on a few samples:")
    for i in range(5):
        # Test on normal sample
        result = detector.predict(normal_files[i])
        print(f"Normal sample {i}: {'Tampered' if result else 'Clean'}")
        
        # Test on tampered sample
        result = detector.predict(tampered_files[i])
        print(f"Tampered sample {i}: {'Tampered' if result else 'Clean'}")

if __name__ == "__main__":
    main()
