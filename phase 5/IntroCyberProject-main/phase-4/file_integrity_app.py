import os
import argparse
from integrity_checker import IntegrityChecker, DigitalSignature, save_metadata, load_metadata
from tampering_detector import TamperingDetector
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib
import time

class FileIntegrityApp:
    """Application for verifying file integrity and detecting tampering."""
    
    def __init__(self, model_path=None):
        """Initialize the application."""
        self.integrity_checker = IntegrityChecker()
        self.tampering_detector = TamperingDetector(model_path)
        self.model_path = model_path
    
    def protect_file(self, input_file, key=None, sign_key=None):
        """Add integrity protection to a file."""
        # Read input file
        with open(input_file, 'rb') as f:
            data = f.read()
        
        # Generate integrity metadata
        metadata = {
            'original_filename': os.path.basename(input_file),
            'timestamp': str(time.time()),
            'filesize': len(data),
            'algorithm': 'sha256'
        }
        
        # Calculate hash
        metadata['hash'] = self.integrity_checker.calculate_hash(data)
        
        # Add HMAC if key is provided
        if key:
            if isinstance(key, str):
                key = key.encode()
            metadata['hmac'] = self.integrity_checker.calculate_hmac(data, key)
        
        # Add digital signature if signing key is provided
        if sign_key:
            signature = DigitalSignature.sign_data(data, sign_key)
            metadata['signature'] = signature
        
        # Save metadata
        save_metadata(input_file, metadata)
        print(f"Integrity protection added to {input_file}")
        
        return metadata
    
    def verify_file(self, input_file, key=None, public_key=None):
        """Verify the integrity of a file."""
        # Read input file
        with open(input_file, 'rb') as f:
            data = f.read()
        
        # Load metadata
        try:
            metadata = load_metadata(input_file)
        except FileNotFoundError:
            print(f"No integrity metadata found for {input_file}")
            return False
        
        # Verify hash
        hash_valid = self.integrity_checker.verify_hash(
            data, 
            metadata['hash'], 
            metadata.get('algorithm', 'sha256')
        )
        
        # Verify HMAC if key is provided
        hmac_valid = True
        if 'hmac' in metadata and key:
            if isinstance(key, str):
                key = key.encode()
            hmac_valid = self.integrity_checker.verify_hmac(
                data, 
                key, 
                metadata['hmac'], 
                metadata.get('algorithm', 'sha256')
            )
        
        # Verify signature if public key is provided
        signature_valid = True
        if 'signature' in metadata and public_key:
            signature_valid = DigitalSignature.verify_signature(
                data, 
                metadata['signature'], 
                public_key
            )
        
        # Use AI model to detect tampering
        ai_tampered = False
        if self.model_path:
            ai_tampered = self.tampering_detector.predict(data)
        
        results = {
            'filename': input_file,
            'hash_valid': hash_valid,
            'hmac_valid': hmac_valid if 'hmac' in metadata else 'Not checked',
            'signature_valid': signature_valid if 'signature' in metadata else 'Not checked',
            'ai_tampering_detected': ai_tampered if self.model_path else 'Not checked',
            'overall_integrity': all([
                hash_valid, 
                hmac_valid if 'hmac' in metadata else True,
                signature_valid if 'signature' in metadata else True,
                not ai_tampered if self.model_path else True
            ])
        }
        
        return results
    
    def generate_key_pair(self, output_prefix='key'):
        """Generate a key pair for digital signatures."""
        private_key, public_key = DigitalSignature.generate_key_pair()
        
        # Save private key
        with open(f"{output_prefix}.private", 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))
        
        # Save public key
        with open(f"{output_prefix}.public", 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ))
        
        print(f"Key pair generated and saved with prefix '{output_prefix}'")
        return private_key, public_key

def main():
    parser = argparse.ArgumentParser(description='AI-Enhanced File Integrity Checker')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Protect command
    protect_parser = subparsers.add_parser('protect', help='Add integrity protection to a file')
    protect_parser.add_argument('file', help='File to protect')
    protect_parser.add_argument('--key', help='Secret key for HMAC (optional)')
    protect_parser.add_argument('--sign', help='Path to private key for signing (optional)')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify file integrity')
    verify_parser.add_argument('file', help='File to verify')
    verify_parser.add_argument('--key', help='Secret key for HMAC verification (optional)')
    verify_parser.add_argument('--pubkey', help='Path to public key for signature verification (optional)')
    verify_parser.add_argument('--model', help='Path to tampering detection model (optional)')
    
    # Generate keys command
    keys_parser = subparsers.add_parser('generate-keys', help='Generate key pair for digital signatures')
    keys_parser.add_argument('--prefix', default='key', help='Output filename prefix')
    
    # Parse arguments
    args = parser.parse_args()
    
    if args.command == 'protect':
        app = FileIntegrityApp()
        
        # Load signing key if provided
        sign_key = None
        if args.sign:
            with open(args.sign, 'rb') as f:
                sign_key = load_pem_private_key(f.read(), password=None)
        
        app.protect_file(args.file, args.key, sign_key)
    
    elif args.command == 'verify':
        app = FileIntegrityApp(args.model)
        
        # Load public key if provided
        public_key = None
        if args.pubkey:
            with open(args.pubkey, 'rb') as f:
                public_key = load_pem_public_key(f.read())
        
        results = app.verify_file(args.file, args.key, public_key)
        print(json.dumps(results, indent=2))
        
        if results['overall_integrity']:
            print("\n✅ File integrity verified!")
        else:
            print("\n❌ File integrity verification failed!")
    
    elif args.command == 'generate-keys':
        app = FileIntegrityApp()
        app.generate_key_pair(args.prefix)

if __name__ == "__main__":
    main()
