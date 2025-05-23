import hashlib
import hmac
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

class IntegrityChecker:
    """Class for checking the integrity of encrypted data using various hashing algorithms."""
    
    @staticmethod
    def calculate_hash(data, algorithm='sha256'):
        """Calculate hash of data using specified algorithm."""
        if algorithm == 'sha256':
            return hashlib.sha256(data).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(data).hexdigest()
        elif algorithm == 'sha3-256':
            return hashlib.sha3_256(data).hexdigest()
        else:
            raise ValueError(f"Unsupported hashing algorithm: {algorithm}")
    
    @staticmethod
    def verify_hash(data, expected_hash, algorithm='sha256'):
        """Verify that the hash of data matches the expected hash."""
        actual_hash = IntegrityChecker.calculate_hash(data, algorithm)
        return actual_hash == expected_hash
    
    @staticmethod
    def calculate_hmac(data, key, algorithm='sha256'):
        """Calculate HMAC for data using specified key and algorithm."""
        if algorithm == 'sha256':
            return hmac.new(key, data, hashlib.sha256).hexdigest()
        elif algorithm == 'sha512':
            return hmac.new(key, data, hashlib.sha512).hexdigest()
        else:
            raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")
    
    @staticmethod
    def verify_hmac(data, key, expected_hmac, algorithm='sha256'):
        """Verify that the HMAC of data matches the expected HMAC."""
        actual_hmac = IntegrityChecker.calculate_hmac(data, key, algorithm)
        return actual_hmac == expected_hmac

class DigitalSignature:
    """Class for creating and verifying digital signatures."""
    
    @staticmethod
    def generate_key_pair():
        """Generate RSA key pair for digital signatures."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def sign_data(data, private_key):
        """Sign data with private key."""
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    def verify_signature(data, signature, public_key):
        """Verify signature using public key."""
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

def save_metadata(filename, metadata):
    """Save integrity metadata to file."""
    with open(f"{filename}.meta", 'w') as f:
        for key, value in metadata.items():
            if isinstance(value, bytes):
                value = value.hex()
            f.write(f"{key}:{value}\n")

def load_metadata(filename):
    """Load integrity metadata from file."""
    metadata = {}
    with open(f"{filename}.meta", 'r') as f:
        for line in f:
            key, value = line.strip().split(':', 1)
            if key in ['signature', 'hmac']:
                value = bytes.fromhex(value)
            metadata[key] = value
    return metadata
