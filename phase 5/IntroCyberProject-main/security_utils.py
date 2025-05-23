"""
Security utilities for the AI-Driven Encryption Framework.
This module provides common security functions and utilities 
that can be used across all phases of the project.
"""

import os
import base64
import secrets
import logging
import hashlib
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("security_utils")

# Secure temporary directory for sensitive operations
SECURE_TEMP_DIR = os.path.join(tempfile.gettempdir(), 'ai_encryption_secure')
os.makedirs(SECURE_TEMP_DIR, exist_ok=True)

def generate_secure_key(length=32):
    """Generate a cryptographically secure random key."""
    return secrets.token_bytes(length)

def derive_key_from_password(password, salt=None, length=32):
    """
    Derive a secure key from a password using PBKDF2.
    
    Args:
        password: The password to derive the key from
        salt: Optional salt, will be generated if not provided
        length: The desired key length in bytes
        
    Returns:
        tuple: (derived_key, salt)
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
        
    if salt is None:
        salt = secrets.token_bytes(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password)
    
    return key, salt

def secure_delete_file(file_path):
    """
    Securely delete a file by overwriting with random data before deleting.
    
    Args:
        file_path: Path to the file to be securely deleted
    """
    if not os.path.exists(file_path):
        return
    
    # Get the file size
    file_size = os.path.getsize(file_path)
    
    try:
        # Overwrite with random data multiple times
        for _ in range(3):
            with open(file_path, 'wb') as f:
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        # Finally delete the file
        os.remove(file_path)
        logger.info(f"Securely deleted file: {file_path}")
    except Exception as e:
        logger.error(f"Error during secure file deletion: {e}")
        # Fall back to regular deletion
        try:
            os.remove(file_path)
        except:
            pass

def sanitize_filename(filename):
    """
    Sanitize a filename to prevent directory traversal attacks.
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        str: Sanitized filename
    """
    # Get just the base filename, no path
    return os.path.basename(filename)

def secure_random_token(length=32):
    """Generate a secure random token string."""
    return secrets.token_hex(length)

def validate_key_strength(key, min_length=16):
    """
    Validate that a cryptographic key meets minimum security requirements.
    
    Args:
        key: The key to validate (bytes or string)
        min_length: Minimum required length in bytes
        
    Returns:
        bool: True if the key meets security requirements
    """
    if isinstance(key, str):
        # Convert hex string to bytes
        try:
            key = bytes.fromhex(key)
        except:
            # Try as base64
            try:
                key = base64.b64decode(key)
            except:
                # Try as UTF-8
                key = key.encode('utf-8')
    
    # Check length
    if len(key) < min_length:
        return False
    
    # Calculate entropy
    entropy = calculate_entropy(key)
    min_entropy = 3.5  # Minimum entropy per byte (good randomness)
    
    return entropy >= min_entropy

def calculate_entropy(data):
    """
    Calculate the Shannon entropy of data.
    
    Args:
        data: Bytes or string data
        
    Returns:
        float: Entropy value (higher is more random)
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Count byte occurrences
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0
    for count in counts.values():
        probability = count / len(data)
        entropy -= probability * (probability.bit_length() if probability > 0 else 0)
    
    return entropy

def create_secure_environment():
    """
    Set up a secure environment for cryptographic operations.
    Checks for insecure configurations and environment variables.
    """
    # Check for PYTHONHASHSEED to ensure hash randomization
    if os.environ.get('PYTHONHASHSEED', '') == '0':
        logger.warning("PYTHONHASHSEED=0 detected, hash randomization is disabled. This is insecure.")
    
    # Create secure directories with proper permissions
    secure_key_dir = os.path.join(os.path.expanduser("~"), ".ai_encryption", "keys")
    os.makedirs(secure_key_dir, exist_ok=True)
    
    # On non-Windows systems, set proper permissions
    if os.name != 'nt':  # Unix-like systems
        try:
            import stat
            os.chmod(secure_key_dir, stat.S_IRUSR | stat.S_IWUSR)  # 0o600 - Owner read/write only
        except Exception as e:
            logger.error(f"Could not set secure permissions: {e}")
    
    return secure_key_dir

def sanitize_input(user_input, max_length=1000):
    """
    Sanitize user input to prevent injection attacks.
    
    Args:
        user_input: The user input to sanitize
        max_length: Maximum allowed length
        
    Returns:
        str: Sanitized input
    """
    if not isinstance(user_input, str):
        return ""
    
    # Limit length
    user_input = user_input[:max_length]
    
    # Remove potentially dangerous characters
    dangerous_chars = ['../', '..\\', ';', '&', '|', '>', '<', '$', '`', '"', "'", '*', '?']
    for char in dangerous_chars:
        user_input = user_input.replace(char, '')
    
    return user_input

class SecureTemporaryFile:
    """
    Context manager for securely handling temporary files with sensitive content.
    Automatically deletes the file when done.
    """
    def __init__(self, suffix=None, prefix=None, dir=None):
        self.suffix = suffix or '.tmp'
        self.prefix = prefix or 'secure_'
        self.dir = dir or SECURE_TEMP_DIR
        self.path = None
    
    def __enter__(self):
        # Create a temporary file
        fd, self.path = tempfile.mkstemp(suffix=self.suffix, prefix=self.prefix, dir=self.dir)
        os.close(fd)
        return self.path
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Securely delete the file
        if self.path and os.path.exists(self.path):
            secure_delete_file(self.path)

# Initialize secure environment when module is imported
secure_key_directory = create_secure_environment()
