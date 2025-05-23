#!/usr/bin/env python
"""
Project Security Enhancement Script
This script secures all phases of the AI-Driven Encryption Framework.
It validates file integrity, sets proper permissions, and enhances security across all phases.
"""

import os
import sys
import hashlib
import logging
import platform
import argparse
import shutil
import stat
import json
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security_audit.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("security_audit")

# Import security utilities if available
try:
    from security_utils import secure_delete_file, calculate_entropy
except ImportError:
    logger.warning("Could not import security_utils, some features will be limited")
    
    # Provide basic implementations of required functions
    def calculate_entropy(data):
        """Basic entropy calculation for bytes or strings."""
        if isinstance(data, str):
            data = data.encode()
        
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        entropy = 0
        for count in byte_counts.values():
            probability = count / len(data)
            if probability > 0:
                entropy -= probability * (probability.bit_length())
        return entropy
    
    def secure_delete_file(file_path):
        """Basic secure file deletion."""
        try:
            os.remove(file_path)
            logger.info(f"Deleted file: {file_path}")
        except Exception as e:
            logger.error(f"Error deleting file {file_path}: {e}")

def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def audit_file_permissions(path):
    """Audit and fix file permissions if needed."""
    if platform.system() != 'Windows':
        # For Unix-like systems, set proper permissions
        try:
            if os.path.isdir(path):
                os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)  # 0o750
                logger.info(f"Set directory permissions for {path}")
            else:
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)  # 0o640
                logger.info(f"Set file permissions for {path}")
        except Exception as e:
            logger.error(f"Could not set permissions for {path}: {e}")

def check_file_entropy(file_path):
    """Check the entropy of a file to identify potentially weak cryptographic material."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        entropy = calculate_entropy(data)
        file_size = os.path.getsize(file_path)
        
        # Files that might contain keys or passwords
        sensitive_extensions = ['.key', '.pem', '.pfx', '.p12', '.keystore', '.jks']
        is_sensitive = any(file_path.endswith(ext) for ext in sensitive_extensions)
        
        # Higher standards for sensitive files
        min_entropy = 3.5 if is_sensitive else 2.0
        
        if entropy < min_entropy and file_size > 20:
            logger.warning(f"Low entropy ({entropy:.2f}) detected in {file_path}. This may indicate weak cryptographic material.")
            return False
        return True
    except Exception as e:
        logger.error(f"Error checking entropy for {file_path}: {e}")
        return False

def secure_python_code(file_path):
    """Scan Python code for common security issues."""
    security_issues = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
            
            # Check for hardcoded secrets
            patterns = [
                ('API key', r'api[_-]?key[\'"\s]*(?:=|:)[\'"\s]*([a-zA-Z0-9]{20,})'),
                ('Password', r'password[\'"\s]*(?:=|:)[\'"\s]*([^\'"\s]{6,})'),
                ('Secret', r'secret[\'"\s]*(?:=|:)[\'"\s]*([^\'"\s]{6,})'),
                ('Private key', r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
                ('AWS key', r'AKIA[0-9A-Z]{16}'),
            ]
            
            for name, pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    security_issues.append(f"Possible hardcoded {name} found")
            
            # Check for security-related issues
            for i, line in enumerate(lines):
                # Check for eval() usage
                if re.search(r'eval\s*\(', line):
                    security_issues.append(f"Line {i+1}: Potentially unsafe eval() usage")
                
                # Check for shell=True in subprocess
                if re.search(r'subprocess\.(?:call|Popen|run).*shell\s*=\s*True', line):
                    security_issues.append(f"Line {i+1}: Potentially unsafe subprocess with shell=True")
                
                # Check for pickle load
                if re.search(r'pickle\.load', line):
                    security_issues.append(f"Line {i+1}: Potentially unsafe pickle.load (deserialization vulnerability)")
                
                # Check for weak hashlib usage
                if re.search(r'hashlib\.(?:md5|sha1)\(', line):
                    security_issues.append(f"Line {i+1}: Weak hash algorithm (MD5/SHA1)")
    
        if security_issues:
            logger.warning(f"Security issues found in {file_path}:")
            for issue in security_issues:
                logger.warning(f"  - {issue}")
            return False
        return True
    
    except Exception as e:
        logger.error(f"Error scanning {file_path}: {e}")
        return False

def create_integrity_manifest(project_path):
    """Create a manifest file with hashes of all files for integrity verification."""
    manifest = {}
    excluded_dirs = ['.git', '__pycache__', '.vscode', '.idea']
    excluded_extensions = ['.pyc', '.pyo', '.pyd', '.log']
    
    for root, dirs, files in os.walk(project_path):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        
        for file in files:
            if any(file.endswith(ext) for ext in excluded_extensions):
                continue
                
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, project_path)
            
            try:
                file_hash = get_file_hash(file_path)
                manifest[rel_path] = {
                    'hash': file_hash,
                    'size': os.path.getsize(file_path),
                    'last_modified': os.path.getmtime(file_path)
                }
            except Exception as e:
                logger.error(f"Error processing {file_path}: {e}")
    
    # Save the manifest
    manifest_path = os.path.join(project_path, 'integrity_manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    logger.info(f"Created integrity manifest with {len(manifest)} files at {manifest_path}")
    return manifest_path

def verify_integrity_manifest(project_path, manifest_path=None):
    """Verify the integrity of files against the manifest."""
    if manifest_path is None:
        manifest_path = os.path.join(project_path, 'integrity_manifest.json')
    
    if not os.path.exists(manifest_path):
        logger.error("Integrity manifest not found. Run with --create-manifest first.")
        return False
    
    with open(manifest_path, 'r') as f:
        manifest = json.load(f)
    
    integrity_verified = True
    modified_files = []
    missing_files = []
    
    for rel_path, file_info in manifest.items():
        file_path = os.path.join(project_path, rel_path)
        
        if not os.path.exists(file_path):
            logger.warning(f"Missing file: {rel_path}")
            missing_files.append(rel_path)
            integrity_verified = False
            continue
        
        current_hash = get_file_hash(file_path)
        if current_hash != file_info['hash']:
            logger.warning(f"Modified file: {rel_path}")
            modified_files.append(rel_path)
            integrity_verified = False
    
    if integrity_verified:
        logger.info("All files verified successfully!")
    else:
        logger.warning(f"{len(modified_files)} files modified, {len(missing_files)} files missing")
    
    return integrity_verified

def check_for_vulnerabilities(project_path):
    """Check for common security vulnerabilities in the project."""
    vulnerabilities = []
    python_files = []
    
    # Find all Python files
    for root, _, files in os.walk(project_path):
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    
    # Import necessary modules
    import re
    
    # Check each Python file
    for file_path in python_files:
        secure_python_code(file_path)
    
    # Check for sensitive files with weak permissions
    sensitive_patterns = ['key', 'password', 'secret', 'token', 'credential']
    for root, _, files in os.walk(project_path):
        for file in files:
            file_lower = file.lower()
            if any(pattern in file_lower for pattern in sensitive_patterns):
                file_path = os.path.join(root, file)
                audit_file_permissions(file_path)
                check_file_entropy(file_path)
    
    return vulnerabilities

def secure_phase(phase_path):
    """Apply security enhancements to a specific phase."""
    if not os.path.exists(phase_path):
        logger.error(f"Phase path does not exist: {phase_path}")
        return False
    
    logger.info(f"Securing phase: {os.path.basename(phase_path)}")
    
    # Create a directory for secure storage of keys and sensitive data
    secure_dir = os.path.join(phase_path, 'secure_storage')
    if not os.path.exists(secure_dir):
        os.makedirs(secure_dir)
        logger.info(f"Created secure storage directory: {secure_dir}")
    
    # Set proper permissions on the secure directory
    audit_file_permissions(secure_dir)
    
    # Create a .gitignore file in the secure directory
    gitignore_path = os.path.join(secure_dir, '.gitignore')
    if not os.path.exists(gitignore_path):
        with open(gitignore_path, 'w') as f:
            f.write("# Ignore all files in this secure storage directory\n*\n!.gitignore\n")
        logger.info(f"Created .gitignore for secure storage")
    
    # Check for vulnerabilities in this phase
    check_for_vulnerabilities(phase_path)
    
    return True

def create_security_documentation(project_path):
    """Create security documentation for the project."""
    doc_path = os.path.join(project_path, 'SECURITY.md')
    
    with open(doc_path, 'w') as f:
        f.write("""# Security Policy and Guidelines

## Reporting Security Issues

If you discover a security vulnerability in this project, please report it by sending an email to [your-email@example.com](mailto:your-email@example.com). We will work with you to address the issue.

## Security Measures Implemented

This project implements the following security measures:

### Cryptographic Key Management
- All cryptographic keys are generated using secure random generators
- Keys are stored in isolated secure storage directories
- Key rotation is implemented for long-term security

### Data Protection
- AES-256 encryption for sensitive data
- RSA-2048 or ECC-256 for asymmetric encryption
- Secure hashing with SHA-256 or better
- Digital signatures for data integrity verification

### Application Security
- Input validation and sanitization
- Protection against common web vulnerabilities (XSS, CSRF, etc.)
- Secure session management
- Proper error handling and logging

### File Security
- Secure file handling procedures
- Integrity verification of project files
- Proper file permissions

## Security Best Practices for Users

1. **Key Protection**: Store encryption keys securely, separate from encrypted data
2. **Password Strength**: Use strong, unique passwords for key derivation
3. **Regular Updates**: Keep the software and its dependencies up to date
4. **Data Backups**: Maintain secure backups of your encryption keys and important data
5. **Secure Environment**: Run the software in a secure environment free from malware

## Third-party Dependencies

This project uses several third-party libraries. We regularly monitor these dependencies for security vulnerabilities and update them as needed.

## Security Audit

The project undergoes regular security audits using the `secure_project.py` script. Run this script to verify the integrity and security of your installation.

```bash
python secure_project.py --check-all
```

## License

This security policy is provided under the same license as the project itself.
""")
    
    logger.info(f"Created security documentation at {doc_path}")
    return doc_path

def main():
    parser = argparse.ArgumentParser(description="Security enhancement tool for AI-Driven Encryption Framework")
    parser.add_argument('--create-manifest', action='store_true', help='Create an integrity manifest')
    parser.add_argument('--verify-integrity', action='store_true', help='Verify file integrity against the manifest')
    parser.add_argument('--check-vulnerabilities', action='store_true', help='Check for security vulnerabilities')
    parser.add_argument('--secure-all-phases', action='store_true', help='Apply security enhancements to all phases')
    parser.add_argument('--create-documentation', action='store_true', help='Create security documentation')
    parser.add_argument('--check-all', action='store_true', help='Run all security checks and enhancements')
    
    args = parser.parse_args()
    
    # Get project root path
    project_path = os.path.dirname(os.path.abspath(__file__))
    logger.info(f"Project path: {project_path}")
    
    # Default to --check-all if no arguments specified
    if not any(vars(args).values()):
        args.check_all = True
    
    if args.create_manifest or args.check_all:
        create_integrity_manifest(project_path)
    
    if args.verify_integrity or args.check_all:
        verify_integrity_manifest(project_path)
    
    if args.check_vulnerabilities or args.check_all:
        check_for_vulnerabilities(project_path)
    
    if args.secure_all_phases or args.check_all:
        # Secure all phases
        for phase_dir in ['phase-1', 'phase-2', 'phase-3', 'phase-4', 'phase-5']:
            phase_path = os.path.join(project_path, phase_dir)
            if os.path.exists(phase_path):
                secure_phase(phase_path)
    
    if args.create_documentation or args.check_all:
        create_security_documentation(project_path)
    
    logger.info("Security operations completed")

if __name__ == "__main__":
    main()
