from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from flask_wtf.csrf import CSRFProtect
import os
import sys
import secrets
import datetime
import json
import uuid
import logging
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import tempfile
import shutil

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ai_encryption_app")

# Add paths to previous phases
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
phase2_path = os.path.join(project_root, 'phase-2')
phase3_path = os.path.join(project_root, 'phase-3')
phase4_path = os.path.join(project_root, 'phase-4')
current_path = os.path.dirname(os.path.abspath(__file__))

# Add the project root to sys.path to import security_utils
sys.path.append(project_root)
sys.path.append(phase2_path)
sys.path.append(phase3_path)
sys.path.append(phase4_path)
sys.path.append(current_path)

# Import security utilities
try:
    from security_utils import (
        generate_secure_key, 
        secure_delete_file, 
        sanitize_filename, 
        secure_random_token,
        SecureTemporaryFile,
        validate_key_strength,
        sanitize_input
    )
except ImportError as e:
    logger.error(f"Could not import security_utils: {e}")

# Import modules from other phases (assuming they're available)
try:
    # Import AI-based encryption modules from phase-3
    from aes import AESEncryption
    from rsa import RSAEncryption
    from ecc import ECCEncryption
    
    # Import integrity checking from phase-4
    from integrity_checker import IntegrityChecker, DigitalSignature
    from tampering_detector import TamperingDetector
    
    # Import report generator from current phase
    from report_generator import EncryptionReportGenerator
except ImportError as e:
    print(f"Warning: Some modules could not be imported: {e}")
    # Define placeholder classes if imports fail
    class AESEncryption:
        @staticmethod
        def encrypt(data, key): return data
        @staticmethod
        def decrypt(data, key): return data
    
    class RSAEncryption:
        @staticmethod
        def encrypt(data, key): return data
        @staticmethod
        def decrypt(data, key): return data

# Initialize Flask app
app = Flask(__name__)

# Enhanced security configurations
app.secret_key = secrets.token_hex(32)  # Using a longer key for better security
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # SameSite cookie attribute
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=1)  # Session timeout

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Use ProxyFix if behind a reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Set maximum content length (16MB)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Configuration
# Secure upload folder with unique session identifier to prevent file access across sessions
def get_session_upload_folder():
    if 'user_id' not in session:
        session['user_id'] = str(uuid.uuid4())
    
    session_folder = os.path.join(tempfile.gettempdir(), 'ai_encryption_uploads', session['user_id'])
    os.makedirs(session_folder, exist_ok=True)
    return session_folder

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'xls', 'xlsx', 'zip'}

app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS

# Create root upload folder if it doesn't exist
os.makedirs(os.path.join(tempfile.gettempdir(), 'ai_encryption_uploads'), exist_ok=True)

# Helper functions
def allowed_file(filename):
    """Check if the file extension is allowed while preventing path traversal."""
    # Sanitize the filename first
    filename = sanitize_filename(filename)
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Render the main page of the application."""
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    """Handle file encryption."""
    if request.method == 'POST':
        # Check if a file was uploaded
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
            
        file = request.files['file']
        
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            # Save the uploaded file
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Get encryption parameters
            algorithm = request.form.get('algorithm', 'aes')
            add_integrity = 'add_integrity' in request.form
            
            try:
                # Read file content
                with open(filepath, 'rb') as f:
                    file_data = f.read()
                
                # Encrypt based on selected algorithm
                if algorithm == 'aes':
                    key = secrets.token_bytes(32)  # 256-bit key
                    encrypted_data = AESEncryption.encrypt(file_data, key)
                    key_info = {'type': 'AES-256', 'key': key.hex()}
                elif algorithm == 'rsa':
                    # In a real app, you would use proper key management
                    key_pair = DigitalSignature.generate_key_pair()
                    encrypted_data = RSAEncryption.encrypt(file_data, key_pair[1])
                    key_info = {'type': 'RSA-2048', 'key': 'Generated RSA key pair'}
                else:
                    # Default to AES
                    key = secrets.token_bytes(32)
                    encrypted_data = AESEncryption.encrypt(file_data, key)
                    key_info = {'type': 'AES-256', 'key': key.hex()}
                
                # Add integrity protection if requested
                if add_integrity:
                    # Create a metadata file with hash
                    encrypted_filepath = filepath + '.enc'
                    with open(encrypted_filepath, 'wb') as f:
                        f.write(encrypted_data)
                        
                    integrity_checker = IntegrityChecker()
                    metadata = {
                        'algorithm': algorithm,
                        'hash': integrity_checker.calculate_hash(encrypted_data),
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                    
                    # Save metadata
                    with open(encrypted_filepath + '.meta', 'w') as f:
                        json.dump(metadata, f)
                        
                    # Save the encrypted file for download
                    download_path = encrypted_filepath
                else:
                    # Save the encrypted file for download
                    download_path = filepath + '.enc'
                    with open(download_path, 'wb') as f:
                        f.write(encrypted_data)
                
                # Store file path in session for download
                session['encrypted_file'] = download_path
                session['key_info'] = key_info
                
                return redirect(url_for('download_encrypted'))
                
            except Exception as e:
                flash(f'Error during encryption: {str(e)}')
                return redirect(request.url)
                
        else:
            flash('File type not allowed')
            return redirect(request.url)
            
    return render_template('encrypt.html', allowed_extensions=ALLOWED_EXTENSIONS)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    """Handle file decryption."""
    if request.method == 'POST':
        # Check if a file was uploaded
        if 'file' not in request.files or 'key' not in request.form:
            flash('Missing file or key')
            return redirect(request.url)
            
        file = request.files['file']
        key = request.form['key']
        
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
            
        if file:
            # Save the uploaded file
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Get decryption parameters
            algorithm = request.form.get('algorithm', 'aes')
            check_integrity = 'check_integrity' in request.form
            
            try:
                # Read file content
                with open(filepath, 'rb') as f:
                    encrypted_data = f.read()
                
                # Check integrity if requested
                integrity_verified = True
                if check_integrity:
                    try:
                        # Check if metadata file exists
                        metadata_path = filepath + '.meta'
                        if os.path.exists(metadata_path):
                            with open(metadata_path, 'r') as f:
                                metadata = json.load(f)
                                
                            integrity_checker = IntegrityChecker()
                            hash_verified = integrity_checker.verify_hash(
                                encrypted_data, 
                                metadata['hash']
                            )
                            
                            if not hash_verified:
                                flash('Warning: Integrity check failed. File may have been tampered with.')
                                integrity_verified = False
                        else:
                            flash('Warning: No integrity metadata found. Skipping integrity check.')
                    except Exception as e:
                        flash(f'Error during integrity check: {str(e)}')
                
                # Decrypt based on selected algorithm
                if algorithm == 'aes':
                    # Convert hex key to bytes
                    key_bytes = bytes.fromhex(key)
                    decrypted_data = AESEncryption.decrypt(encrypted_data, key_bytes)
                elif algorithm == 'rsa':
                    # In a real app, you would use proper key management
                    # This is a simplified example
                    flash('RSA decryption would require private key handling')
                    return redirect(request.url)
                else:
                    # Default to AES
                    key_bytes = bytes.fromhex(key)
                    decrypted_data = AESEncryption.decrypt(encrypted_data, key_bytes)
                
                # Save the decrypted file for download
                output_filename = filename
                if output_filename.endswith('.enc'):
                    output_filename = output_filename[:-4]
                
                download_path = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_' + output_filename)
                with open(download_path, 'wb') as f:
                    f.write(decrypted_data)
                
                # Store file path in session for download
                session['decrypted_file'] = download_path
                session['integrity_verified'] = integrity_verified
                
                return redirect(url_for('download_decrypted'))
                
            except Exception as e:
                flash(f'Error during decryption: {str(e)}')
                return redirect(request.url)
                
    return render_template('decrypt.html')

@app.route('/download-encrypted')
def download_encrypted():
    """Provide download for encrypted file and display key."""
    if 'encrypted_file' not in session:
        flash('No encrypted file available')
        return redirect(url_for('encrypt'))
        
    encrypted_file = session['encrypted_file']
    key_info = session.get('key_info', {})
    
    if not os.path.exists(encrypted_file):
        flash('Encrypted file not found')
        return redirect(url_for('encrypt'))
        
    return render_template('download_encrypted.html', 
                          filename=os.path.basename(encrypted_file),
                          key_info=key_info)

@app.route('/download-decrypted')
def download_decrypted():
    """Provide download for decrypted file."""
    if 'decrypted_file' not in session:
        flash('No decrypted file available')
        return redirect(url_for('decrypt'))
        
    decrypted_file = session['decrypted_file']
    integrity_verified = session.get('integrity_verified', False)
    
    if not os.path.exists(decrypted_file):
        flash('Decrypted file not found')
        return redirect(url_for('decrypt'))
        
    return render_template('download_decrypted.html', 
                          filename=os.path.basename(decrypted_file),
                          integrity_verified=integrity_verified)

@app.route('/download-file/<file_type>')
def download_file(file_type):
    """Handle file downloads."""
    if file_type == 'encrypted':
        if 'encrypted_file' not in session:
            flash('No encrypted file available')
            return redirect(url_for('encrypt'))
            
        filepath = session['encrypted_file']
        
    elif file_type == 'decrypted':
        if 'decrypted_file' not in session:
            flash('No decrypted file available')
            return redirect(url_for('decrypt'))
            
        filepath = session['decrypted_file']
        
    else:
        flash('Invalid file type')
        return redirect(url_for('index'))
    
    if not os.path.exists(filepath):
        flash('File not found')
        return redirect(url_for('index'))
        
    return send_file(filepath, as_attachment=True)

@app.route('/generate-report', methods=['GET', 'POST'])
def generate_report():
    """Generate an encryption security report."""
    if request.method == 'POST':
        # Get report parameters
        report_name = request.form.get('report_name', 'Encryption_Security_Report')
        include_key_analysis = 'include_key_analysis' in request.form
        include_algorithm_analysis = 'include_algorithm_analysis' in request.form
        include_recommendations = 'include_recommendations' in request.form
        
        # Create report generator
        generator = EncryptionReportGenerator()
        
        # Add report sections based on user selections
        if include_key_analysis:
            # Example key data (in a real app, this would be from the user's encryption)
            generator.analyze_key_strength(os.urandom(32), 'AES')
            
        if include_algorithm_analysis:
            generator.analyze_encryption_algorithms()
            
        if include_recommendations:
            generator.generate_recommendations()
            
        # Always include a summary
        generator.generate_summary()
        
        # Generate and save report
        report_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{report_name}.html")
        generator.generate_report(report_path)
        
        # Store report path in session for download
        session['report_file'] = report_path
        
        return redirect(url_for('download_report'))
        
    return render_template('generate_report.html')

@app.route('/download-report')
def download_report():
    """Provide download for generated report."""
    if 'report_file' not in session:
        flash('No report available')
        return redirect(url_for('generate_report'))
        
    report_file = session['report_file']
    
    if not os.path.exists(report_file):
        flash('Report file not found')
        return redirect(url_for('generate_report'))
        
    return render_template('download_report.html', 
                          filename=os.path.basename(report_file))

@app.route('/download-report-file')
def download_report_file():
    """Handle report file download."""
    if 'report_file' not in session:
        flash('No report available')
        return redirect(url_for('generate_report'))
        
    filepath = session['report_file']
    
    if not os.path.exists(filepath):
        flash('Report file not found')
        return redirect(url_for('generate_report'))
        
    return send_file(filepath, as_attachment=True)

@app.route('/documentation')
def documentation():
    """Provide documentation on encryption methods."""
    return render_template('documentation.html')

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; font-src 'self' https://cdnjs.cloudflare.com"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Clean up old files securely
@app.before_request
def cleanup_old_files():
    """Securely clean up files older than 1 hour."""
    try:
        now = datetime.datetime.now()
        root_upload_dir = os.path.join(tempfile.gettempdir(), 'ai_encryption_uploads')
        
        if os.path.exists(root_upload_dir):
            # Iterate through session directories
            for session_id in os.listdir(root_upload_dir):
                session_dir = os.path.join(root_upload_dir, session_id)
                
                if os.path.isdir(session_dir):
                    # Check directory modification time
                    dir_modified = datetime.datetime.fromtimestamp(os.path.getmtime(session_dir))
                    
                    # Remove old session directories completely
                    if (now - dir_modified).seconds > 3600:  # 1 hour
                        for filename in os.listdir(session_dir):
                            filepath = os.path.join(session_dir, filename)
                            if os.path.isfile(filepath):
                                secure_delete_file(filepath)
                        
                        # Try to remove the directory after deleting files
                        try:
                            os.rmdir(session_dir)
                        except Exception as e:
                            logger.error(f"Could not remove session directory: {e}")
    except Exception as e:
        logger.error(f"Error during file cleanup: {e}")

if __name__ == '__main__':
    # In production, set debug=False and use a production WSGI server
    app.run(debug=False, host='127.0.0.1', port=5000, ssl_context='adhoc')
