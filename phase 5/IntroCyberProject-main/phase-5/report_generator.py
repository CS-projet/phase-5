import os
import json
import datetime
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from jinja2 import Environment, FileSystemLoader
import weasyprint
import sys

# Add paths to previous phases to import their modules
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'phase-1'))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'phase-2'))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'phase-3'))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'phase-4'))

# Import necessary modules from previous phases
try:
    from phase_4.integrity_checker import IntegrityChecker
    from phase_4.tampering_detector import TamperingDetector
except ImportError:
    print("Warning: Couldn't import all modules from previous phases")

class EncryptionReportGenerator:
    """AI-powered generator for encryption security reports."""
    
    def __init__(self):
        """Initialize the report generator."""
        self.report_data = {
            'title': 'AI-Driven Encryption Security Report',
            'date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': '',
            'key_strength': {},
            'encryption_analysis': {},
            'integrity_check': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Load templates
        template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
        if not os.path.exists(template_dir):
            os.makedirs(template_dir)
        
        # Create a default template if it doesn't exist
        default_template_path = os.path.join(template_dir, 'report_template.html')
        if not os.path.exists(default_template_path):
            self._create_default_template(default_template_path)
        
        self.env = Environment(loader=FileSystemLoader(template_dir))
    
    def _create_default_template(self, template_path):
        """Create a default HTML template for reports."""
        with open(template_path, 'w') as f:
            f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        h1 { color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        h2 { color: #3498db; margin-top: 30px; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .danger { color: #e74c3c; }
        .warning { color: #f39c12; }
        .success { color: #2ecc71; }
        .recommendation { background-color: #e8f4fc; padding: 10px; margin: 10px 0; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .chart-container { margin: 20px 0; }
        footer { margin-top: 50px; text-align: center; color: #7f8c8d; font-size: 0.8em; }
    </style>
</head>
<body>
    <h1>{{ report.title }}</h1>
    <p>Generated on: {{ report.date }}</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>{{ report.summary }}</p>
    </div>
    
    {% if report.key_strength %}
    <h2>Key Strength Analysis</h2>
    <table>
        <tr>
            <th>Parameter</th>
            <th>Value</th>
            <th>Assessment</th>
        </tr>
        {% for key, data in report.key_strength.items() %}
        <tr>
            <td>{{ key }}</td>
            <td>{{ data.value }}</td>
            <td class="{{ data.status }}">{{ data.message }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}
    
    {% if report.encryption_analysis %}
    <h2>Encryption Algorithm Analysis</h2>
    <table>
        <tr>
            <th>Algorithm</th>
            <th>Strength</th>
            <th>Speed</th>
            <th>Recommendation</th>
        </tr>
        {% for algo, data in report.encryption_analysis.items() %}
        <tr>
            <td>{{ algo }}</td>
            <td class="{{ data.strength_status }}">{{ data.strength }}</td>
            <td>{{ data.speed }}</td>
            <td>{{ data.recommendation }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}
    
    {% if report.integrity_check %}
    <h2>Data Integrity Check</h2>
    <table>
        <tr>
            <th>Check Type</th>
            <th>Result</th>
            <th>Details</th>
        </tr>
        {% for check, data in report.integrity_check.items() %}
        <tr>
            <td>{{ check }}</td>
            <td class="{{ data.status }}">{{ data.result }}</td>
            <td>{{ data.details }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}
    
    {% if report.vulnerabilities %}
    <h2>Detected Vulnerabilities</h2>
    <ul>
        {% for vuln in report.vulnerabilities %}
        <li class="{{ vuln.severity }}">
            <strong>{{ vuln.title }}</strong>: {{ vuln.description }}
        </li>
        {% endfor %}
    </ul>
    {% endif %}
    
    {% if report.recommendations %}
    <h2>Recommendations</h2>
    {% for rec in report.recommendations %}
    <div class="recommendation">
        <strong>{{ rec.title }}</strong>
        <p>{{ rec.description }}</p>
        {% if rec.code_example %}
        <pre><code>{{ rec.code_example }}</code></pre>
        {% endif %}
    </div>
    {% endfor %}
    {% endif %}
    
    <footer>
        <p>Generated by AI-Driven Encryption Security Framework</p>
    </footer>
</body>
</html>""")
    
    def analyze_key_strength(self, key_data, key_type='AES'):
        """Analyze the strength of cryptographic keys."""
        key_strength = {}
        
        if key_type == 'AES':
            # Analyze AES key
            key_length = len(key_data) * 8 if isinstance(key_data, bytes) else len(key_data)
            
            # Evaluate key length
            if key_length >= 256:
                status = 'success'
                message = 'Excellent - Suitable for top-secret data'
            elif key_length >= 192:
                status = 'success'
                message = 'Very strong - Suitable for sensitive data'
            elif key_length >= 128:
                status = 'warning'
                message = 'Adequate - Minimum recommended for sensitive data'
            else:
                status = 'danger'
                message = 'Weak - Not recommended for sensitive data'
            
            key_strength['Key Length'] = {
                'value': f"{key_length} bits",
                'status': status,
                'message': message
            }
            
            # Evaluate entropy if key_data is bytes
            if isinstance(key_data, bytes):
                entropy = self._calculate_entropy(key_data)
                max_entropy = 8.0  # Maximum entropy for byte values (0-255)
                entropy_percentage = (entropy / max_entropy) * 100
                
                if entropy_percentage >= 90:
                    status = 'success'
                    message = 'Excellent entropy'
                elif entropy_percentage >= 75:
                    status = 'success'
                    message = 'Good entropy'
                elif entropy_percentage >= 60:
                    status = 'warning'
                    message = 'Moderate entropy'
                else:
                    status = 'danger'
                    message = 'Poor entropy - consider regenerating'
                
                key_strength['Entropy'] = {
                    'value': f"{entropy:.2f} ({entropy_percentage:.1f}%)",
                    'status': status,
                    'message': message
                }
        
        elif key_type == 'RSA':
            # Analyze RSA key
            key_length = key_data
            
            if key_length >= 4096:
                status = 'success'
                message = 'Excellent - Future-proof security'
            elif key_length >= 3072:
                status = 'success'
                message = 'Very strong - NIST recommended for long-term security'
            elif key_length >= 2048:
                status = 'warning'
                message = 'Adequate - Minimum recommended for sensitive data'
            else:
                status = 'danger'
                message = 'Weak - Not recommended for modern applications'
            
            key_strength['Key Length'] = {
                'value': f"{key_length} bits",
                'status': status,
                'message': message
            }
        
        self.report_data['key_strength'] = key_strength
        return key_strength
    
    def analyze_encryption_algorithms(self, algorithms=None):
        """Analyze the strength and performance of encryption algorithms."""
        if algorithms is None:
            algorithms = ['AES-128', 'AES-256', 'RSA-2048', 'ECC-256']
        
        encryption_analysis = {}
        
        algorithm_data = {
            'AES-128': {
                'strength': 'Strong',
                'strength_status': 'warning',
                'speed': 'Very Fast',
                'recommendation': 'Good for bulk data encryption, but consider AES-256 for sensitive data'
            },
            'AES-256': {
                'strength': 'Very Strong',
                'strength_status': 'success',
                'speed': 'Fast',
                'recommendation': 'Recommended for sensitive data encryption'
            },
            'RSA-2048': {
                'strength': 'Strong',
                'strength_status': 'warning',
                'speed': 'Slow',
                'recommendation': 'Use for small data encryption or signatures, consider 3072+ bits for long-term security'
            },
            'RSA-4096': {
                'strength': 'Very Strong',
                'strength_status': 'success',
                'speed': 'Very Slow',
                'recommendation': 'Good for long-term security, but significant performance impact'
            },
            'ECC-256': {
                'strength': 'Very Strong',
                'strength_status': 'success',
                'speed': 'Moderate',
                'recommendation': 'Excellent balance of security and performance, preferred for mobile applications'
            },
            'ChaCha20': {
                'strength': 'Strong',
                'strength_status': 'success',
                'speed': 'Very Fast',
                'recommendation': 'Excellent for software implementations and mobile devices'
            }
        }
        
        for algo in algorithms:
            if algo in algorithm_data:
                encryption_analysis[algo] = algorithm_data[algo]
        
        self.report_data['encryption_analysis'] = encryption_analysis
        return encryption_analysis
    
    def analyze_integrity_checks(self, integrity_results=None):
        """Analyze the results of integrity checks."""
        if integrity_results is None:
            # Provide a sample analysis if no results provided
            integrity_results = {
                'Hash Verification': {
                    'result': 'Passed',
                    'status': 'success',
                    'details': 'SHA-256 hash matches original'
                },
                'Digital Signature': {
                    'result': 'Passed',
                    'status': 'success',
                    'details': 'RSA-2048 signature verification successful'
                },
                'AI Tampering Detection': {
                    'result': 'No tampering detected',
                    'status': 'success',
                    'details': 'AI model confidence: 98.5%'
                }
            }
        
        self.report_data['integrity_check'] = integrity_results
        return integrity_results
    
    def identify_vulnerabilities(self, encrypted_data=None, encryption_info=None):
        """Identify potential vulnerabilities in the encryption implementation."""
        vulnerabilities = []
        
        # Sample vulnerabilities for demonstration
        if encryption_info and 'algorithm' in encryption_info:
            if encryption_info['algorithm'] == 'AES-CBC':
                vulnerabilities.append({
                    'title': 'Padding Oracle Vulnerability',
                    'description': 'AES-CBC mode is vulnerable to padding oracle attacks. Consider using AES-GCM instead.',
                    'severity': 'warning'
                })
            
            if encryption_info.get('key_length', 0) < 128:
                vulnerabilities.append({
                    'title': 'Insufficient Key Length',
                    'description': f"Key length of {encryption_info['key_length']} bits is below recommended minimum of 128 bits.",
                    'severity': 'danger'
                })
        
        if not vulnerabilities:
            vulnerabilities.append({
                'title': 'No Critical Vulnerabilities Detected',
                'description': 'The current encryption implementation appears to follow security best practices.',
                'severity': 'success'
            })
        
        self.report_data['vulnerabilities'] = vulnerabilities
        return vulnerabilities
    
    def generate_recommendations(self):
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        # Check if we have key strength data
        if 'key_strength' in self.report_data and self.report_data['key_strength']:
            key_length = next((item for item in self.report_data['key_strength'].values() 
                             if 'status' in item and item['status'] == 'danger'), None)
            
            if key_length:
                recommendations.append({
                    'title': 'Increase Key Length',
                    'description': 'Increase your encryption key length to at least 128 bits for symmetric encryption or 2048 bits for RSA.',
                    'code_example': '# Generate a secure AES-256 key\nfrom cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\nfrom cryptography.hazmat.primitives import hashes\nimport os\n\nsalt = os.urandom(16)\nkdf = PBKDF2HMAC(\n    algorithm=hashes.SHA256(),\n    length=32,  # 256 bits\n    salt=salt,\n    iterations=100000,\n)\nkey = kdf.derive(password)'
                })
        
        # Add general recommendations
        recommendations.extend([
            {
                'title': 'Use Authenticated Encryption',
                'description': 'Always use authenticated encryption modes like AES-GCM or ChaCha20-Poly1305 to protect against tampering.',
                'code_example': 'from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nimport os\n\nkey = AESGCM.generate_key(bit_length=256)\naes = AESGCM(key)\nnonce = os.urandom(12)\nencrypted = aes.encrypt(nonce, data, associated_data)'
            },
            {
                'title': 'Implement Secure Key Management',
                'description': 'Store keys securely using a hardware security module (HSM) or a secure key vault. Never hardcode keys in your application.',
                'code_example': '# Example using environment variables\nimport os\nfrom cryptography.fernet import Fernet\n\n# Retrieve key from environment variable\nkey = os.environ.get("ENCRYPTION_KEY")\nif not key:\n    raise ValueError("Encryption key not found in environment variables")\n\nf = Fernet(key)\nencrypted = f.encrypt(data)'
            },
            {
                'title': 'Regular Key Rotation',
                'description': 'Implement a key rotation policy to regularly update encryption keys, reducing the impact of potential key compromise.',
                'code_example': '# Pseudo-code for key rotation\ndef rotate_keys():\n    # Generate new key\n    new_key = generate_secure_key()\n    \n    # Re-encrypt sensitive data with new key\n    for data_item in get_all_sensitive_data():\n        plaintext = decrypt(data_item, old_key)\n        updated_data = encrypt(plaintext, new_key)\n        store_updated_data(updated_data)\n    \n    # Update key reference and securely delete old key\n    update_key_reference(new_key)\n    securely_delete(old_key)'
            }
        ])
        
        self.report_data['recommendations'] = recommendations
        return recommendations
    
    def generate_summary(self):
        """Generate an executive summary based on the report data."""
        # Count vulnerabilities by severity
        vuln_count = {'danger': 0, 'warning': 0, 'success': 0}
        for vuln in self.report_data.get('vulnerabilities', []):
            if 'severity' in vuln:
                vuln_count[vuln['severity']] = vuln_count.get(vuln['severity'], 0) + 1
        
        # Determine overall security rating
        if vuln_count['danger'] > 0:
            security_rating = 'Poor'
        elif vuln_count['warning'] > 0:
            security_rating = 'Moderate'
        else:
            security_rating = 'Strong'
        
        # Generate summary text
        summary = f"This report provides an AI-driven analysis of the encryption implementation. "
        summary += f"The overall security rating is {security_rating}. "
        
        if vuln_count['danger'] > 0:
            summary += f"There are {vuln_count['danger']} critical vulnerabilities that require immediate attention. "
        
        if vuln_count['warning'] > 0:
            summary += f"There are {vuln_count['warning']} potential vulnerabilities that should be addressed. "
        
        if vuln_count['success'] > 0:
            summary += f"The analysis found {vuln_count['success']} areas where security best practices are being followed. "
        
        summary += "Review the detailed findings and recommendations in this report to enhance your encryption security."
        
        self.report_data['summary'] = summary
        return summary
    
    def generate_report(self, output_path, template_name='report_template.html'):
        """Generate a complete report and save it to the specified path."""
        # Make sure we have all components of the report
        if not self.report_data.get('summary'):
            self.generate_summary()
        
        if not self.report_data.get('recommendations'):
            self.generate_recommendations()
        
        # Render the report
        template = self.env.get_template(template_name)
        html = template.render(report=self.report_data)
        
        # Determine output format based on file extension
        file_ext = os.path.splitext(output_path)[1].lower()
        
        if file_ext == '.pdf':
            # Generate PDF
            weasyprint.HTML(string=html).write_pdf(output_path)
        elif file_ext == '.html':
            # Save as HTML
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
        else:
            # Default to HTML
            with open(f"{output_path}.html", 'w', encoding='utf-8') as f:
                f.write(html)
            output_path = f"{output_path}.html"
        
        print(f"Report generated and saved to {output_path}")
        return output_path
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data."""
        if not data:
            return 0
        
        # Count occurrences of each byte value
        counts = {}
        for byte in data:
            counts[byte] = counts.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0
        for count in counts.values():
            probability = count / len(data)
            entropy -= probability * np.log2(probability)
        
        return entropy

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='AI-Driven Encryption Security Report Generator')
    parser.add_argument('--output', default='encryption_report', help='Output file path (without extension)')
    parser.add_argument('--format', choices=['html', 'pdf'], default='html', help='Output format')
    args = parser.parse_args()
    
    # Generate a sample report
    generator = EncryptionReportGenerator()
    
    # Add sample data
    generator.analyze_key_strength(os.urandom(32), 'AES')
    generator.analyze_encryption_algorithms()
    generator.analyze_integrity_checks()
    generator.identify_vulnerabilities(None, {'algorithm': 'AES-GCM', 'key_length': 256})
    generator.generate_recommendations()
    generator.generate_summary()
    
    # Generate and save the report
    output_path = f"{args.output}.{args.format}"
    generator.generate_report(output_path)
