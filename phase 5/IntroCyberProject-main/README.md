# AI-Driven Encryption Framework

## 📌 Project Overview

This comprehensive AI-powered encryption framework enhances traditional encryption methods, automates cryptographic key management, and detects vulnerabilities in encrypted data. The project is structured into five complementary phases, each building upon the previous to create a complete security solution.

## 🔐 Key Features

- AI-enhanced cryptanalysis for vulnerability detection
- Machine learning-optimized cryptographic key generation
- AI-driven encryption algorithm optimization
- Deep learning-based tampering detection
- Automated security reporting and recommendation system
- Web-based secure file encryption/decryption interface

## 🏗️ Project Structure

This project is organized into five distinct phases:

### Phase 1: AI-Enhanced Cryptanalysis & Security Assessment
- Implements AI-based cryptanalysis to detect weaknesses in ciphers
- Uses machine learning models to predict weak keys and identify patterns
- Includes tools for testing encryption security

### Phase 2: AI-Powered Key Generation & Management
- Develops AI-generated cryptographic keys that optimize entropy
- Implements a Reinforcement Learning model to enhance key randomness
- Integrates quantum-resistant key exchange mechanisms

### Phase 3: AI-Optimized Data Encryption & Decryption
- Implements AES, RSA, and ECC encryption with AI-driven optimizations
- Optimizes encryption speed and security with adaptive algorithms
- Includes benchmarking tools for performance testing

### Phase 4: AI-Assisted Encrypted Data Integrity & Authentication
- Implements AI-based integrity checks for encrypted data
- Trains deep learning models to detect tampering or unauthorized modifications
- Uses advanced hashing and digital signatures for verification

### Phase 5: AI-Generated Encryption Report & Deployment
- Provides a web interface for secure file encryption and decryption
- Generates comprehensive AI-powered security reports
- Offers actionable recommendations for security improvements

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation Steps

1. Clone the repository
```bash
git clone https://github.com/yourusername/ProjetCyber.git
cd ProjetCyber
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

3. Set up environment variables for secure key storage
```bash
# On Windows
setx ENCRYPTION_KEY_PATH "C:\secure\path\to\keys"

# On Linux/macOS
export ENCRYPTION_KEY_PATH="/secure/path/to/keys"
```

## 🚀 Usage

### Running the Web Interface (Phase 5)

```bash
cd phase-5
python app.py
```

This will start the Flask application on http://localhost:5000

### Using Individual Components

#### Phase 1: Cryptanalysis
```bash
cd phase-1
python cryptanalysis_tool.py --file your_encrypted_file.bin
```

#### Phase 2: Key Generation
```bash
cd phase-2
python main_pipeline.py --key-type aes-256
```

#### Phase 3: Encryption/Decryption
```bash
cd phase-3
python benchmark.py --algorithm aes --mode gcm
```

#### Phase 4: Integrity Checking
```bash
cd phase-4
python file_integrity_app.py protect your_file.txt --key your_secret_key
```

## 🔒 Security Recommendations

1. **Key Management**: Always store encryption keys securely, using hardware security modules (HSMs) or secure key vaults when possible.

2. **Regular Updates**: Keep all dependencies updated to protect against vulnerabilities.

3. **Quantum Readiness**: Consider using post-quantum cryptographic algorithms for long-term data protection.

4. **Secure Deployment**: When deploying the web interface, use HTTPS and proper authentication mechanisms.

5. **Key Rotation**: Implement regular key rotation to minimize the impact of potential key compromise.

## 📚 Resources

- [Cryptography and Network Security – William Stallings](https://www.pearson.com/us/higher-education/program/Stallings-Cryptography-and-Network-Security-Principles-and-Practice-7th-Edition/PGM322599.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/Projects/Cryptographic-Standards-and-Guidelines)
- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/en/latest/)
- [TensorFlow Documentation](https://www.tensorflow.org/api_docs)

## 🙋 Contributing

Contributions to improve the project are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔍 Authors

- **[Adama Mentagui]** - *AI powered encryption framework* - [adamo349341](https://github.com/adamo349341)
- **[Adeshero]** - *AI powered encryption framework* - [adeshero](https://github.com/adeshero)
- **[Hamza3-sys]** - *AI powered encryption framework* - [Hamza3-sys](https://github.com/Hamza3-sys)
- **[YoussefMisaoui]** - *AI powered encryption framework* - [YoussefMisaoui](https://github.com/YoussefMisaoui)
- **[zakariakharroubi21]** - *AI powered encryption framework* - [zakariakharroubi21](https://github.com/zakariakharroubi21)

## 🙏 Acknowledgments

- The Windsurf engineering team for inspiration and guidance
- Open-source cryptography and machine learning communities
- NIST for cryptographic standards and guidelines
