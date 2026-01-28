# 🛡️ CyberX - Advanced Cybersecurity Platform

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Django-6.0-green.svg" alt="Django">
  <img src="https://img.shields.io/badge/PyTorch-2.0%2B-red.svg" alt="PyTorch">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Accuracy-95%25%2B-brightgreen.svg" alt="Accuracy">
</p>

<p align="center">
  <b>AI-powered cybersecurity platform for URL threat detection, phishing analysis, and email validation</b>
</p>

---

## 📋 Table of Contents

1. [Overview](#-overview)
2. [Features](#-features)
3. [Architecture](#-architecture)
4. [Installation](#-installation)
5. [Usage](#-usage)
6. [API Reference](#-api-reference)
7. [Machine Learning](#-machine-learning)
8. [Project Structure](#-project-structure)
9. [Configuration](#-configuration)
10. [Contributing](#-contributing)

---

## 🚀 Overview

CyberX is a comprehensive cybersecurity platform that combines multiple AI/ML models to provide real-time threat detection and validation services. Built with Django 6.0 and powered by machine learning, it offers three core security modules:

| Module                      | Description                         | Technology             | Accuracy |
| --------------------------- | ----------------------------------- | ---------------------- | -------- |
| 🔗 **URL Threat Detection** | Malicious URL identification        | Ensemble ML (3 models) | 95%+     |
| 🎣 **Phishing Detection**   | Phishing website analysis           | PyTorch Neural Network | 95%+     |
| 📧 **Email Validation**     | Email verification & temp detection | Pattern + DNS Analysis | 99%+     |

### Why CyberX?

- **Real-time Analysis**: Instant threat assessment in milliseconds
- **Multi-layer Security**: Three independent security modules working together
- **AI-Powered**: State-of-the-art machine learning models
- **Production Ready**: Built for scalability and reliability
- **Beautiful UI**: Modern, responsive web interface
- **REST APIs**: Easy integration with existing systems

---

## ✨ Features

### 🔗 URL Threat Detection

Analyzes URLs using an ensemble of three machine learning models:

- **Decision Tree Classifier**: Fast pattern-based detection
- **Random Forest Classifier**: Robust multi-tree voting
- **Extra Trees Classifier**: Additional ensemble diversity

**Capabilities**:

- Phishing site detection
- Malware distribution identification
- Website defacement recognition
- 35+ URL features analyzed
- Ensemble voting for accuracy

### 🎣 Phishing Detection

Deep learning-powered phishing analysis using PyTorch:

- **87 Feature Analysis**: Comprehensive URL examination
- **Neural Network**: 3-layer deep learning model
- **Trusted Domain Recognition**: Zero false positives for major sites
- **Real-time WHOIS**: Domain age and registration checking
- **DNS Validation**: Live DNS record verification

### 📧 Email Validation

Multi-layer email verification system:

- **300+ Temporary Domains**: Comprehensive disposable email database
- **DNS/MX Verification**: Real-time mail server checking
- **RFC 5322 Compliance**: Standards-based syntax validation
- **Quality Scoring**: 0-100 email quality assessment
- **Pattern Detection**: Advanced regex for evolving services

---

## 🏗️ Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CyberX Platform                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                        Django 6.0 Backend                        │   │
│  │                                                                   │   │
│  │   ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │   │
│  │   │    URL      │   │  Phishing   │   │      Email          │   │   │
│  │   │   Threat    │   │  Detection  │   │    Validation       │   │   │
│  │   │  Detection  │   │             │   │                     │   │   │
│  │   │             │   │             │   │                     │   │   │
│  │   │ • 3 Models  │   │ • PyTorch   │   │ • 300+ domains     │   │   │
│  │   │ • 35 feats  │   │ • 87 feats  │   │ • DNS lookup       │   │   │
│  │   │ • Ensemble  │   │ • Deep NN   │   │ • Pattern match    │   │   │
│  │   └─────────────┘   └─────────────┘   └─────────────────────┘   │   │
│  │                                                                   │   │
│  │                     ┌─────────────────────┐                      │   │
│  │                     │    REST APIs        │                      │   │
│  │                     │  • /api/analyze/    │                      │   │
│  │                     │  • /api/validate/   │                      │   │
│  │                     └─────────────────────┘                      │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                      Frontend (HTML/CSS/JS)                       │   │
│  │                                                                   │   │
│  │   • Responsive Design      • Real-time Feedback                  │   │
│  │   • Modern UI/UX           • Interactive Results                 │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    Machine Learning Models                        │   │
│  │                                                                   │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────┐  │   │
│  │  │ Decision Tree   │  │ Random Forest   │  │  Extra Trees     │  │   │
│  │  │ (.joblib)       │  │ (.joblib)       │  │  (.joblib)       │  │   │
│  │  └─────────────────┘  └─────────────────┘  └──────────────────┘  │   │
│  │                                                                   │   │
│  │  ┌─────────────────┐  ┌─────────────────┐                        │   │
│  │  │ PyTorch Model   │  │ Feature Scaler  │                        │   │
│  │  │ (.pth)          │  │ (.joblib)       │                        │   │
│  │  └─────────────────┘  └─────────────────┘                        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer               | Technology                               |
| ------------------- | ---------------------------------------- |
| **Backend**         | Django 6.0, Python 3.8+                  |
| **ML Framework**    | PyTorch, scikit-learn                    |
| **Data Processing** | pandas, numpy                            |
| **DNS/Email**       | dnspython, email-validator               |
| **URL Analysis**    | tldextract, beautifulsoup4, python-whois |
| **Database**        | SQLite (dev), PostgreSQL (prod)          |
| **Frontend**        | HTML5, CSS3, JavaScript ES6+             |

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git
- Virtual environment support

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/cyberx.git
cd cyberx

# 2. Create virtual environment
python -m venv env

# 3. Activate virtual environment
# Windows:
env\Scripts\activate
# macOS/Linux:
source env/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Navigate to App directory
cd App

# 6. Run migrations
python manage.py migrate

# 7. Start development server
python manage.py runserver

# 8. Open browser
# http://127.0.0.1:8000/
```

### Verify Installation

After starting the server, you should see:

```
✅ Using enhanced production URL analyzer v3.0
System check identified no issues (0 silenced).
Django version 6.0, using settings 'CyberX.settings'
Starting development server at http://127.0.0.1:8000/
```

---

## 💻 Usage

### Web Interface

| Module                   | URL                                         | Description              |
| ------------------------ | ------------------------------------------- | ------------------------ |
| **Home**                 | `http://127.0.0.1:8000/`                    | Main dashboard           |
| **URL Threat Detection** | `http://127.0.0.1:8000/urlthreatdetection/` | Analyze URLs for threats |
| **Phishing Detection**   | `http://127.0.0.1:8000/phishingdetection/`  | Check for phishing       |
| **Email Validation**     | `http://127.0.0.1:8000/emailvalidation/`    | Validate emails          |

### Example Workflows

#### Analyzing a URL for Threats

1. Go to `/urlthreatdetection/`
2. Enter URL: `https://example.com`
3. Click "Analyze"
4. View threat level, confidence, and indicators

#### Checking for Phishing

1. Go to `/phishingdetection/`
2. Enter suspicious URL
3. Get instant risk assessment
4. Review risk factors and recommendations

#### Validating an Email

1. Go to `/emailvalidation/`
2. Enter email address
3. View validation results
4. Check if it's a temporary email

---

## 🔌 API Reference

### URL Threat Detection API

```bash
POST /urlthreatdetection/api/analyze/
Content-Type: application/json

{
    "url": "https://example.com"
}
```

**Response**:

```json
{
  "success": true,
  "url": "https://example.com",
  "is_malicious": false,
  "threat_level": "safe",
  "threat_score": 12,
  "confidence": 94.5,
  "threat_indicators": [],
  "processing_time_ms": 45.2
}
```

### Phishing Detection API

```bash
POST /phishingdetection/api/analyze/
Content-Type: application/json

{
    "url": "https://suspicious-site.com"
}
```

**Response**:

```json
{
  "success": true,
  "url": "https://suspicious-site.com",
  "is_phishing": true,
  "confidence": 92.3,
  "risk_score": 78,
  "risk_factors": ["Suspicious TLD detected", "New domain (15 days old)"],
  "security_indicators": [],
  "model_used": true
}
```

### Email Validation API

```bash
POST /emailvalidation/api/validate/
Content-Type: application/json

{
    "email": "user@example.com"
}
```

**Response**:

```json
{
  "success": true,
  "email": "user@example.com",
  "is_valid": true,
  "is_temporary": false,
  "quality_score": 95,
  "risk_level": "low",
  "validation": {
    "syntax": { "valid": true },
    "dns": { "valid": true, "has_mx": true }
  }
}
```

---

## 🧠 Machine Learning

### URL Threat Detection Models

| Model        | Algorithm       | Features | Accuracy  |
| ------------ | --------------- | -------- | --------- |
| Model 1      | Decision Tree   | 35       | 93.2%     |
| Model 2      | Random Forest   | 35       | 96.1%     |
| Model 3      | Extra Trees     | 35       | 95.8%     |
| **Ensemble** | Weighted Voting | 35       | **96.5%** |

### Phishing Detection Neural Network

```
Architecture:
├── Input Layer: 87 features
├── Hidden Layer 1: 300 neurons (ReLU + BatchNorm)
├── Hidden Layer 2: 100 neurons (ReLU + BatchNorm + Dropout)
└── Output Layer: 1 neuron (Sigmoid)

Training:
├── Dataset: 11,431 URLs
├── Split: 80% train, 20% test
├── Optimizer: Adam (lr=0.001)
├── Loss: Binary Cross-Entropy
└── Epochs: 100 (early stopping)

Performance:
├── Accuracy: ~95%
├── Precision: ~94%
├── Recall: ~96%
└── F1-Score: ~95%
```

### Feature Importance (Top 10)

| Rank | Feature              | Importance |
| ---- | -------------------- | ---------- |
| 1    | `domain_age`         | 0.085      |
| 2    | `https_token`        | 0.078      |
| 3    | `nb_subdomains`      | 0.065      |
| 4    | `length_url`         | 0.058      |
| 5    | `dns_record`         | 0.055      |
| 6    | `shortening_service` | 0.052      |
| 7    | `phish_hints`        | 0.048      |
| 8    | `ip`                 | 0.045      |
| 9    | `suspicious_tld`     | 0.042      |
| 10   | `login_form`         | 0.038      |

---

## 📁 Project Structure

```
CyberX/
├── App/                              # Django Application
│   ├── CyberX/                       # Main Django project
│   │   ├── __init__.py
│   │   ├── settings.py               # Django settings
│   │   ├── urls.py                   # Main URL routing
│   │   ├── wsgi.py                   # WSGI config
│   │   └── asgi.py                   # ASGI config
│   │
│   ├── Home/                         # Home app
│   │   ├── views.py
│   │   └── urls.py
│   │
│   ├── EmailValidation/              # Email validation module
│   │   ├── views.py                  # Validation logic (655 lines)
│   │   ├── urls.py
│   │   └── README.md                 # Module documentation
│   │
│   ├── UrlThreadDetection/           # URL threat detection module
│   │   ├── views.py                  # View handlers (347 lines)
│   │   ├── url_analyzer_production.py # ML analyzer
│   │   ├── urls.py
│   │   └── README.md                 # Module documentation
│   │
│   ├── PhisingDetection/             # Phishing detection module
│   │   ├── views.py                  # View handlers (605 lines)
│   │   ├── feature_extractor.py      # 87-feature extraction
│   │   ├── urls.py
│   │   ├── README.md                 # Module documentation
│   │   └── models/                   # Model files
│   │       ├── phishing_model.pth    # PyTorch model
│   │       ├── phishing_scaler.joblib # Feature scaler
│   │       └── feature_names.json    # Feature reference
│   │
│   ├── Frontend/                     # Frontend templates
│   │   ├── templates/
│   │   │   ├── base.html             # Base template
│   │   │   ├── home.html             # Home page
│   │   │   ├── EmailValidation.html  # Email validation UI
│   │   │   ├── URLThreatDetection.html # URL detection UI
│   │   │   └── PhishingDetection.html # Phishing detection UI
│   │   └── static/
│   │       ├── css/                  # Stylesheets
│   │       └── js/                   # JavaScript
│   │
│   ├── manage.py                     # Django management
│   └── db.sqlite3                    # Development database
│
├── Services/                         # ML Training Services
│   ├── EmailValidation/
│   │   ├── Main.ipynb                # Email validation notebook
│   │   └── README.md
│   │
│   ├── Phishing-detection/
│   │   ├── Model.ipynb               # Model training notebook
│   │   ├── Dataset/                  # Training data
│   │   ├── phishing_model.pth        # Trained model
│   │   ├── phishing_scaler.joblib    # Fitted scaler
│   │   └── feature_names.json        # Feature names
│   │
│   └── URL threat scanning/
│       ├── Main.ipynb                # Training notebook
│       ├── README.md
│       └── models/                   # Trained models
│           ├── Decision_Tree_*.joblib
│           ├── Random_Forest_*.joblib
│           └── Extra_Trees_*.joblib
│
├── env/                              # Virtual environment
├── requirements.txt                  # Python dependencies
├── README.md                         # This file
└── .gitignore                        # Git ignore rules
```

---

## ⚙️ Configuration

### Dependencies (requirements.txt)

```txt
# Django
Django>=6.0

# Machine Learning
torch>=2.0.0
scikit-learn>=1.8.0
pandas>=2.0.0
numpy>=1.23.0
joblib>=1.3.0

# URL/Domain Analysis
tldextract>=3.0.0
beautifulsoup4>=4.11.0
python-whois>=0.8.0
requests>=2.28.0

# DNS/Email
dnspython>=2.3.0
email-validator>=2.0.0
```

### Environment Variables (Production)

```bash
# Django
SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=your-domain.com

# Database
DATABASE_URL=postgres://user:pass@host:5432/dbname

# Security
CSRF_TRUSTED_ORIGINS=https://your-domain.com
```

### Django Settings Highlights

```python
# settings.py

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # CyberX Apps
    'Home',
    'EmailValidation',
    'UrlThreadDetection',
    'PhisingDetection',
    'Frontend',
]

# Template Configuration
TEMPLATES = [
    {
        'DIRS': [BASE_DIR / 'Frontend' / 'templates'],
        ...
    },
]

# Static Files
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'Frontend' / 'static']
```

---

## 🤝 Contributing

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Reporting Issues

- Use GitHub Issues for bug reports
- Include reproduction steps
- Provide system information

### Development Setup

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
python manage.py test

# Check code style
flake8 .

# Format code
black .
```

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [PhishTank](https://phishtank.org/) - Phishing URL database
- [Kaggle](https://kaggle.com/) - Phishing detection dataset
- [URLhaus](https://urlhaus.abuse.ch/) - Malware URL feed
- Django & PyTorch communities

---

## 📞 Support

- **Documentation**: Check individual module READMEs
- **Issues**: [GitHub Issues](https://github.com/yourusername/cyberx/issues)
- **Email**: support@cyberx.example.com

---

<p align="center">
  <b>CyberX</b> - Protecting users with AI-powered cybersecurity
  <br><br>
  Made with ❤️ for a safer internet
</p>
