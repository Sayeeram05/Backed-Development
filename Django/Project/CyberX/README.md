<p align="center">
  <img src="https://img.shields.io/badge/Django-6.0-green?style=for-the-badge&logo=django" />
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/PyTorch-2.0+-orange?style=for-the-badge&logo=pytorch" />
  <img src="https://img.shields.io/badge/scikit--learn-1.4+-yellow?style=for-the-badge&logo=scikit-learn" />
</p>

# CyberX - AI-Powered Cybersecurity Platform

CyberX is a full-stack Django web application that bundles **five independent security modules** into a single dashboard. Each module uses machine-learning or rule-based analysis to detect threats in real time.

| Module | Technique | Key Metric |
|--------|-----------|------------|
| **Email Validation** | Regex + DNS MX + temp-mail DB | 200+ disposable-domain list |
| **URL Threat Detection** | 3-model ML ensemble (DT, RF, ET) | 95%+ accuracy |
| **Phishing Detection** | PyTorch deep-learning MLP | 98% detection rate (87 features) |
| **Malware Analysis** | Signature + Heuristic + ML (RF, GB) | 100% ML accuracy |
| **Network IDS** | Ensemble (RF + XGBoost) on flow features | 98%+ accuracy, 7 attack classes |

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Project Structure](#project-structure)
3. [Step-by-Step Setup](#step-by-step-setup)
   - [1. Clone the Repository](#1-clone-the-repository)
   - [2. Create a Virtual Environment](#2-create-a-virtual-environment)
   - [3. Install Dependencies](#3-install-dependencies)
   - [4. Train / Obtain ML Models](#4-train--obtain-ml-models)
   - [5. Apply Migrations](#5-apply-migrations)
   - [6. Run the Development Server](#6-run-the-development-server)
4. [Module Details](#module-details)
   - [Email Validation](#email-validation)
   - [URL Threat Detection](#url-threat-detection)
   - [Phishing Detection](#phishing-detection)
   - [Malware Analysis](#malware-analysis)
   - [Network IDS](#network-ids)
5. [API Endpoints](#api-endpoints)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)
8. [Contributing](#contributing)
9. [License](#license)

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Python** | 3.10 or higher | [python.org/downloads](https://www.python.org/downloads/) |
| **pip** | Latest | Ships with Python |
| **Git** | Any recent | [git-scm.com](https://git-scm.com/) |
| **Npcap** *(Windows, optional)* | Latest | Required **only** for the Network IDS live-capture feature. [npcap.com](https://npcap.com/) - install with *"WinPcap API-compatible Mode"* checked |
| **Jupyter Notebook** *(optional)* | Any | Only needed if you want to retrain the ML models yourself |

> **Windows users:** If you plan to use the live Network IDS capture, run your terminal (or VS Code) **as Administrator** so Scapy can access network interfaces.

---

## Project Structure

```
CyberX/
+-- App/                          # Django project root
|   +-- manage.py
|   +-- db.sqlite3
|   +-- CyberX/                   # Django settings & URL config
|   |   +-- settings.py
|   |   +-- urls.py
|   |   +-- wsgi.py / asgi.py
|   +-- Home/                     # Landing page app
|   +-- EmailValidation/          # Email validation service
|   +-- UrlThreadDetection/       # URL threat scanning service
|   +-- PhisingDetection/         # Phishing URL detection service
|   |   +-- models/               # Trained phishing model files
|   +-- MalwareAnalysis/          # Malware file analysis service
|   +-- NetworkIDS/               # Network intrusion detection service
|   |   +-- models/               # Trained NIDS model files
|   +-- Frontend/                 # Shared templates, static CSS/JS
|       +-- templates/
|       +-- static/
|           +-- css/              # main.css, home.css, services.css
|           +-- js/
+-- Services/                     # ML training notebooks & model artifacts
|   +-- EmailValidation/
|   +-- MalwareAnalysis/
|   |   +-- model.ipynb
|   |   +-- models/               # Trained malware models (loaded at runtime)
|   +-- NetworkIDS/
|   |   +-- model.ipynb
|   |   +-- Dataset/
|   |   +-- models/
|   +-- Phishing-detection/
|   |   +-- Model.ipynb
|   |   +-- Dataset/
|   +-- URL threat scanning/
|       +-- Main.ipynb
|       +-- models/               # Trained URL threat models (loaded at runtime)
+-- requirements.txt
+-- .gitignore
+-- README.md
```

---

## Step-by-Step Setup

### 1. Clone the Repository

```bash
git clone https://github.com/<your-username>/CyberX.git
cd CyberX
```

### 2. Create a Virtual Environment

**Windows (PowerShell):**

```powershell
python -m venv env
.\env\Scripts\Activate.ps1
```

**Windows (Command Prompt):**

```cmd
python -m venv env
env\Scripts\activate.bat
```

**macOS / Linux:**

```bash
python3 -m venv env
source env/bin/activate
```

You should see `(env)` in your terminal prompt.

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> **Note on PyTorch:** The default `pip install torch` installs the CPU-only version. If you have an NVIDIA GPU and want faster inference for the Phishing Detection module, install PyTorch with CUDA support instead:
>
> ```bash
> pip install torch --index-url https://download.pytorch.org/whl/cu121
> ```
>
> See [pytorch.org/get-started](https://pytorch.org/get-started/locally/) for the exact command for your system.

### 4. Train / Obtain ML Models

The application loads pre-trained ML models at runtime. Some model files are large binary files and are **not** committed to Git. You have two options:

#### Option A - Train the Models Yourself (Recommended)

Each service includes a Jupyter notebook that trains and saves the required model files.

| Module | Notebook | Output Directory |
|--------|----------|-----------------|
| **URL Threat Detection** | `Services/URL threat scanning/Main.ipynb` | `Services/URL threat scanning/models/` |
| **Phishing Detection** | `Services/Phishing-detection/Model.ipynb` | `Services/Phishing-detection/` then copy to `App/PhisingDetection/models/` |
| **Malware Analysis** | `Services/MalwareAnalysis/model.ipynb` | `Services/MalwareAnalysis/models/` |
| **Network IDS** | `Services/NetworkIDS/model.ipynb` | `Services/NetworkIDS/models/` then copy to `App/NetworkIDS/models/` |

```bash
pip install jupyter
jupyter notebook
```

Open each notebook and **Run All Cells**. The trained model files will be saved to the paths listed above.

#### Option B - Copy Pre-trained Models

If you already have the `.joblib` / `.pth` / `.json` model files (from a teammate or shared drive), place them in these exact locations:

**Phishing Detection** - copy into `App/PhisingDetection/models/`:

```
App/PhisingDetection/models/
+-- phishing_model.pth
+-- phishing_scaler.joblib
+-- feature_names.json
```

**Network IDS** - copy into `App/NetworkIDS/models/`:

```
App/NetworkIDS/models/
+-- nids_model.joblib
+-- nids_scaler.joblib
+-- nids_feature_names.json
+-- nids_label_encoder.json
```

**Malware Analysis** - the app loads models from `Services/MalwareAnalysis/models/`:

```
Services/MalwareAnalysis/models/
+-- malware_rf_model.joblib
+-- malware_gb_model.joblib
+-- malware_scaler.joblib
+-- malware_feature_names.json
```

**URL Threat Detection** - the app loads models from `Services/URL threat scanning/models/`:

```
Services/URL threat scanning/models/
+-- Decision_Tree_Classifier_URL_Threat_Detection.joblib
+-- Random_Forest_Classifier_URL_Threat_Detection.joblib
+-- Extra_Trees_Classifier_URL_Threat_Detection.joblib
```

> **Important:** The Email Validation module does **not** use ML - it works out of the box with no model files.

### 5. Apply Migrations

```bash
cd App
python manage.py migrate
```

### 6. Run the Development Server

```bash
python manage.py runserver
```

Open your browser and navigate to **http://127.0.0.1:8000/**

You are all set! The CyberX dashboard should load with all five services accessible from the navigation bar.

---

## Module Details

### Email Validation

**Path:** `/emailvalidation/`

Validates email addresses through a multi-layer pipeline:

1. **Regex format check** - RFC-compliant pattern matching
2. **Library validation** - `email-validator` deep checks
3. **Temporary email detection** - 200+ disposable domain database
4. **MX record lookup** - real-time DNS verification via `dnspython`
5. **Confidence scoring** - aggregated pass/fail across all layers

**No ML models required** - works immediately after setup.

---

### URL Threat Detection

**Path:** `/urlthreatdetection/`

Analyzes URLs using a 3-model ensemble:

- Decision Tree Classifier
- Random Forest Classifier
- Extra Trees Classifier

Extracts 35+ URL features (length, special characters, TLD risk, IP usage, homograph detection, etc.) and uses majority voting across all three models.

**Model files needed:** 3 `.joblib` files in `Services/URL threat scanning/models/`

---

### Phishing Detection

**Path:** `/phishingdetection/`

Deep-learning phishing URL detector built with PyTorch:

- **Architecture:** Multi-Layer Perceptron (87 -> 300 -> 100 -> 1 sigmoid)
- **Features:** URL structural analysis, HTML content scanning (via `requests` + `BeautifulSoup`), WHOIS age, domain entropy, brand impersonation checks
- **Fallback:** If the model file is not found, the system uses heuristic scoring

**Model files needed:** `phishing_model.pth`, `phishing_scaler.joblib`, `feature_names.json` in `App/PhisingDetection/models/`

---

### Malware Analysis

**Path:** `/malwareanalysis/`

Multi-engine malware scanner that combines three detection methods:

1. **Signature-based** - MD5/SHA hash matching against known malware signatures
2. **Heuristic analysis** - 10 behavioral rules (entropy, packed executables, suspicious imports, etc.)
3. **Machine Learning** - Random Forest + Gradient Boosting ensemble on extracted features

Supports any file type. PE (`.exe`, `.dll`) files get deeper analysis via the `pefile` library.

**Model files needed:** 3 `.joblib` + 1 `.json` in `Services/MalwareAnalysis/models/`

---

### Network IDS

**Path:** `/networkids/`

Real-time network intrusion detection with two input modes:

- **PCAP Upload** - analyze captured network traffic files (`.pcap`, `.pcapng`, `.cap`)
- **Live Capture** - sniff packets directly from a network interface (requires admin privileges + Npcap on Windows)

Extracts 78 CICFlowMeter-compatible bidirectional flow features and classifies traffic as one of 7 classes: **Benign, DoS, DDoS, Port Scan, Brute Force, Web Attack, Botnet/C2**.

**Model files needed:** `nids_model.joblib`, `nids_scaler.joblib`, + 2 `.json` files in `App/NetworkIDS/models/`

> **Windows:** Install [Npcap](https://npcap.com/) with *WinPcap API-compatible Mode* for live capture.
> **Linux:** Scapy uses raw sockets - run the server with `sudo python manage.py runserver`.

---

## API Endpoints

| Method | URL | Description |
|--------|-----|-------------|
| `GET` | `/` | Home / Dashboard |
| `GET/POST` | `/emailvalidation/` | Email validation form and results |
| `GET/POST` | `/urlthreatdetection/` | URL threat scanner form and results |
| `GET/POST` | `/phishingdetection/` | Phishing URL detector form and results |
| `GET/POST` | `/malwareanalysis/` | Malware file upload and analysis |
| `GET/POST` | `/networkids/` | Network IDS (PCAP upload + live capture) |

All endpoints accept `GET` for the form page and `POST` for analysis submission.

---

## Configuration

Key settings in `App/CyberX/settings.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `DEBUG` | `True` | Set to `False` in production |
| `ALLOWED_HOSTS` | `['*']` | Restrict in production |
| `DATA_UPLOAD_MAX_MEMORY_SIZE` | `104857600` (100 MB) | Max upload size for PCAP/malware files |
| `FILE_UPLOAD_MAX_MEMORY_SIZE` | `104857600` (100 MB) | In-memory upload limit |
| Database | SQLite (`db.sqlite3`) | Default - switch to PostgreSQL for production |

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'django'`

Your virtual environment is not activated. Run:

```powershell
.\env\Scripts\Activate.ps1   # Windows PowerShell
source env/bin/activate       # macOS / Linux
```

### `ModuleNotFoundError: No module named 'scapy'`

Scapy is needed for the Network IDS module:

```bash
pip install scapy
```

### Models not loading / "ML model not loaded" warning

Ensure model files are in the correct directories (see [Step 4](#4-train--obtain-ml-models)). The services will fall back to heuristic analysis if models are missing.

### Network IDS live capture not working (Windows)

1. Install [Npcap](https://npcap.com/) with **WinPcap API-compatible Mode** enabled
2. Run your terminal / VS Code **as Administrator**
3. Ensure the `netifaces` package is installed: `pip install netifaces`

### Network IDS live capture not working (Linux/macOS)

Run Django with elevated privileges:

```bash
sudo python manage.py runserver
```

### `ImportError: No module named 'pefile'`

Required only for the Malware Analysis module PE file analysis:

```bash
pip install pefile
```

### PyTorch CUDA errors

If you get CUDA-related errors but do not have a GPU, ensure you installed CPU-only torch:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

### Port 8000 already in use

```bash
python manage.py runserver 8080   # Use a different port
```

### Static files not loading

Run collectstatic if deploying behind a web server:

```bash
python manage.py collectstatic
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m "Add your feature"`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request

---

## License

This project is for educational and research purposes.
