# 🔗 URL Threat Detection - CyberX

## Overview

The CyberX URL Threat Detection module is an AI-powered malicious URL detection system that uses ensemble machine learning to identify phishing sites, malware distribution, defacement, and other web-based threats with 95%+ accuracy.

---

## 🎯 Problem Statement

Malicious URLs are a primary vector for cyber attacks:

- **Phishing**: Fake websites stealing credentials
- **Malware**: Sites distributing viruses and trojans
- **Defacement**: Compromised websites
- **Scams**: Fraudulent sites targeting users

Our solution provides:

1. **Real-time Analysis**: Instant URL threat assessment
2. **Machine Learning**: Ensemble of 3 trained models
3. **35+ Features**: Comprehensive URL analysis
4. **Detailed Reports**: Actionable threat intelligence

---

## 🧠 Machine Learning Pipeline

### Data Collection & Preparation

```
┌─────────────────────────────────────────────────────────────────┐
│                     Data Sources                                 │
├─────────────────────────────────────────────────────────────────┤
│  • PhishTank Dataset       • Malware Domain List                │
│  • OpenPhish Database      • URLhaus Feed                       │
│  • Clean URL Database      • Alexa Top 1M (legitimate)          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Data Preprocessing                             │
├─────────────────────────────────────────────────────────────────┤
│  1. URL Parsing (protocol, domain, path, query)                 │
│  2. Feature Extraction (35+ features)                           │
│  3. Label Encoding (0=benign, 1-4=malicious types)              │
│  4. Train/Test Split (80/20)                                    │
│  5. Feature Scaling (StandardScaler)                            │
└─────────────────────────────────────────────────────────────────┘
```

### Feature Engineering (35+ Features)

#### URL Structure Features

| Feature           | Description               | Type    |
| ----------------- | ------------------------- | ------- |
| `url_length`      | Total URL character count | Numeric |
| `domain_length`   | Domain name length        | Numeric |
| `path_length`     | URL path length           | Numeric |
| `path_depth`      | Number of path segments   | Numeric |
| `query_length`    | Query string length       | Numeric |
| `fragment_length` | Fragment length           | Numeric |
| `num_subdomains`  | Count of subdomains       | Numeric |

#### Character Analysis

| Feature             | Description                      | Type    |
| ------------------- | -------------------------------- | ------- |
| `num_dots`          | Count of dots in URL             | Numeric |
| `num_hyphens`       | Count of hyphens                 | Numeric |
| `num_underscores`   | Count of underscores             | Numeric |
| `num_slashes`       | Count of forward slashes         | Numeric |
| `num_special_chars` | Special character count          | Numeric |
| `num_digits`        | Count of numeric characters      | Numeric |
| `digit_ratio`       | Ratio of digits to total length  | Numeric |
| `letter_ratio`      | Ratio of letters to total length | Numeric |

#### Domain Intelligence

| Feature            | Description                       | Type    |
| ------------------ | --------------------------------- | ------- |
| `has_ip_address`   | URL contains IP instead of domain | Binary  |
| `is_https`         | Uses HTTPS protocol               | Binary  |
| `suspicious_tld`   | Has high-risk TLD                 | Binary  |
| `is_url_shortener` | Known URL shortener               | Binary  |
| `domain_entropy`   | Randomness of domain name         | Numeric |
| `has_port`         | Non-standard port specified       | Binary  |

#### Content Indicators

| Feature                 | Description                   | Type    |
| ----------------------- | ----------------------------- | ------- |
| `has_login_keyword`     | Contains login/signin/account | Binary  |
| `has_secure_keyword`    | Contains secure/verify/update | Binary  |
| `has_brand_keyword`     | Contains known brand names    | Binary  |
| `suspicious_word_count` | Count of phishing keywords    | Numeric |
| `has_obfuscation`       | URL encoding/obfuscation      | Binary  |

### Model Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   Ensemble Learning System                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐  │
│  │  Decision Tree   │  │  Random Forest   │  │  Extra Trees  │  │
│  │   Classifier     │  │   Classifier     │  │  Classifier   │  │
│  │                  │  │                  │  │               │  │
│  │  • Max Depth: 20 │  │  • Estimators:   │  │ • Estimators: │  │
│  │  • Min Samples:5 │  │    100           │  │   100         │  │
│  │  • Criterion:    │  │  • Max Depth:    │  │ • Bootstrap:  │  │
│  │    Gini          │  │    None          │  │   False       │  │
│  └────────┬─────────┘  └────────┬─────────┘  └───────┬───────┘  │
│           │                     │                     │          │
│           └─────────────────────┼─────────────────────┘          │
│                                 │                                │
│                                 ▼                                │
│                    ┌────────────────────────┐                    │
│                    │   Ensemble Voting      │                    │
│                    │  (Weighted Average)    │                    │
│                    │                        │                    │
│                    │  DT: 30% | RF: 40%    │                    │
│                    │  ET: 30%               │                    │
│                    └────────────────────────┘                    │
│                                 │                                │
│                                 ▼                                │
│                    ┌────────────────────────┐                    │
│                    │   Final Prediction     │                    │
│                    │  + Confidence Score    │                    │
│                    └────────────────────────┘                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Training Process

```python
# 1. Load and preprocess data
df = pd.read_csv('url_dataset.csv')
X = df.drop('label', axis=1)
y = df['label']

# 2. Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 3. Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 4. Train models
models = {
    'Decision_Tree': DecisionTreeClassifier(max_depth=20, min_samples_split=5),
    'Random_Forest': RandomForestClassifier(n_estimators=100, n_jobs=-1),
    'Extra_Trees': ExtraTreesClassifier(n_estimators=100, bootstrap=False)
}

for name, model in models.items():
    model.fit(X_train_scaled, y_train)
    joblib.dump(model, f'{name}_URL_Threat_Detection.joblib')

# 5. Evaluate
for name, model in models.items():
    y_pred = model.predict(X_test_scaled)
    print(f"{name}: {accuracy_score(y_test, y_pred):.4f}")
```

### Model Performance

| Model         | Accuracy  | Precision | Recall    | F1-Score  |
| ------------- | --------- | --------- | --------- | --------- |
| Decision Tree | 93.2%     | 92.8%     | 93.5%     | 93.1%     |
| Random Forest | 96.1%     | 95.9%     | 96.3%     | 96.1%     |
| Extra Trees   | 95.8%     | 95.5%     | 96.0%     | 95.7%     |
| **Ensemble**  | **96.5%** | **96.2%** | **96.8%** | **96.5%** |

---

## 🏗️ System Architecture

### Analysis Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                      User Input (URL)                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   URL Preprocessing                              │
│  • Normalize URL (add https:// if missing)                      │
│  • Parse components (domain, path, query)                       │
│  • Extract raw features                                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                Feature Extraction Engine                         │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐          │
│  │ URL Parser  │  │ Character    │  │ Domain         │          │
│  │ Features    │  │ Analysis     │  │ Intelligence   │          │
│  └─────────────┘  └──────────────┘  └────────────────┘          │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐          │
│  │ Keyword     │  │ Entropy      │  │ Reputation     │          │
│  │ Detection   │  │ Calculator   │  │ Check          │          │
│  └─────────────┘  └──────────────┘  └────────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Feature Scaling                                 │
│            (StandardScaler - pre-trained)                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                Ensemble Model Prediction                         │
│                                                                  │
│    Decision Tree ─┬─> Weighted Vote ─> Final Prediction         │
│    Random Forest ─┤                    + Confidence              │
│    Extra Trees ───┘                                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Result Generation                              │
│  • Threat Level (safe/suspicious/malicious)                     │
│  • Confidence Score (0-100%)                                    │
│  • Threat Indicators (detailed breakdown)                       │
│  • Recommendations (security advice)                            │
└─────────────────────────────────────────────────────────────────┘
```

### File Structure

```
App/UrlThreadDetection/
├── __init__.py
├── admin.py
├── apps.py
├── models.py
├── urls.py                       # URL routing
├── views.py                      # Web views (347 lines)
├── url_analyzer_production.py    # ML analyzer engine
├── tests.py
├── migrations/
│   └── __init__.py
└── models/                       # ML model files (optional local copy)

Services/URL threat scanning/
├── Main.ipynb                    # Training notebook
├── README.md                     # Documentation
└── models/
    ├── Decision_Tree_Classifier_URL_Threat_Detection.joblib
    ├── Random_Forest_Classifier_URL_Threat_Detection.joblib
    └── Extra_Trees_Classifier_URL_Threat_Detection.joblib
```

---

## 🌐 API Reference

### Web Interface

**URL**: `/urlthreatdetection/`

**Method**: GET (display form), POST (analyze URL)

### REST API

**Endpoint**: `/urlthreatdetection/api/analyze/`

**Method**: POST

**Request**:

```json
{
  "url": "https://example.com/login"
}
```

**Response**:

```json
{
  "success": true,
  "url": "https://example.com/login",
  "domain": "example.com",
  "is_malicious": false,
  "threat_level": "safe",
  "threat_score": 12,
  "confidence": 94.5,
  "threat_type": "benign",
  "threat_indicators": [],
  "model_predictions": {
    "decision_tree": "benign",
    "random_forest": "benign",
    "extra_trees": "benign"
  },
  "features_analyzed": 35,
  "processing_time_ms": 45.2,
  "recommendations": ["URL appears safe for browsing"]
}
```

### Threat Classification

| Type       | Code | Description             |
| ---------- | ---- | ----------------------- |
| Benign     | 0    | Safe, legitimate URL    |
| Defacement | 1    | Website defacement/hack |
| Phishing   | 2    | Credential theft site   |
| Malware    | 3    | Malware distribution    |
| Spam       | 4    | Spam/advertising site   |

---

## 📊 Detection Examples

### Safe URL Analysis

```
URL: https://www.google.com
├── Threat Level: ✅ SAFE
├── Confidence: 98.2%
├── Threat Score: 5/100
├── Domain: google.com (Trusted)
├── Protocol: HTTPS ✓
└── Indicators: None
```

### Phishing URL Analysis

```
URL: http://secure-paypa1-verify.com/login
├── Threat Level: 🔴 MALICIOUS (Phishing)
├── Confidence: 96.5%
├── Threat Score: 89/100
├── Domain: secure-paypa1-verify.com
├── Protocol: HTTP (No encryption) ⚠️
└── Indicators:
    ├── Brand impersonation detected (paypal)
    ├── Suspicious domain pattern
    ├── Contains login/secure keywords
    └── New/unknown domain
```

### Suspicious URL Analysis

```
URL: http://192.168.1.1/admin/setup
├── Threat Level: ⚠️ SUSPICIOUS
├── Confidence: 72.3%
├── Threat Score: 58/100
├── Domain: 192.168.1.1 (IP Address)
├── Protocol: HTTP ⚠️
└── Indicators:
    ├── IP address instead of domain
    ├── No SSL encryption
    └── Admin path detected
```

---

## ⚙️ Configuration

### Dependencies

```txt
Django>=4.0
scikit-learn>=1.0.0
pandas>=1.5.0
numpy>=1.23.0
joblib>=1.3.0
```

### Django Settings

```python
INSTALLED_APPS = [
    ...
    'UrlThreadDetection',
]
```

### Model Paths

Models are loaded from:

```
Services/URL threat scanning/models/
├── Decision_Tree_Classifier_URL_Threat_Detection.joblib
├── Random_Forest_Classifier_URL_Threat_Detection.joblib
└── Extra_Trees_Classifier_URL_Threat_Detection.joblib
```

---

## 🔒 Security Features

### Blacklist/Whitelist

**Trusted Domains (500+)**:

- Major tech companies
- Government domains
- Educational institutions
- Known safe services

**Known Malicious Patterns**:

- URL shortener abuse patterns
- Brand impersonation patterns
- Known malware distribution domains

### Rate Limiting

Recommended production configuration:

```python
RATELIMIT_URL_ANALYSIS = '100/hour'  # Per user
RATELIMIT_API = '1000/hour'          # Per API key
```

---

## 📚 References

- [PhishTank](https://www.phishtank.com/) - Phishing URL database
- [URLhaus](https://urlhaus.abuse.ch/) - Malware URL feed
- [scikit-learn Documentation](https://scikit-learn.org/)

---

**CyberX URL Threat Detection** - AI-powered malicious URL detection for secure browsing.
