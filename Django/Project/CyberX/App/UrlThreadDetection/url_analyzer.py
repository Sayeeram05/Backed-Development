"""
URL Threat Detection ML Model Integration
This module contains all the functions and models for real-time URL threat analysis
"""

import re
import os
import time
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from collections import Counter
import joblib
from django.conf import settings
from tld import get_tld

class URLThreatAnalyzer:
    """Complete URL Threat Detection System with ML Models"""
    
    def __init__(self):
        self.threat_labels = {0: 'Benign', 1: 'Defacement', 2: 'Phishing', 3: 'Malware'}
        self.threat_colors = {
            'Benign': 'success',
            'Defacement': 'warning', 
            'Phishing': 'danger',
            'Malware': 'danger'
        }
        self.threat_icons = {
            'Benign': 'fas fa-shield-check',
            'Defacement': 'fas fa-exclamation-triangle',
            'Phishing': 'fas fa-fish',
            'Malware': 'fas fa-bug'
        }
        self.models = {}
        self._load_models()
    
    def _load_models(self):
        """Load the trained ML models"""
        try:
            # Model paths - use Services directory directly to avoid large file copies
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            model_dir = os.path.join(base_dir, 'Services', 'URL threat scanning', 'models')
            
            print(f"Looking for models in: {model_dir}")
            
            model_files = {
                'Decision Tree': 'Decision_Tree_Classifier_URL_Threat_Detection.joblib',
                'Random Forest': 'Random_Forest_Classifier_URL_Threat_Detection.joblib', 
                'Extra Trees': 'Extra_Trees_Classifier_URL_Threat_Detection.joblib'
            }
            
            for model_name, filename in model_files.items():
                model_path = os.path.join(model_dir, filename)
                
                if os.path.exists(model_path):
                    try:
                        print(f"Loading {model_name} from {model_path}")
                        self.models[model_name] = joblib.load(model_path)
                        print(f"✅ Successfully loaded {model_name} model")
                    except Exception as e:
                        print(f"❌ Error loading {model_name}: {str(e)}")
                else:
                    print(f"❌ Model file not found: {model_path}")
                    
            print(f"Loaded {len(self.models)} models total")
        except Exception as e:
            print(f"❌ Error in _load_models: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def having_ip_address(self, url):
        """Returns 1 if the URL contains an IP address, else 0"""
        match = re.search(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
            r'([01]?\d\d?|2[0-4]\d|25[0-5]))|'  # IPv4
            r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2}))|'  # IPv4 in hex
            r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'  # IPv6
            r'([0-9]+(?:\.[0-9]+){3}:[0-9]+)',  # IPv4 with port
            url
        )
        return 1 if match else 0
    
    def abnormal_url(self, url):
        """Check if URL has abnormal patterns"""
        try:
            hostname = urlparse(url).hostname
            if hostname:
                hostname = str(hostname)
                match = re.search(hostname, url)
                return 1 if match else 0
        except:
            return 1
        return 0
    
    def http_secure(self, url):
        """Check if URL uses HTTPS"""
        try:
            scheme = urlparse(url).scheme
            return 1 if scheme == 'https' else 0
        except:
            return 0
    
    def shortening_service(self, url):
        """Returns 1 if the URL uses a known shortening service, else 0"""
        match = re.search(
            r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
            r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
            r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
            r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
            r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
            r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
            r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
            r'tr\.im|link\.zip\.net',
            url
        )
        return 1 if match else 0
    
    def digit_count(self, url):
        """Count number of digits in URL"""
        return sum(c.isdigit() for c in url)
    
    def letter_count(self, url):
        """Count number of letters in URL"""
        return sum(c.isalpha() for c in url)
    
    def extract_features(self, url):
        """Extract all features from a URL"""
        # Add protocol if missing for proper parsing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        features = {
            'url_len': len(url),
            'having_ip_address': self.having_ip_address(url),
            'abnormal_url': self.abnormal_url(url), 
            'https': self.http_secure(url),
            'Shortining_Service': self.shortening_service(url),
            'digits': self.digit_count(url),
            'letters': self.letter_count(url)
        }
        
        # Count special characters
        special_chars = ['@','?','-','=','.','#','%','+','$','!','*',',','//']
        for char in special_chars:
            features[char] = url.count(char)
        
        return features
    
    def analyze_url(self, url):
        """
        Complete URL Threat Detection Analysis
        
        Args:
            url (str): URL to analyze
        
        Returns:
            dict: Comprehensive analysis results
        """
        start_time = time.time()
        
        try:
            original_url = url.strip()
            
            # Extract features
            features = self.extract_features(original_url)
            
            # Create DataFrame with correct column order
            expected_columns = ['url_len', '@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//', 
                               'abnormal_url', 'https', 'digits', 'letters', 'Shortining_Service', 'having_ip_address']
            
            url_df = pd.DataFrame([features])
            
            # Ensure all columns are present and in correct order
            for col in expected_columns:
                if col not in url_df.columns:
                    url_df[col] = 0
            
            url_df = url_df[expected_columns]
            
            # Model predictions
            predictions = {}
            all_preds = []
            model_results = []
            
            for model_name, model in self.models.items():
                try:
                    # Make prediction
                    pred = model.predict(url_df)[0]
                    prob = model.predict_proba(url_df)[0]
                    confidence = max(prob) * 100
                    
                    threat_type = self.threat_labels[pred]
                    
                    predictions[model_name] = {
                        'prediction': pred,
                        'threat_type': threat_type,
                        'confidence': confidence
                    }
                    
                    all_preds.append(pred)
                    
                    # Format for frontend
                    model_results.append({
                        'model': model_name,
                        'result': threat_type,
                        'confidence': round(confidence, 1),
                        'status': 'valid',
                        'icon': self.threat_icons[threat_type]
                    })
                    
                except Exception as e:
                    print(f"Error with {model_name}: {str(e)}")
                    continue
            
            if not all_preds:
                return {
                    'success': False,
                    'error': 'No models available for prediction',
                    'title': 'System Error',
                    'explanation': 'ML models are not loaded. Please check system configuration.',
                    'status_color': 'danger',
                    'status_icon': 'fas fa-exclamation-circle'
                }
            
            # Ensemble voting (majority decision)
            vote_counts = Counter(all_preds)
            ensemble_pred = vote_counts.most_common(1)[0][0]
            ensemble_confidence = (vote_counts[ensemble_pred] / len(all_preds)) * 100
            threat_type = self.threat_labels[ensemble_pred]
            
            # Calculate processing time
            processing_time = round((time.time() - start_time) * 1000, 1)
            
            # Calculate risk score (0-100)
            if ensemble_pred == 0:  # Benign
                risk_score = max(5, int(100 - ensemble_confidence))
            else:  # Malicious
                risk_score = max(75, int(ensemble_confidence))
            
            # Generate recommendation
            if ensemble_pred == 0:
                recommendation = "URL appears safe to access"
                title = "URL is Safe"
                explanation = f"Our AI models analyzed this URL and found no threats. The URL appears to be {threat_type.lower()}."
            else:
                recommendation = f"⚠️ BLOCK THIS URL - {threat_type} detected"
                title = f"⚠️ THREAT DETECTED: {threat_type}"
                explanation = f"Our AI models detected this URL as {threat_type.lower()}. Do not click or visit this URL."
            
            result = {
                'success': True,
                'url': original_url,
                'final_prediction': ensemble_pred,
                'threat_type': threat_type,
                'ensemble_confidence': round(ensemble_confidence, 1),
                'is_malicious': ensemble_pred > 0,
                'status_color': self.threat_colors[threat_type],
                'status_icon': self.threat_icons[threat_type],
                'title': title,
                'explanation': explanation,
                'recommendation': recommendation,
                'processing_time_ms': processing_time,
                'features_analyzed': len(features),
                'models_used': len(self.models),
                'risk_score': risk_score,
                'model_results': model_results,
                'individual_predictions': predictions
            }
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'title': 'Analysis Error',
                'explanation': 'An error occurred while analyzing the URL. Please try again.',
                'status_color': 'danger',
                'status_icon': 'fas fa-exclamation-circle'
            }

# Global analyzer instance
analyzer = URLThreatAnalyzer()