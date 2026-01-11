"""
Enhanced URL Threat Analyzer v3.0
Advanced machine learning-based URL threat detection with 35+ features
Improved accuracy and comprehensive validation features
"""

import os
import re
import time
import logging
import numpy as np
import pandas as pd
import joblib
from urllib.parse import urlparse, parse_qs
from collections import Counter

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class URLThreatAnalyzer:
    """
    Enhanced URL Threat Analyzer with advanced features and improved accuracy
    Version 3.0 with 35+ feature analysis and comprehensive validation
    """
    
    def __init__(self, models_dir='../../Services/URL threat scanning/models'):
        # Comprehensive threat intelligence databases
        self.KNOWN_MALICIOUS_TLDS = {
            '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ws', '.info', '.biz',
            '.top', '.click', '.download', '.stream', '.science', '.party', '.racing',
            '.win', '.loan', '.faith', '.accountant', '.cricket', '.date', '.review',
            '.country', '.kim', '.work', '.men', '.trade', '.webcam', '.bid'
        }
        
        self.SUSPICIOUS_KEYWORDS = [
            'login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm',
            'suspended', 'locked', 'limited', 'verification', 'security', 'alert',
            'urgent', 'immediate', 'expire', 'expires', 'click', 'here', 'now',
            'free', 'prize', 'winner', 'congratulations', 'claim', 'bonus',
            'paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook',
            'bank', 'banking', 'credit', 'card', 'payment', 'transfer'
        ]
        
        self.LEGITIMATE_DOMAINS_EXTENDED = {
            # Major Tech Companies
            'google.com', 'youtube.com', 'gmail.com', 'gstatic.com',
            'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'msn.com',
            'apple.com', 'icloud.com', 'itunes.com', 'me.com', 'mac.com',
            'amazon.com', 'aws.amazon.com', 'amazonaws.com', 'amzn.to',
            'facebook.com', 'instagram.com', 'whatsapp.com', 'fb.me',
            'twitter.com', 'x.com', 't.co', 'twimg.com',
            'linkedin.com', 'licdn.com',
            
            # Development & Tech
            'github.com', 'stackoverflow.com', 'stackexchange.com', 'gitlab.com',
            'bitbucket.org', 'sourceforge.net', 'npm.org', 'pypi.org',
            'docker.com', 'kubernetes.io', 'mozilla.org', 'firefox.com',
            
            # Educational & Reference
            'wikipedia.org', 'wikimedia.org', 'scholar.google.com', 'arxiv.org',
            'mit.edu', 'stanford.edu', 'harvard.edu', 'berkeley.edu', 'princeton.edu',
            'coursera.org', 'edx.org', 'khanacademy.org',
            
            # News & Media
            'cnn.com', 'bbc.com', 'reuters.com', 'ap.org', 'npr.org', 'pbs.org',
            'nytimes.com', 'washingtonpost.com', 'theguardian.com', 'wsj.com',
            
            # Financial Services
            'paypal.com', 'stripe.com', 'square.com', 'visa.com', 'mastercard.com',
            
            # Cloud & Services
            'dropbox.com', 'box.com', 'onedrive.com', 'mega.nz',
            'zoom.us', 'teams.microsoft.com', 'slack.com', 'discord.com',
            
            # Government
            'whitehouse.gov', 'cdc.gov', 'nih.gov', 'fda.gov'
        }
        
        self.URL_SHORTENERS_COMPREHENSIVE = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'cli.gs',
            'tiny.cc', 'url4.eu', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to',
            'ping.fm', 'post.ly', 'just.as', 'bkite.com', 'snipr.com', 'fic.kr',
            'loopt.us', 'doiop.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com',
            'om.ly', 'to.ly', 'bit.do', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly',
            'bitly.com', 'cur.lv', 'ity.im', 'q.gs', 'po.st', 'bc.vc', 'u.to',
            'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org', 'x.co',
            'scrnch.me', 'vzurl.com', 'qr.net', '1url.com', 'tweez.me', 'v.gd',
            'tr.im', 'rebrand.ly', 'buff.ly', 'hootsuite.com', 'shor.by'
        }
        
        self.models_dir = models_dir
        self.models = {}
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained ML models"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        models_path = os.path.join(current_dir, self.models_dir)
        
        logger.info(f"Looking for models in: {models_path}")
        
        model_files = {
            'Decision_Tree': 'Decision_Tree_Classifier_URL_Threat_Detection.joblib',
            'Random_Forest': 'Random_Forest_Classifier_URL_Threat_Detection.joblib',
            'Extra_Trees': 'Extra_Trees_Classifier_URL_Threat_Detection.joblib'
        }
        
        for model_name, filename in model_files.items():
            model_path = os.path.join(models_path, filename)
            if os.path.exists(model_path):
                try:
                    logger.info(f"Loading {model_name} from {model_path}")
                    self.models[model_name] = joblib.load(model_path)
                    logger.info(f"✅ Successfully loaded {model_name} model")
                except Exception as e:
                    logger.error(f"❌ Failed to load {model_name}: {str(e)}")
            else:
                logger.warning(f"❌ Model file not found: {model_path}")
        
        logger.info(f"Loaded {len(self.models)} models total")
        
        if not self.models:
            logger.warning("No models loaded - predictions will use fallback logic")
    
    def extract_advanced_features(self, url):
        """
        Extract comprehensive URL features for enhanced threat detection
        35+ advanced features for better accuracy
        """
        original_url = url
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            parsed = urlparse(url)
            features = {}
            
            # Basic URL metrics (improved)
            features['url_len'] = len(original_url)
            features['domain_len'] = len(parsed.netloc) if parsed.netloc else 0
            features['path_len'] = len(parsed.path) if parsed.path else 0
            features['query_len'] = len(parsed.query) if parsed.query else 0
            
            # Protocol analysis
            features['https'] = 1 if original_url.startswith('https://') else 0
            features['has_port'] = 1 if ':' in parsed.netloc and not parsed.netloc.endswith(':80') and not parsed.netloc.endswith(':443') else 0
            
            # Domain analysis (enhanced)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Subdomain analysis
            domain_parts = domain.split('.')
            features['subdomain_count'] = max(0, len(domain_parts) - 2) if len(domain_parts) > 1 else 0
            features['domain_depth'] = len(domain_parts)
            
            # TLD analysis
            features['tld_suspicious'] = 0
            features['tld_len'] = 0
            try:
                if '.' in domain:
                    tld_part = '.' + domain.split('.')[-1]
                    features['tld_suspicious'] = 1 if tld_part in self.KNOWN_MALICIOUS_TLDS else 0
                    features['tld_len'] = len(tld_part)
            except:
                features['tld_suspicious'] = 0
                features['tld_len'] = 0
            
            # IP address detection (enhanced)
            ip_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
            features['having_ip_address'] = 1 if re.search(ip_pattern, domain) else 0
            
            # URL shortener detection (comprehensive)
            features['is_shortener'] = 1 if any(shortener in domain for shortener in self.URL_SHORTENERS_COMPREHENSIVE) else 0
            features['Shortining_Service'] = features['is_shortener']  # Legacy compatibility
            
            # Character analysis (enhanced)
            features['digits'] = sum(1 for c in original_url if c.isdigit())
            features['letters'] = sum(1 for c in original_url if c.isalpha())
            features['digit_ratio'] = features['digits'] / len(original_url) if len(original_url) > 0 else 0
            features['letter_ratio'] = features['letters'] / len(original_url) if len(original_url) > 0 else 0
            
            # Special character counts and analysis
            special_chars = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//', '&', '_', '~']
            for char in special_chars:
                features[char] = original_url.count(char)
            
            features['special_char_count'] = sum(features.get(char, 0) for char in special_chars)
            features['hyphen_ratio'] = features.get('-', 0) / features['domain_len'] if features['domain_len'] > 0 else 0
            
            # Suspicious pattern detection
            features['suspicious_keywords'] = sum(1 for keyword in self.SUSPICIOUS_KEYWORDS if keyword.lower() in original_url.lower())
            features['multiple_subdomains'] = 1 if features['subdomain_count'] > 2 else 0
            features['long_domain'] = 1 if features['domain_len'] > 20 else 0
            features['many_dots'] = 1 if features.get('.', 0) > 4 else 0
            
            # URL structure analysis
            features['path_depth'] = len([p for p in parsed.path.split('/') if p]) if parsed.path else 0
            features['has_query'] = 1 if parsed.query else 0
            features['query_params'] = len(parse_qs(parsed.query)) if parsed.query else 0
            features['has_fragment'] = 1 if parsed.fragment else 0
            
            # Security indicators
            features['double_slash_redirect'] = 1 if '//' in parsed.path else 0
            features['at_symbol'] = 1 if '@' in original_url else 0
            features['abnormal_url'] = 1 if domain and domain not in original_url.replace(f'//{parsed.netloc}', '') else 0
            
            # Advanced threat indicators
            features['hex_chars'] = len(re.findall(r'[0-9a-fA-F]{8,}', original_url))  # Long hex strings
            features['random_string'] = 1 if re.search(r'[a-zA-Z0-9]{20,}', domain) else 0  # Random-looking strings
            features['punycode'] = 1 if 'xn--' in domain else 0  # Internationalized domains
            
            # Brand impersonation detection (advanced)
            brand_keywords = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook', 'netflix', 'bank']
            features['brand_spoofing'] = 1 if any(brand in domain.lower() and domain not in self.LEGITIMATE_DOMAINS_EXTENDED for brand in brand_keywords) else 0
            
            # Simple entropy calculation (randomness measure)
            def simple_entropy(s):
                if not s or len(s) < 2:
                    return 0
                try:
                    entropy = 0
                    for char in set(s):
                        p = s.count(char) / len(s)
                        if p > 0:
                            entropy += p * (-1 * (p * 10))  # Simplified calculation
                    return min(entropy, 10)  # Cap at 10
                except:
                    return 0
            
            features['domain_entropy'] = simple_entropy(domain) if domain else 0
            features['path_entropy'] = simple_entropy(parsed.path) if parsed.path else 0
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            # Return safe defaults
            default_features = {
                'url_len': len(original_url), 'domain_len': 0, 'path_len': 0, 'query_len': 0,
                'https': 0, 'has_port': 0, 'subdomain_count': 0, 'domain_depth': 0,
                'tld_suspicious': 0, 'tld_len': 0, 'having_ip_address': 0, 'is_shortener': 0,
                'Shortining_Service': 0, 'digits': 0, 'letters': 0, 'digit_ratio': 0,
                'letter_ratio': 0, 'special_char_count': 0, 'hyphen_ratio': 0,
                'suspicious_keywords': 0, 'multiple_subdomains': 0, 'long_domain': 0,
                'many_dots': 0, 'path_depth': 0, 'has_query': 0, 'query_params': 0,
                'has_fragment': 0, 'double_slash_redirect': 0, 'at_symbol': 0,
                'abnormal_url': 0, 'hex_chars': 0, 'random_string': 0, 'punycode': 0,
                'brand_spoofing': 0, 'domain_entropy': 0, 'path_entropy': 0
            }
            # Add special characters
            for char in ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//', '&', '_', '~']:
                default_features[char] = 0
            return default_features
    
    def is_legitimate_domain_advanced(self, url):
        """
        Advanced legitimate domain detection with extended whitelist
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            domain = urlparse(url).netloc.lower().replace('www.', '')
            
            # Direct match check
            if domain in self.LEGITIMATE_DOMAINS_EXTENDED:
                return True, 'direct_match'
            
            # TLD-based check for government and educational domains
            if domain.endswith('.gov') or domain.endswith('.edu') or domain.endswith('.mil'):
                return True, 'government_educational'
            
            # Major domain suffix check
            major_domains = ['.google.', '.microsoft.', '.amazon.', '.apple.', '.facebook.']
            if any(major in domain for major in major_domains):
                return True, 'major_domain_suffix'
            
            return False, 'unknown'
            
        except:
            return False, 'error'
    
    def analyze_url(self, url, confidence_threshold=0.70):
        """
        Main method to analyze URL threat level with enhanced features
        """
        try:
            start_time = time.time()
            
            # Quick legitimate domain check
            is_legit, reason = self.is_legitimate_domain_advanced(url)
            if is_legit:
                validation_features = {
                    'domain_whitelist': True,
                    'ip_address_detected': False,
                    'url_shortener': False,
                    'suspicious_tld': False,
                    'brand_spoofing_risk': False,
                    'multiple_subdomains': False,
                    'suspicious_keywords_count': 0,
                    'domain_entropy': 0,
                    'https_enabled': url.startswith('https://'),
                    'port_analysis': False,
                    'url_length_analysis': 'normal',
                    'risk_score': 0,
                    'government_domain': reason == 'government_educational',
                    'major_tech_domain': reason in ['direct_match', 'major_domain_suffix']
                }
                
                return {
                    'url': url,
                    'threat_type': 'Benign',
                    'confidence': 95.0,
                    'ensemble_confidence': 95.0,
                    'is_malicious': False,
                    'reason': f'whitelisted_{reason}',
                    'processing_time': time.time() - start_time,
                    'validation_features': validation_features,
                    'individual_predictions': {},
                    'risk_factors': 0
                }
            
            # Extract advanced features
            features = self.extract_advanced_features(url)
            
            # Create DataFrame with proper structure
            url_df = pd.DataFrame([features])
            
            # Ensure all required columns exist for legacy model compatibility
            legacy_columns = ['url_len', '@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//', 
                             'abnormal_url', 'https', 'digits', 'letters', 'Shortining_Service', 'having_ip_address']
            
            # Add missing legacy columns and reorder
            for col in legacy_columns:
                if col not in url_df.columns:
                    url_df[col] = 0
            url_df = url_df[legacy_columns]
            
            if not self.models:
                # Fallback logic if no models available
                return self._fallback_analysis(url, features, start_time)
            
            # Model predictions with enhanced logic
            predictions = {}
            all_preds = []
            all_confidences = []
            all_probabilities = []
            
            for model_name, model in self.models.items():
                try:
                    pred = model.predict(url_df)[0]
                    prob = model.predict_proba(url_df)[0]
                    confidence = max(prob) * 100
                    
                    predictions[model_name] = {
                        'prediction': pred,
                        'threat_type': {0: 'Benign', 1: 'Defacement', 2: 'Phishing', 3: 'Malware'}[pred],
                        'confidence': confidence
                    }
                    
                    all_preds.append(pred)
                    all_confidences.append(confidence)
                    all_probabilities.append(prob)
                    
                except Exception as e:
                    logger.error(f"Error with {model_name}: {str(e)}")
                    continue
            
            if not all_preds:
                return self._fallback_analysis(url, features, start_time)
            
            # Advanced ensemble voting with probability weighting
            threat_labels = {0: 'Benign', 1: 'Defacement', 2: 'Phishing', 3: 'Malware'}
            
            # Weighted average of probabilities
            avg_probabilities = np.mean(all_probabilities, axis=0)
            ensemble_pred = np.argmax(avg_probabilities)
            ensemble_confidence = avg_probabilities[ensemble_pred] * 100
            
            # Agreement calculation
            vote_counts = Counter(all_preds)
            agreement = (vote_counts[ensemble_pred] / len(all_preds)) * 100
            
            # Advanced confidence adjustment based on feature analysis
            risk_factors = 0
            if features.get('having_ip_address', 0) == 1:
                risk_factors += 1
            if features.get('is_shortener', 0) == 1:
                risk_factors += 1
            if features.get('suspicious_keywords', 0) > 2:
                risk_factors += 1
            if features.get('brand_spoofing', 0) == 1:
                risk_factors += 2  # Higher weight for brand spoofing
            if features.get('tld_suspicious', 0) == 1:
                risk_factors += 1
            
            # Adjust confidence based on risk factors
            if ensemble_pred > 0:  # If predicted as malicious
                ensemble_confidence = min(95, ensemble_confidence + (risk_factors * 5))
            else:  # If predicted as benign
                if risk_factors > 2:
                    ensemble_confidence = max(60, ensemble_confidence - (risk_factors * 10))
            
            # Apply stricter threshold for malicious classification
            if ensemble_pred > 0 and ensemble_confidence < confidence_threshold * 100:
                ensemble_pred = 0
                ensemble_confidence = 65.0
            
            processing_time = time.time() - start_time
            
            # Detailed validation features
            validation_features = {
                'domain_whitelist': False,
                'ip_address_detected': features.get('having_ip_address', 0) == 1,
                'url_shortener': features.get('is_shortener', 0) == 1,
                'suspicious_tld': features.get('tld_suspicious', 0) == 1,
                'brand_spoofing_risk': features.get('brand_spoofing', 0) == 1,
                'multiple_subdomains': features.get('multiple_subdomains', 0) == 1,
                'suspicious_keywords_count': features.get('suspicious_keywords', 0),
                'domain_entropy': features.get('domain_entropy', 0),
                'https_enabled': features.get('https', 0) == 1,
                'port_analysis': features.get('has_port', 0) == 1,
                'url_length_analysis': 'long' if features.get('url_len', 0) > 75 else 'normal',
                'risk_score': (risk_factors / 7) * 100,  # Risk score out of 100
                'government_domain': False,
                'major_tech_domain': False
            }
            
            result = {
                'url': url,
                'threat_type': threat_labels[ensemble_pred],
                'confidence': ensemble_confidence,
                'ensemble_confidence': ensemble_confidence,
                'agreement': agreement,
                'individual_predictions': predictions,
                'is_malicious': ensemble_pred > 0,
                'risk_factors': risk_factors,
                'processing_time': processing_time,
                'validation_features': validation_features
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            return {
                'error': f'Analysis failed: {str(e)}',
                'url': url,
                'threat_type': 'Unknown',
                'is_malicious': False,
                'confidence': 0
            }
    
    def _fallback_analysis(self, url, features, start_time):
        """
        Fallback analysis when no models are available
        Uses rule-based logic with advanced features
        """
        risk_score = 0
        
        # Risk factors based on features
        if features.get('having_ip_address', 0) == 1:
            risk_score += 25
        if features.get('is_shortener', 0) == 1:
            risk_score += 20
        if features.get('suspicious_keywords', 0) > 2:
            risk_score += 20
        if features.get('brand_spoofing', 0) == 1:
            risk_score += 30
        if features.get('tld_suspicious', 0) == 1:
            risk_score += 15
        if features.get('abnormal_url', 0) == 1:
            risk_score += 10
        
        is_malicious = risk_score > 50
        threat_type = 'Phishing' if risk_score > 70 else ('Suspicious' if is_malicious else 'Benign')
        
        validation_features = {
            'domain_whitelist': False,
            'ip_address_detected': features.get('having_ip_address', 0) == 1,
            'url_shortener': features.get('is_shortener', 0) == 1,
            'suspicious_tld': features.get('tld_suspicious', 0) == 1,
            'brand_spoofing_risk': features.get('brand_spoofing', 0) == 1,
            'multiple_subdomains': features.get('multiple_subdomains', 0) == 1,
            'suspicious_keywords_count': features.get('suspicious_keywords', 0),
            'domain_entropy': features.get('domain_entropy', 0),
            'https_enabled': features.get('https', 0) == 1,
            'port_analysis': features.get('has_port', 0) == 1,
            'url_length_analysis': 'long' if features.get('url_len', 0) > 75 else 'normal',
            'risk_score': risk_score,
            'government_domain': False,
            'major_tech_domain': False
        }
        
        return {
            'url': url,
            'threat_type': threat_type,
            'confidence': min(95, max(55, 100 - risk_score)),
            'ensemble_confidence': min(95, max(55, 100 - risk_score)),
            'is_malicious': is_malicious,
            'reason': 'fallback_analysis',
            'processing_time': time.time() - start_time,
            'validation_features': validation_features,
            'individual_predictions': {},
            'risk_factors': risk_score // 15
        }

# Create analyzer instance
analyzer = URLThreatAnalyzer()