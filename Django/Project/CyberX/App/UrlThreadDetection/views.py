from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib import messages
import re
import os
import time
import json
import logging
from urllib.parse import urlparse

# Import the enhanced URL analyzer
try:
    from .url_analyzer_production import analyzer
    print("✅ Using enhanced production URL analyzer v3.0")
except ImportError:
    try:
        from .url_analyzer_fixed import analyzer
        print("⚠️  Using fallback fixed URL analyzer")
    except ImportError:
        # Last resort fallback to original if enhanced versions not available
        from .url_analyzer import analyzer
        print("⚠️  Using original URL analyzer")

logger = logging.getLogger('UrlThreatDetection')

def url_threat_detection_view(request):
    """Main view for URL threat detection page - handles GET and POST"""
    if request.method == 'POST':
        return analyze_url_view(request)
    return render(request, 'URLThreatDetection.html')


def analyze_url_view(request):
    """Process URL analysis and return results for template"""
    start_time = time.time()
    url = request.POST.get('url', '').strip()
    
    logger.info(f"📥 URL Threat Detection Request: {url}")
    
    if not url:
        logger.warning("⚠️ Empty URL submitted")
        return render(request, 'URLThreatDetection.html', {'error': 'Please enter a URL to analyze'})
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # Parse URL components
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        protocol = parsed.scheme or 'https'
        
        logger.info(f"🔍 Analyzing URL: {url} (domain: {domain})")
        
        # Get analysis from the ML analyzer
        analysis = analyzer.analyze_url(url, confidence_threshold=0.70)
        
        processing_time = (time.time() - start_time) * 1000
        
        # Determine threat level and score
        is_malicious = analysis.get('is_malicious', False)
        confidence = analysis.get('ensemble_confidence', analysis.get('confidence', 0))
        risk_factors = analysis.get('risk_factors', 0)
        
        # Calculate threat score (0-100, higher = more dangerous)
        if is_malicious:
            threat_score = min(95, 50 + confidence * 0.4 + risk_factors * 3)
            threat_level = 'malicious' if threat_score > 70 else 'suspicious'
        else:
            threat_score = max(5, 50 - confidence * 0.4 + risk_factors * 2)
            threat_level = 'safe' if threat_score < 30 else 'suspicious'
        
        # Build threat indicators from validation features
        threat_indicators = []
        validation = analysis.get('validation_features', {})
        
        if validation.get('ip_address_detected'):
            threat_indicators.append({
                'name': 'IP Address in URL',
                'description': 'URL uses IP address instead of domain name - common phishing technique',
                'severity': 'high'
            })
        
        if validation.get('url_shortener'):
            threat_indicators.append({
                'name': 'URL Shortener Detected',
                'description': 'URL shorteners can hide malicious destinations',
                'severity': 'medium'
            })
        
        if validation.get('suspicious_tld'):
            threat_indicators.append({
                'name': 'Suspicious TLD',
                'description': f'Domain uses a commonly abused top-level domain',
                'severity': 'medium'
            })
        
        if validation.get('brand_spoofing_risk'):
            threat_indicators.append({
                'name': 'Potential Brand Spoofing',
                'description': 'URL may be impersonating a known brand',
                'severity': 'high'
            })
        
        suspicious_keywords = validation.get('suspicious_keywords_count', 0)
        if suspicious_keywords > 0:
            threat_indicators.append({
                'name': 'Suspicious Keywords',
                'description': f'{suspicious_keywords} phishing-related keywords detected in URL',
                'severity': 'medium' if suspicious_keywords < 3 else 'high'
            })
        
        if validation.get('https_enabled'):
            threat_indicators.append({
                'name': 'HTTPS Enabled',
                'description': 'Connection is encrypted (but doesn\'t guarantee safety)',
                'severity': 'safe'
            })
        else:
            threat_indicators.append({
                'name': 'No HTTPS',
                'description': 'Connection is not encrypted - data may be intercepted',
                'severity': 'medium'
            })
        
        excessive_length = validation.get('excessive_length', len(url) > 100)
        if excessive_length:
            threat_indicators.append({
                'name': 'Excessive URL Length',
                'description': 'Very long URLs are often used to hide malicious content',
                'severity': 'low'
            })
        
        # Build model predictions
        model_predictions = []
        individual = analysis.get('individual_predictions', {})
        if individual:
            for model_name, prediction in individual.items():
                model_predictions.append({
                    'name': model_name.replace('_', ' ').title(),
                    'prediction': 'Malicious' if prediction else 'Safe',
                    'confidence': int(confidence)
                })
        else:
            # Fallback if no individual predictions
            model_predictions = [
                {'name': 'Decision Tree', 'prediction': 'Malicious' if is_malicious else 'Safe', 'confidence': int(confidence)},
                {'name': 'Random Forest', 'prediction': 'Malicious' if is_malicious else 'Safe', 'confidence': int(confidence)},
                {'name': 'Extra Trees', 'prediction': 'Malicious' if is_malicious else 'Safe', 'confidence': int(confidence)},
            ]
        
        # Generate summary and recommendation
        if threat_level == 'safe':
            summary = 'This URL appears to be safe based on our analysis.'
            recommendation = 'This URL shows no significant threat indicators. However, always exercise caution when entering personal information on any website.'
        elif threat_level == 'suspicious':
            summary = 'This URL shows some suspicious characteristics that warrant caution.'
            recommendation = 'We recommend verifying this URL before proceeding. Check for typos in the domain name and ensure you\'re on the correct website.'
        else:
            summary = 'This URL exhibits characteristics commonly associated with malicious websites.'
            recommendation = 'We strongly recommend NOT visiting this URL. It shows multiple indicators of phishing or malware distribution.'
        
        # Build result object
        result = {
            'url': url,
            'domain': domain,
            'protocol': protocol,
            'url_length': len(url),
            'threat_level': threat_level,
            'threat_score': int(threat_score),
            'is_malicious': is_malicious,
            'has_ip': validation.get('ip_address_detected', False),
            'suspicious_tld': validation.get('suspicious_tld', False),
            'processing_time_ms': processing_time,
            'summary': summary,
            'recommendation': recommendation,
            'threat_indicators': threat_indicators,
            'model_predictions': model_predictions,
            'confidence': confidence,
        }
        
        logger.info(f"✅ Analysis complete: {url} -> {threat_level} (score: {threat_score}%, time: {processing_time:.0f}ms)")
        
        return render(request, 'URLThreatDetection.html', {'result': result})
        
    except Exception as e:
        logger.error(f"❌ URL analysis error: {str(e)}")
        return render(request, 'URLThreatDetection.html', {
            'error': f'Analysis error: {str(e)}. Please try a different URL.'
        })

@csrf_exempt
@require_http_methods(["POST"])
def analyze_url_api(request):
    """Enhanced API endpoint for URL threat analysis with improved accuracy"""
    try:
        # Handle both form data and JSON requests
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            url = data.get('url', '').strip()
        else:
            url = request.POST.get('url', '').strip()
        
        if not url:
            result = {
                'success': False,
                'error': 'No URL provided',
                'title': 'Invalid Input',
                'explanation': 'Please enter a valid URL to analyze for threats.',
                'status_color': 'warning',
                'status_icon': 'fas fa-exclamation-triangle',
                'recommendation': 'Enter a URL like "example.com" or "https://example.com"'
            }
            
            # Return JSON for AJAX requests, render template for form submissions
            if request.content_type == 'application/json':
                return JsonResponse(result)
            return render(request, 'URLThreatDetection.html', {'result': result})
        
        # Enhanced URL validation
        if not _is_valid_url_enhanced(url):
            result = {
                'success': False,
                'error': 'Invalid URL format',
                'title': 'Invalid URL Format',
                'explanation': 'Please enter a valid URL. Accepted formats: example.com, www.example.com, https://example.com',
                'status_color': 'warning',
                'status_icon': 'fas fa-exclamation-triangle',
                'recommendation': 'Enter a properly formatted URL'
            }
            
            if request.content_type == 'application/json':
                return JsonResponse(result)
            return render(request, 'URLThreatDetection.html', {'result': result})
        
        logger.info(f"Analyzing URL with enhanced analyzer v3.0: {url}")
        
        # Use the enhanced analyzer with comprehensive features
        result = analyzer.analyze_url(url, confidence_threshold=0.70)
        
        # Add additional UI-friendly fields
        if result.get('success', True):  # Most analyzers don't return 'success' field
            threat_type = result.get('threat_type', 'Unknown').lower()
            
            # Enhanced logging with more details
            confidence = result.get('ensemble_confidence', result.get('confidence', 0))
            validation_features = result.get('validation_features', {})
            risk_factors = result.get('risk_factors', 0)
            
            logger.info(f"✅ Enhanced analysis complete: {url} -> {threat_type} "
                       f"(confidence: {confidence:.1f}%, risk_factors: {risk_factors})")
            
            # Add validation feature summary for display
            feature_summary = []
            if validation_features.get('ip_address_detected'):
                feature_summary.append("IP address detected")
            if validation_features.get('url_shortener'):
                feature_summary.append("URL shortener service")
            if validation_features.get('suspicious_tld'):
                feature_summary.append("Suspicious TLD")
            if validation_features.get('brand_spoofing_risk'):
                feature_summary.append("Brand spoofing risk")
            if validation_features.get('suspicious_keywords_count', 0) > 0:
                feature_summary.append(f"{validation_features['suspicious_keywords_count']} suspicious keywords")
            
            result['feature_summary'] = feature_summary
            result['feature_count'] = len(feature_summary)
            
            # Enhanced recommendation based on analysis
            if not result.get('is_malicious', False):
                if validation_features.get('https_enabled'):
                    result['security_note'] = "✓ HTTPS enabled"
                else:
                    result['security_note'] = "⚠ HTTP only (not encrypted)"
        else:
            logger.error(f"❌ Enhanced analysis failed for {url}: {result.get('error', 'Unknown error')}")
        
        # Return appropriate response type
        if request.content_type == 'application/json':
            return JsonResponse(result)
        return render(request, 'URLThreatDetection.html', {'result': result})
        
    except json.JSONDecodeError:
        error_result = {
            'success': False,
            'error': 'Invalid JSON data',
            'title': 'Request Error',
            'explanation': 'Invalid request format. Please try again.',
            'status_color': 'danger',
            'status_icon': 'fas fa-exclamation-triangle'
        }
        return JsonResponse(error_result)
        
    except Exception as e:
        logger.error(f"Error in enhanced URL analysis: {str(e)}")
        error_result = {
            'success': False,
            'error': str(e),
            'title': 'Analysis Error',
            'explanation': 'An unexpected error occurred during URL analysis. Please try again.',
            'status_color': 'danger',
            'status_icon': 'fas fa-exclamation-triangle',
            'recommendation': 'Try again with a different URL or contact support if the issue persists'
        }
        
        if request.content_type == 'application/json':
            return JsonResponse(error_result)
        return render(request, 'URLThreatDetection.html', {'result': error_result})

def _is_valid_url_enhanced(url):
    """Enhanced URL validation with better pattern matching"""
    if not url or len(url.strip()) < 4:
        return False
    
    url = url.strip()
    
    # Remove common prefixes for validation
    test_url = url.lower()
    if test_url.startswith(('http://', 'https://')):
        url_without_protocol = url[url.find('://') + 3:]
    else:
        url_without_protocol = url
    
    # Basic domain validation patterns
    patterns = [
        # Standard domain: example.com, www.example.com
        r'^(www\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,}|[a-zA-Z]{2,}\.[a-zA-Z]{2,})(/.*)?$',
        
        # IP addresses: 192.168.1.1
        r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?(/.*)?$',
        
        # Localhost variations
        r'^localhost(:\d+)?(/.*)?$',
        
        # Simple domain without www: google.com
        r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}(/.*)?$'
    ]
    
    for pattern in patterns:
        if re.match(pattern, url_without_protocol, re.IGNORECASE):
            return True
    
    return False
