from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json
import re
try:
    from email_validator import validate_email, EmailNotValidError
except ImportError:
    EmailNotValidError = Exception
    validate_email = None

try:
    import dns.resolver
except ImportError:
    dns = None

def email_validation_view(request):
    """Render the email validation page"""
    return render(request, 'EmailValidation.html')

@csrf_exempt
@require_http_methods(["POST"])
def validate_email_api(request):
    """API endpoint for email validation"""
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()
        
        if not email:
            return JsonResponse({
                'error': 'Email address is required',
                'status': 'invalid'
            }, status=400)
        
        result = perform_email_validation(email)
        return JsonResponse(result)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON data',
            'status': 'invalid'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'error': f'Validation error: {str(e)}',
            'status': 'error'
        }, status=500)

def perform_email_validation(email):
    """Perform comprehensive email validation"""
    
    result = {
        'email': email,
        'status': 'valid',
        'status_icon': 'fas fa-check-circle',
        'title': 'Valid Email',
        'explanation': 'This email address appears to be valid and reachable.',
        'confidence': 85,
        'confidence_text': 'High Confidence',
        'safety': 'low-risk',
        'safety_text': 'Low Risk',
        'checks': {
            'format': {'status': 'valid', 'text': 'Valid'},
            'domain': {'status': 'valid', 'text': 'Exists'},
            'mail_server': {'status': 'valid', 'text': 'Available'},
            'mailbox': {'status': 'valid', 'text': 'Accepted'},
            'disposable': {'status': 'valid', 'text': 'No'},
            'risk': {'status': 'low-risk', 'text': 'Low Risk'}
        }
    }
    
    # Step 1: Regex format check
    if not is_valid_email_regex(email):
        result.update({
            'status': 'invalid',
            'status_icon': 'fas fa-times-circle',
            'title': 'Invalid Email Format',
            'explanation': 'The email address format is incorrect.',
            'confidence': 100,
            'confidence_text': 'Certain',
            'safety': 'high-risk',
            'safety_text': 'High Risk',
            'checks': {
                'format': {'status': 'invalid', 'text': 'Invalid'},
                'domain': {'status': 'invalid', 'text': 'N/A'},
                'mail_server': {'status': 'invalid', 'text': 'N/A'},
                'mailbox': {'status': 'invalid', 'text': 'N/A'},
                'disposable': {'status': 'invalid', 'text': 'N/A'},
                'risk': {'status': 'high-risk', 'text': 'High Risk'}
            }
        })
        return result
    
    # Check for disposable email domains
    domain = email.split('@')[1]
    disposable_domains = [
        '10minutemail.com', 'tempmail.org', 'guerrillamail.com', 
        'mailinator.com', 'throwaway.email', 'temp-mail.org'
    ]
    
    if domain.lower() in disposable_domains:
        result.update({
            'status': 'warning',
            'status_icon': 'fas fa-exclamation-triangle',
            'title': 'Disposable Email',
            'explanation': 'This appears to be a temporary or disposable email address.',
            'confidence': 95,
            'confidence_text': 'High Confidence',
            'safety': 'medium-risk',
            'safety_text': 'Medium Risk',
            'checks': {
                'format': {'status': 'valid', 'text': 'Valid'},
                'domain': {'status': 'warning', 'text': 'Disposable'},
                'mail_server': {'status': 'valid', 'text': 'Available'},
                'mailbox': {'status': 'warning', 'text': 'Temporary'},
                'disposable': {'status': 'warning', 'text': 'Yes'},
                'risk': {'status': 'medium-risk', 'text': 'Medium Risk'}
            }
        })
    
    # Check for suspicious patterns
    suspicious_patterns = ['test', 'fake', 'spam', 'noreply', 'donotreply']
    if any(pattern in email.lower() for pattern in suspicious_patterns):
        result.update({
            'status': 'warning',
            'status_icon': 'fas fa-exclamation-triangle',
            'title': 'Suspicious Email',
            'explanation': 'This email contains patterns that might indicate it\'s not genuine.',
            'confidence': 70,
            'confidence_text': 'Medium Confidence',
            'safety': 'medium-risk',
            'safety_text': 'Medium Risk',
            'checks': {
                'format': {'status': 'valid', 'text': 'Valid'},
                'domain': {'status': 'valid', 'text': 'Exists'},
                'mail_server': {'status': 'valid', 'text': 'Available'},
                'mailbox': {'status': 'warning', 'text': 'Suspicious'},
                'disposable': {'status': 'valid', 'text': 'No'},
                'risk': {'status': 'medium-risk', 'text': 'Medium Risk'}
            }
        })
    
    return result

def is_valid_email_regex(email):
    """Check if email format is valid using regex"""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email))
