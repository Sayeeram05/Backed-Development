"""
Enhanced Email Validation System v2.0
Advanced email validation with temporary domain detection and DNS warnings
Improved accuracy and comprehensive validation features
"""

from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
import re
import time
import json
import socket
from email_validator import validate_email, EmailNotValidError
import dns.resolver

# Comprehensive temporary email domain list
TEMPORARY_EMAIL_DOMAINS = {
    # Popular temporary email services
    '10minutemail.com', '10minutemail.net', '10minutemail.org',
    'mailinator.com', 'guerrillamail.com', 'guerrillamail.org',
    'temp-mail.org', 'tempmail.net', 'throwaway.email',
    'maildrop.cc', 'yopmail.com', 'yopmail.fr', 'yopmail.net',
    'sharklasers.com', 'guerrillamail.net', 'guerrillamail.de',
    'getairmail.com', 'airmail.cc', 'guerrillamail.biz',
    'guerrillamail.info', 'guerrillamailblock.com',
    
    # Other temporary providers
    'tempail.com', 'tempemail.com', 'temporaryemail.net',
    'emailondeck.com', 'mytrashmail.com', 'trashmail.com',
    'disposable-email.ml', 'burnermail.io', 'mohmal.com',
    'getnada.com', 'fakemail.net', 'temp-mail.ru',
    'dispostable.com', 'fakeinbox.com', 'harakirimail.com',
    'mintemail.com', 'temp-mail.io', 'tempinbox.com',
    'throwawaymail.com', 'binmail.net', 'mailcatch.com',
    'mailexpire.com', 'mailforspam.com', 'mailnesia.com',
    'spamgourmet.com', 'spamgourmet.net', 'spamgourmet.org',
    '20minutemail.com', '20email.eu', '33mail.com',
    'anonbox.net', 'bccto.me', 'byom.de', 'crazymailing.com',
    'deadaddress.com', 'despam.it', 'devnullmail.com',
    'e4ward.com', 'emailinfive.com', 'emailsensei.com',
    'emailto.de', 'emz.net', 'fakemailz.com', 'fastmail.fm',
    'filzmail.com', 'getonemail.com', 'great-host.in',
    'hidemyass.com', 'incognitomail.org', 'jetable.org',
    'kasmail.com', 'keepmymail.com', 'klzlk.com', 'kurzepost.de',
    'lhsdv.com', 'lookugly.com', 'lopl.co.cc', 'lr78.com',
    'maileater.com', 'mailexpire.com', 'mailforspam.com',
    'mailfreeonline.com', 'mailnesia.com', 'mailscrap.com',
    'mailzilla.org', 'mbx.cc', 'mt2009.com', 'mx0.wwwnew.eu',
    'mytempemail.com', 'neverbox.com', 'no-spam.ws',
    'nobulk.com', 'noclickemail.com', 'nogmailspam.info',
    'notmailinator.com', 'nowmymail.com', 'objectmail.com',
    'obobbo.com', 'onewaymail.com', 'owlpic.com', 'pooae.com',
    'prtnx.com', 'rmqkr.net', 's0ny.net', 'safe-mail.net',
    'selfdestructingmail.com', 'sendspamhere.com', 'skeefmail.com',
    'snakemail.com', 'sofort-mail.de', 'sogetthis.com',
    'soodonims.com', 'spam4.me', 'spamail.de', 'spambog.com',
    'spambog.de', 'spambog.ru', 'spamfree24.com', 'spamfree24.de',
    'spamfree24.eu', 'spamfree24.net', 'spamfree24.org',
    'spamherald.com', 'spamhole.com', 'spamify.com', 'spaminator.de',
    'spamkill.info', 'spaml.com', 'spaml.de', 'spammotel.com',
    'spamobox.com', 'spamspot.com', 'spamstack.net', 'speed.1s.fr',
    'supergreatmail.com', 'supermailer.jp', 'superrito.com',
    'tagyourself.com', 'teewars.org', 'tempalias.com',
    'tempe-mail.com', 'tempemail.biz', 'tempemail.com',
    'tempinbox.co.uk', 'tempinbox.com', 'tempmail.eu',
    'tempmail2.com', 'tempmaildemo.com', 'tempsky.com',
    'thanksnospam.info', 'thankyou2010.com', 'thisisnotmyrealemail.com',
    'thrma.com', 'tilien.com', 'tipsmail.com', 'toiea.com',
    'turual.com', 'twinmail.de', 'tyldd.com', 'uroid.com',
    'venompen.com', 'veryrealemail.com', 'wh4f.org',
    'whatiaas.com', 'willhackforfood.biz', 'willselldrugs.com',
    'xoxy.net', 'yogamaven.com', 'yuurok.com', 'zehnminutenmail.de',
    'zoemail.org', 'zoemail.net', 'zzzmail.com'
}

# Additional suspicious patterns
SUSPICIOUS_PATTERNS = [
    r'.*temp.*mail.*',
    r'.*fake.*mail.*',
    r'.*trash.*mail.*',
    r'.*spam.*mail.*',
    r'.*disposable.*',
    r'.*throw.*away.*',
    r'.*burn.*mail.*',
    r'.*dump.*mail.*'
]

def is_valid_email_regex(email: str) -> tuple:
    """Enhanced email format validation using regex."""
    # More comprehensive regex pattern
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    is_valid = bool(re.match(pattern, email))
    
    additional_checks = []
    
    # Check for common issues
    if '..' in email:
        is_valid = False
        additional_checks.append("Contains consecutive dots")
    
    if email.startswith('.') or email.startswith('@'):
        is_valid = False
        additional_checks.append("Invalid start character")
    
    if email.endswith('.') or email.endswith('@'):
        is_valid = False
        additional_checks.append("Invalid end character")
    
    # Check for minimum local part length
    if '@' in email:
        local_part = email.split('@')[0]
        if len(local_part) < 1:
            is_valid = False
            additional_checks.append("Local part too short")
    
    details = {
        'status': 'valid' if is_valid else 'invalid',
        'message': 'Email format is valid' if is_valid else 'Invalid email format',
        'technical_info': 'Passes enhanced RFC 5322 pattern validation' if is_valid else f"Format issues: {', '.join(additional_checks) if additional_checks else 'Basic format validation failed'}",
        'additional_checks': additional_checks
    }
    return is_valid, details

def is_valid_email_library(email: str) -> tuple:
    """Enhanced email validation using the email-validator library."""
    try:
        valid = validate_email(
            email, 
            check_deliverability=False,  # We'll do our own DNS checks
            test_environment=False
        )
        details = {
            'status': 'valid',
            'message': 'Email is syntactically valid',
            'normalized_email': valid.email,
            'local_part': valid.local_part,
            'domain': valid.domain,
            'technical_info': 'Passes comprehensive RFC compliance validation including internationalization',
            'original_domain': email.split('@')[1].lower() if '@' in email else None
        }
        return True, details, valid.email
    except EmailNotValidError as e:
        details = {
            'status': 'invalid',
            'message': f'Email validation failed: {str(e)}',
            'normalized_email': None,
            'local_part': None,
            'domain': None,
            'technical_info': f'Library validation error: {str(e)}',
            'original_domain': email.split('@')[1].lower() if '@' in email and len(email.split('@')) > 1 else None
        }
        return False, details, None

def is_temporary_email(domain: str) -> dict:
    """Enhanced temporary email domain detection."""
    domain = domain.lower().strip()
    
    # Direct match check
    if domain in TEMPORARY_EMAIL_DOMAINS:
        return {
            'is_temporary': True,
            'reason': 'direct_match',
            'confidence': 95,
            'message': f'Domain "{domain}" is a known temporary email provider'
        }
    
    # Pattern matching for suspicious domains
    for pattern in SUSPICIOUS_PATTERNS:
        if re.match(pattern, domain):
            return {
                'is_temporary': True,
                'reason': 'pattern_match',
                'confidence': 80,
                'message': f'Domain "{domain}" matches temporary email pattern'
            }
    
    # Check for numeric-only TLD or suspicious patterns
    if domain.endswith('.tk') or domain.endswith('.ml') or domain.endswith('.ga'):
        return {
            'is_temporary': True,
            'reason': 'suspicious_tld',
            'confidence': 70,
            'message': f'Domain "{domain}" uses a TLD commonly associated with temporary services'
        }
    
    return {
        'is_temporary': False,
        'reason': 'not_detected',
        'confidence': 85,
        'message': f'Domain "{domain}" does not appear to be a temporary email provider'
    }

def has_mx_record(domain: str) -> tuple:
    """Enhanced MX record checking with better error handling."""
    try:
        start_time = time.time()
        
        # Try MX record lookup
        try:
            mx_answers = dns.resolver.resolve(domain, 'MX')
            response_time = round((time.time() - start_time) * 1000, 2)
            
            mx_records = []
            for rdata in mx_answers:
                mx_records.append({
                    'priority': rdata.preference,
                    'exchange': str(rdata.exchange).rstrip('.')
                })
            
            # Sort by priority (lower is higher priority)
            mx_records.sort(key=lambda x: x['priority'])
            
            details = {
                'status': 'valid',
                'has_mx': True,
                'mx_count': len(mx_records),
                'mx_records': mx_records,
                'primary_mx': mx_records[0]['exchange'] if mx_records else None,
                'response_time_ms': response_time,
                'message': f'Domain has {len(mx_records)} MX record(s) and can receive email',
                'technical_info': f'MX lookup successful in {response_time}ms'
            }
            return True, details
            
        except dns.resolver.NoAnswer:
            # No MX records, try A record as fallback
            try:
                a_answers = dns.resolver.resolve(domain, 'A')
                response_time = round((time.time() - start_time) * 1000, 2)
                
                details = {
                    'status': 'fallback',
                    'has_mx': False,
                    'has_a_record': True,
                    'mx_count': 0,
                    'mx_records': [],
                    'fallback_ips': [str(rdata) for rdata in a_answers],
                    'response_time_ms': response_time,
                    'message': 'No MX records found, but domain exists (fallback to A record)',
                    'technical_info': f'No MX records, using A record fallback (RFC compliant)'
                }
                return True, details
                
            except:
                response_time = round((time.time() - start_time) * 1000, 2)
                details = {
                    'status': 'no_records',
                    'has_mx': False,
                    'has_a_record': False,
                    'mx_count': 0,
                    'mx_records': [],
                    'response_time_ms': response_time,
                    'message': 'Domain has no MX or A records and cannot receive email',
                    'technical_info': 'Neither MX nor A records found for domain'
                }
                return False, details
                
    except dns.resolver.NXDOMAIN:
        response_time = round((time.time() - start_time) * 1000, 2)
        details = {
            'status': 'domain_not_found',
            'has_mx': False,
            'mx_count': 0,
            'mx_records': [],
            'response_time_ms': response_time,
            'message': 'Domain does not exist',
            'technical_info': 'DNS NXDOMAIN - domain name does not exist'
        }
        return False, details
        
    except dns.resolver.Timeout:
        response_time = round((time.time() - start_time) * 1000, 2)
        details = {
            'status': 'timeout',
            'has_mx': None,
            'mx_count': 0,
            'mx_records': [],
            'response_time_ms': response_time,
            'message': 'DNS lookup timed out - domain status unknown',
            'technical_info': 'DNS query timeout - network or DNS server issue'
        }
        return None, details
        
    except Exception as e:
        response_time = round((time.time() - start_time) * 1000, 2)
        details = {
            'status': 'dns_error',
            'has_mx': None,
            'mx_count': 0,
            'mx_records': [],
            'response_time_ms': response_time,
            'message': f'DNS lookup failed: {str(e)}',
            'technical_info': f'DNS resolution error: {str(e)}'
        }
        return None, details

def validate_email_comprehensive(email: str) -> dict:
    """
    Comprehensive email validation combining all checks
    Returns detailed validation results
    """
    start_time = time.time()
    results = {
        'email': email,
        'is_valid': False,
        'is_deliverable': False,
        'is_temporary': False,
        'confidence_score': 0,
        'warnings': [],
        'errors': [],
        'details': {}
    }
    
    # Step 1: Basic format validation
    format_valid, format_details = is_valid_email_regex(email)
    results['details']['format'] = format_details
    
    if not format_valid:
        results['errors'].append("Invalid email format")
        results['confidence_score'] = 0
        results['processing_time_ms'] = round((time.time() - start_time) * 1000, 2)
        return results
    
    # Step 2: Library validation (more thorough)
    library_valid, library_details, normalized_email = is_valid_email_library(email)
    results['details']['library'] = library_details
    
    if not library_valid:
        results['errors'].append(library_details.get('message', 'Library validation failed'))
        results['confidence_score'] = 20
        results['processing_time_ms'] = round((time.time() - start_time) * 1000, 2)
        return results
    
    # Extract domain for further checks
    domain = library_details.get('domain') or email.split('@')[1].lower()
    results['domain'] = domain
    results['normalized_email'] = normalized_email
    
    # Step 3: Temporary email detection
    temp_check = is_temporary_email(domain)
    results['details']['temporary'] = temp_check
    results['is_temporary'] = temp_check['is_temporary']
    
    if temp_check['is_temporary']:
        results['warnings'].append(f"Temporary email detected: {temp_check['message']}")
        results['confidence_score'] = max(results['confidence_score'], 30)
    
    # Step 4: DNS/MX record validation
    mx_valid, mx_details = has_mx_record(domain)
    results['details']['dns'] = mx_details
    
    if mx_valid is True:
        results['is_deliverable'] = True
        results['confidence_score'] = max(results['confidence_score'], 85)
    elif mx_valid is False:
        results['errors'].append(mx_details.get('message', 'Domain cannot receive email'))
        results['confidence_score'] = max(results['confidence_score'], 40)
    else:  # mx_valid is None (timeout/error)
        results['warnings'].append(mx_details.get('message', 'Could not verify domain'))
        results['confidence_score'] = max(results['confidence_score'], 60)
    
    # Step 5: Final validation decision
    results['is_valid'] = format_valid and library_valid
    
    # Adjust confidence based on temporary email detection
    if results['is_temporary']:
        results['confidence_score'] = min(results['confidence_score'], 50)
        if temp_check['confidence'] > 90:
            results['confidence_score'] = min(results['confidence_score'], 30)
    
    results['processing_time_ms'] = round((time.time() - start_time) * 1000, 2)
    
    return results

@csrf_exempt
@require_http_methods(["GET", "POST"])
def email_validation_view(request):
    """Enhanced email validation view with improved UI and features"""
    if request.method == 'GET':
        return render(request, 'EmailValidation.html')
    
    if request.method == 'POST':
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body)
                email = data.get('email', '').strip()
            else:
                email = request.POST.get('email', '').strip()
            
            if not email:
                return JsonResponse({
                    'success': False,
                    'error': 'No email address provided',
                    'message': 'Please enter an email address to validate'
                })
            
            # Perform comprehensive validation
            validation_results = validate_email_comprehensive(email)
            
            # Prepare response
            response = {
                'success': True,
                'email': validation_results['email'],
                'normalized_email': validation_results.get('normalized_email'),
                'is_valid': validation_results['is_valid'],
                'is_deliverable': validation_results['is_deliverable'],
                'is_temporary': validation_results['is_temporary'],
                'confidence_score': validation_results['confidence_score'],
                'warnings': validation_results['warnings'],
                'errors': validation_results['errors'],
                'processing_time_ms': validation_results['processing_time_ms'],
                'domain': validation_results.get('domain'),
                
                # UI-friendly fields
                'status': 'valid' if validation_results['is_valid'] and validation_results['is_deliverable'] and not validation_results['is_temporary'] else 'warning' if validation_results['is_valid'] else 'invalid',
                'title': get_validation_title(validation_results),
                'message': get_validation_message(validation_results),
                'status_color': get_status_color(validation_results),
                'status_icon': get_status_icon(validation_results),
                'recommendation': get_recommendation(validation_results),
                
                # Detailed results for advanced users
                'details': validation_results['details']
            }
            
            return JsonResponse(response)
            
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid JSON data',
                'message': 'Please check your request format'
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e),
                'message': 'An error occurred during validation'
            })

def get_validation_title(results):
    """Generate appropriate title based on validation results"""
    if not results['is_valid']:
        return "Invalid Email Address"
    elif results['is_temporary']:
        return "Temporary Email Detected"
    elif not results['is_deliverable']:
        return "Email May Not Be Deliverable"
    elif results['warnings']:
        return "Valid Email with Warnings"
    else:
        return "Valid Email Address"

def get_validation_message(results):
    """Generate detailed message based on validation results"""
    if not results['is_valid']:
        return f"This email address is not valid. {' '.join(results['errors'])}"
    elif results['is_temporary']:
        return f"This appears to be a temporary email address. While valid, it may not be suitable for long-term communication."
    elif not results['is_deliverable']:
        return f"This email address is valid but may not be deliverable. {' '.join(results['errors'])}"
    elif results['warnings']:
        return f"This email address is valid but has some concerns: {' '.join(results['warnings'])}"
    else:
        return f"This email address is valid and appears to be deliverable with {results['confidence_score']}% confidence."

def get_status_color(results):
    """Get appropriate Bootstrap color class"""
    if not results['is_valid']:
        return 'danger'
    elif results['is_temporary'] or not results['is_deliverable']:
        return 'warning'
    elif results['warnings']:
        return 'info'
    else:
        return 'success'

def get_status_icon(results):
    """Get appropriate FontAwesome icon"""
    if not results['is_valid']:
        return 'fas fa-times-circle'
    elif results['is_temporary']:
        return 'fas fa-clock'
    elif not results['is_deliverable']:
        return 'fas fa-exclamation-triangle'
    elif results['warnings']:
        return 'fas fa-info-circle'
    else:
        return 'fas fa-check-circle'

def get_recommendation(results):
    """Generate security/usage recommendation"""
    if not results['is_valid']:
        return "Please correct the email address format and try again."
    elif results['is_temporary']:
        return "Consider using a permanent email address for important accounts and communications."
    elif not results['is_deliverable']:
        return "Verify the domain name and try again, or contact the recipient through alternative means."
    elif results['confidence_score'] < 70:
        return "Exercise caution - this email may have deliverability issues."
    else:
        return "This email address appears safe to use for communication."