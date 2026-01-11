from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
import re
import time
from email_validator import validate_email, EmailNotValidError
import dns.resolver

def is_valid_email_regex(email: str) -> tuple:
    """Quickly check if the email looks valid using regex."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    is_valid = bool(re.match(pattern, email))
    details = {
        'status': 'valid' if is_valid else 'invalid',
        'message': 'Email format is valid' if is_valid else 'Invalid email format - contains illegal characters or missing components',
        'technical_info': 'Passes RFC 5322 basic pattern validation' if is_valid else 'Does not match standard email format (user@domain.com)'
    }
    return is_valid, details

def is_valid_email_library(email: str) -> tuple:
    """Validate email using the email-validator library. Returns normalized email and details."""
    try:
        valid = validate_email(email, check_deliverability=False)
        details = {
            'status': 'valid',
            'message': 'Email is syntactically valid',
            'normalized_email': valid.email,
            'local_part': valid.local_part,
            'domain': valid.domain,
            'technical_info': 'Passes comprehensive RFC compliance validation including internationalization'
        }
        return True, details, valid.email
    except EmailNotValidError as e:
        details = {
            'status': 'invalid',
            'message': f'Email validation failed: {str(e)}',
            'normalized_email': None,
            'local_part': None,
            'domain': None,
            'technical_info': f'Library validation error: {str(e)}'
        }
        return False, details, None

def has_mx_record(domain: str) -> tuple:
    """Check if the domain has at least one MX record (accepts email)."""
    try:
        start_time = time.time()
        answers = dns.resolver.resolve(domain, 'MX')
        response_time = round((time.time() - start_time) * 1000, 2)
        
        mx_records = []
        for rdata in answers:
            mx_records.append({
                'preference': rdata.preference,
                'exchange': str(rdata.exchange),
                'priority': 'Primary' if rdata.preference <= 10 else 'Secondary' if rdata.preference <= 20 else 'Backup'
            })
        
        # Sort by preference (lower number = higher priority)
        mx_records.sort(key=lambda x: x['preference'])
        
        details = {
            'status': 'valid',
            'message': f'Domain accepts email - {len(mx_records)} mail server(s) found',
            'mx_count': len(mx_records),
            'mx_records': mx_records,
            'response_time_ms': response_time,
            'technical_info': f'DNS MX lookup successful in {response_time}ms - {len(mx_records)} mail exchangers configured'
        }
        return True, details
        
    except dns.resolver.NXDOMAIN:
        details = {
            'status': 'invalid',
            'message': 'Domain does not exist',
            'mx_count': 0,
            'mx_records': [],
            'response_time_ms': 0,
            'technical_info': 'DNS NXDOMAIN - Domain name does not exist'
        }
        return False, details
    except dns.resolver.NoAnswer:
        details = {
            'status': 'warning',
            'message': 'Domain exists but has no mail servers configured',
            'mx_count': 0,
            'mx_records': [],
            'response_time_ms': 0,
            'technical_info': 'DNS query successful but no MX records found - domain cannot receive email'
        }
        return False, details
    except Exception as e:
        details = {
            'status': 'error',
            'message': f'Unable to check mail servers: {str(e)}',
            'mx_count': 0,
            'mx_records': [],
            'response_time_ms': 0,
            'technical_info': f'DNS lookup failed: {str(e)}'
        }
        return False, details

def check_disposable_email(domain: str) -> tuple:
    """Check if the domain is a known disposable email provider."""
    # Expanded disposable email domains list
    disposable_domains = {
        # Popular disposable email services
        '10minutemail.com', '10minutemail.net', '10minemail.com',
        'guerrillamail.com', 'guerrillamailblock.com', 'guerrillamail.de',
        'mailinator.com', 'mailinator2.com', 'mailinator.net',
        'tempmail.org', 'temp-mail.org', 'tempmail.net',
        'throwaway.email', 'throwawamail.com', 'trashmail.com',
        'fakeinbox.com', 'fake-mail.ml', 'fakemail.net',
        'dispostable.com', 'disposable.ml', 'disposablemail.com',
        'yopmail.com', 'yopmail.fr', 'yopmail.net',
        'maildrop.cc', 'mailtothis.com', 'mailcatch.com',
        'sharklasers.com', 'grr.la', 'guerrillamail.org',
        # More comprehensive list
        '0-mail.com', '0815.ru', '10mail.org', '20minutemail.com',
        '2prong.com', '30minutemail.com', '3d-painting.com',
        '4warding.com', '7tags.com', '9ox.net', 'aaathats3as.com',
        'abyssmail.com', 'adobeccepdm.com', 'agedmail.com',
        'ama-trade.de', 'amazonses.com', 'antichef.com',
        'armyspy.com', 'beefmilk.com', 'binkmail.com',
        'bobmail.info', 'bodhi.lawlita.com', 'boun.cr',
        'breakthru.com', 'burstmail.info', 'byom.de',
        'chacuo.net', 'chammy.info', 'childsavetrust.org',
        'chogmail.com', 'cool.fr.nf', 'correo.blogos.net',
        'criczz.com', 'cust.in', 'dacoolest.com',
        'deadaddress.com', 'despam.it', 'devnullmail.com',
        'dfgh.net', 'digitalsanctuary.com', 'discardmail.com',
        'dontreg.com', 'e4ward.com', 'emailias.com',
        'emailinfive.com', 'emailsensei.com', 'emailtemporanea.com',
        'emailwarden.com', 'explodemail.com', 'ez-mail.biz',
        'fakeemailgenerator.com', 'fastacura.com', 'fastchevy.com',
        'flapped.com', 'gishpuppy.com', 'great-host.in',
        'gtopala.com', 'gufum.com', 'guerrillamail.biz',
        'haltospam.com', 'harakirimail.com', 'hatespam.org',
        'hidemail.de', 'hotpop.com', 'ieh-mail.de',
        'inbox.si', 'incognitomail.org', 'jetable.org',
        'koszmail.pl', 'kurzepost.de', 'lifebyfood.com',
        'lnotu.com', 'lookugly.com', 'lopl.co.cc',
        'lr78.com', 'mail.by', 'mail4trash.com',
        'mailbidon.com', 'mailexpire.com', 'mailfree.ga',
        'mailguard.me', 'mailimate.com', 'mailmetrash.com',
        'mailnator.com', 'mailnesia.com', 'mailnull.com',
        'mailsac.com', 'mailshell.com', 'mailsiphon.com',
        'mailtmp.com', 'mailzilla.com', 'mbx.cc',
        'meltmail.com', 'mintemail.com', 'mjukglass.nu',
        'noclickemail.com', 'nogmailspam.info', 'nomail.xl.cx',
        'notmailinator.com', 'nurfuerspam.de', 'objectmail.com',
        'obobbo.com', 'oneoffemail.com', 'onewaymail.com',
        'ordinaryamerican.net', 'otherinbox.com', 'ovpn.to',
        'owlpic.com', 'pancakemail.com', 'pcusers.otherinbox.com',
        'plancdb.com', 'poeticverse.com', 'pooae.com',
        'proxymail.eu', 'putthisinyourspamdatabase.com', 'quickinbox.com',
        'rcpt.at', 'recode.me', 'recursor.net',
        'rootfest.net', 's0ny.net', 'safe-mail.net',
        'safetymail.info', 'sandelf.de', 'selfdestructingmail.com',
        'sendspamhere.com', 'sharklasers.com', 'shieldedmail.com',
        'smellfear.com', 'snkmail.com', 'sofort-mail.de',
        'spam4.me', 'spamail.de', 'spambob.net',
        'spambog.com', 'spambog.de', 'spamgourmet.com',
        'spamherald.com', 'spamhole.com', 'spamify.com',
        'spaml.com', 'spammotel.com', 'spamobox.com',
        'spamstack.net', 'spamthis.co.uk', 'spamthisplease.com',
        'speed.1s.fr', 'superrito.com', 'superstachel.de',
        'suremail.info', 'tagyourself.com', 'teleworm.us',
        'tempinbox.co.uk', 'tempinbox.com', 'tempmail.eu',
        'tempmail.it', 'tempmail.us', 'tempomail.fr',
        'temporarily.de', 'temporaryemail.net', 'temporaryinbox.com',
        'thanksnospam.info', 'thankyou2010.com', 'thecloudindex.com',
        'thisisnotmyrealemail.com', 'throwawaymailbox.com', 'tilien.com',
        'tmail.ws', 'tmailinator.com', 'tradermail.info',
        'trash-mail.at', 'trash-mail.com', 'trash-mail.de',
        'trashdevil.com', 'trashemail.de', 'trashmail.at',
        'trashmail.com', 'trashmail.de', 'trashmail.me',
        'trashmail.net', 'trashmail.org', 'trashmail.ws',
        'trashmailer.com', 'trashymail.com', 'tyldd.com',
        'uggsrock.com', 'upliftnow.com', 'uplipht.com',
        'venompen.com', 'veryrealemail.com', 'vidchart.com',
        'viditag.com', 'viewcastmedia.com', 'viewcastmedia.net',
        'viewcastmedia.org', 'vubby.com', 'wasteland.rfc822.org',
        'webemail.me', 'weg-werf-email.de', 'wegwerfadresse.de',
        'wegwerfemail.com', 'wegwerfemail.de', 'wegwerfmail.de',
        'wegwerfmail.net', 'wegwerfmail.org', 'wh4f.org',
        'whopy.com', 'willselfdestruct.com', 'wuzup.net',
        'wuzupmail.net', 'www.e4ward.com', 'www.gishpuppy.com',
        'www.mailinator.com', 'wwwnew.eu', 'x.ip6.li',
        'xagloo.com', 'xemaps.com', 'xents.com',
        'xmaily.com', 'xoxy.net', 'yepthatsit.com',
        'yogamaven.com', 'yomail.info', 'yuurok.com',
        'zehnminutenmail.de', 'zetmail.com', 'zoemail.org'
    }
    
    is_disposable = domain.lower() in disposable_domains
    details = {
        'status': 'warning' if is_disposable else 'valid',
        'message': 'Disposable/temporary email detected' if is_disposable else 'Permanent email address',
        'technical_info': f'Domain "{domain}" is in disposable email blacklist ({len(disposable_domains)} domains checked)' if is_disposable else f'Domain "{domain}" not found in disposable email blacklist ({len(disposable_domains)} domains checked)'
    }
    return is_disposable, details

def check_domain_existence(domain: str) -> tuple:
    """Check if domain exists by performing DNS A/AAAA record lookup."""
    try:
        start_time = time.time()
        # Try to resolve A record first
        try:
            answers = dns.resolver.resolve(domain, 'A')
            a_records = [str(rdata) for rdata in answers]
            response_time = round((time.time() - start_time) * 1000, 2)
        except dns.resolver.NoAnswer:
            # If no A record, try AAAA (IPv6)
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                a_records = [str(rdata) for rdata in answers]
                response_time = round((time.time() - start_time) * 1000, 2)
            except dns.resolver.NoAnswer:
                a_records = []
                response_time = round((time.time() - start_time) * 1000, 2)
        
        if a_records:
            details = {
                'status': 'valid',
                'message': f'Domain exists and is reachable',
                'a_records': a_records[:3],  # Show first 3 records
                'response_time_ms': response_time,
                'technical_info': f'DNS A/AAAA lookup successful in {response_time}ms - {len(a_records)} IP address(es) found'
            }
            return True, details
        else:
            details = {
                'status': 'warning',
                'message': 'Domain exists but may not be fully configured',
                'a_records': [],
                'response_time_ms': response_time,
                'technical_info': f'DNS lookup completed in {response_time}ms but no A/AAAA records found'
            }
            return False, details
            
    except dns.resolver.NXDOMAIN:
        details = {
            'status': 'invalid',
            'message': 'Domain does not exist',
            'a_records': [],
            'response_time_ms': 0,
            'technical_info': 'DNS NXDOMAIN - Domain name does not exist in DNS'
        }
        return False, details
    except Exception as e:
        details = {
            'status': 'error',
            'message': f'Unable to verify domain: {str(e)}',
            'a_records': [],
            'response_time_ms': 0,
            'technical_info': f'DNS lookup failed: {str(e)}'
        }
        return False, details

def calculate_risk_score(regex_valid: bool, library_valid: bool, mx_valid: bool, is_disposable: bool, domain: str) -> dict:
    """Calculate overall risk score and safety assessment."""
    score = 0
    risk_factors = []
    
    # Base scoring
    if regex_valid:
        score += 25
    else:
        risk_factors.append("Invalid email format")
    
    if library_valid:
        score += 35
    else:
        risk_factors.append("Failed comprehensive validation")
    
    if mx_valid:
        score += 30
    else:
        risk_factors.append("No mail servers configured")
    
    if not is_disposable:
        score += 10
    else:
        risk_factors.append("Disposable email provider")
        score -= 20
    
    # Domain reputation bonus/penalty
    trusted_domains = ['gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com', 'protonmail.com']
    if domain.lower() in trusted_domains:
        score += 5
    
    score = max(0, min(100, score))  # Clamp between 0-100
    
    if score >= 80:
        risk_level = 'low'
        risk_text = 'Low Risk'
        safety_color = 'success'
        recommendation = 'Email is safe to use and likely deliverable'
    elif score >= 60:
        risk_level = 'medium'
        risk_text = 'Medium Risk'  
        safety_color = 'warning'
        recommendation = 'Email may have some delivery issues but appears legitimate'
    else:
        risk_level = 'high'
        risk_text = 'High Risk'
        safety_color = 'danger'
        recommendation = 'Email has significant issues and may not be deliverable'
    
    return {
        'score': score,
        'risk_level': risk_level,
        'risk_text': risk_text,
        'safety_color': safety_color,
        'recommendation': recommendation,
        'risk_factors': risk_factors
    }

@csrf_exempt
@require_http_methods(["POST"])
def validate_email_api(request):
    """Comprehensive email validation API with detailed analysis."""
    email = request.POST.get('email', '').strip()
    
    if not email:
        return render(request, 'EmailValidation.html', {
            'result': {
                'email': '',
                'status': 'error',
                'status_icon': 'fas fa-exclamation-triangle',
                'title': 'No Email Provided',
                'explanation': 'Please enter an email address to validate.',
                'confidence': 0,
                'safety_score': 0
            }
        })
    
    # Start comprehensive validation
    start_time = time.time()
    
    # Step 1: Regex validation
    regex_valid, regex_details = is_valid_email_regex(email)
    
    # Step 2: Library validation
    library_valid, library_details, normalized_email = is_valid_email_library(email)
    
    # Step 3: Extract domain for further checks
    domain = None
    if normalized_email:
        domain = normalized_email.split('@')[1]
    elif '@' in email:
        domain = email.split('@')[1]
    
    # Step 4: Domain existence check
    domain_valid, domain_details = False, {'status': 'error', 'message': 'Cannot check without valid domain'}
    if domain:
        domain_valid, domain_details = check_domain_existence(domain)
    
    # Step 5: MX record check
    mx_valid, mx_details = False, {'status': 'error', 'message': 'Cannot check without valid domain'}
    if domain:
        mx_valid, mx_details = has_mx_record(domain)
    
    # Step 6: Disposable email check
    is_disposable, disposable_details = False, {'status': 'valid', 'message': 'Cannot check without domain'}
    if domain:
        is_disposable, disposable_details = check_disposable_email(domain)
    
    # Step 7: Calculate risk assessment
    risk_assessment = calculate_risk_score(regex_valid, library_valid, mx_valid, is_disposable, domain or 'unknown')
    
    # Calculate processing time
    processing_time = round((time.time() - start_time) * 1000, 2)
    
    # Determine overall status
    if regex_valid and library_valid and mx_valid and not is_disposable:
        overall_status = 'valid'
        status_icon = 'fas fa-check-circle'
        status_color = 'success'
        title = 'Email Validated Successfully'
        explanation = f'This email address is valid, deliverable, and safe to use. All security checks passed with a {risk_assessment["score"]}/100 safety score.'
    elif regex_valid and library_valid:
        overall_status = 'warning'  
        status_icon = 'fas fa-exclamation-triangle'
        status_color = 'warning'
        title = 'Email Valid with Warnings'
        explanation = f'The email format is correct, but there may be delivery or security concerns. Safety score: {risk_assessment["score"]}/100.'
    else:
        overall_status = 'invalid'
        status_icon = 'fas fa-times-circle' 
        status_color = 'danger'
        title = 'Invalid Email Address'
        explanation = f'This email address has critical validation errors and should not be used. Safety score: {risk_assessment["score"]}/100.'
    
    # Compile detailed result
    result = {
        'email': email,
        'normalized_email': normalized_email,
        'domain': domain,
        'status': overall_status,
        'status_icon': status_icon,
        'status_color': status_color,
        'title': title,
        'explanation': explanation,
        'confidence': min(100, max(0, int((risk_assessment['score'] / 100) * 100))),
        'safety_score': risk_assessment['score'],
        'risk_level': risk_assessment['risk_level'],
        'risk_text': risk_assessment['risk_text'],
        'recommendation': risk_assessment['recommendation'],
        'processing_time_ms': processing_time,
        'validation_steps': {
            'regex_check': regex_details,
            'library_check': library_details,
            'domain_check': domain_details,
            'mx_check': mx_details,
            'disposable_check': disposable_details
        },
        'checks': {
            'format': {
                'status': regex_details['status'],
                'text': 'Valid' if regex_valid else 'Invalid',
                'icon': 'fas fa-check' if regex_valid else 'fas fa-times'
            },
            'domain': {
                'status': domain_details['status'] if domain else 'invalid',
                'text': domain_details['message'] if domain else 'Missing',
                'icon': 'fas fa-check' if domain_valid else 'fas fa-exclamation-triangle' if domain and domain_details['status'] == 'warning' else 'fas fa-times'
            },
            'mail_server': {
                'status': mx_details['status'],
                'text': f"Available ({mx_details.get('mx_count', 0)} servers)" if mx_valid else 'Unavailable',
                'icon': 'fas fa-check' if mx_valid else 'fas fa-times'
            },
            'deliverability': {
                'status': 'valid' if (regex_valid and library_valid and mx_valid) else 'invalid',
                'text': 'Deliverable' if (regex_valid and library_valid and mx_valid) else 'Not Deliverable',
                'icon': 'fas fa-check' if (regex_valid and library_valid and mx_valid) else 'fas fa-times'
            },
            'disposable': {
                'status': 'warning' if is_disposable else 'valid',
                'text': 'Yes' if is_disposable else 'No',
                'icon': 'fas fa-exclamation-triangle' if is_disposable else 'fas fa-check'
            },
            'risk': {
                'status': risk_assessment['risk_level'],
                'text': risk_assessment['risk_text'],
                'icon': 'fas fa-shield-check' if risk_assessment['risk_level'] == 'low' else 'fas fa-exclamation-triangle' if risk_assessment['risk_level'] == 'medium' else 'fas fa-times-circle'
            }
        },
        'risk_factors': risk_assessment['risk_factors']
    }
    
    return render(request, 'EmailValidation.html', {'result': result})

def email_validation_view(request):
    """Render the email validation page"""
    return render(request, 'EmailValidation.html')

