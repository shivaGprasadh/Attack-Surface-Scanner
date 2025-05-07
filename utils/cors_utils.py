import json
import requests
import logging
from urllib.parse import urlparse

def scan_cors(url):
    """
    Scan for CORS misconfiguration issues
    
    Args:
        url (str): The URL to scan
        
    Returns:
        dict: Dictionary containing CORS information
    """
    result = {
        'has_cors': False,
        'cors_policy': None,
        'issues': None,
        'test_results': None  # Store detailed test results for UI display
    }
    
    try:
        # Define origins to test
        test_origins = [
            'https://evil.com',
            'https://attacker.com',
            'null',
            'https://malicious-site.com',
            'http://localhost:8080',
            'https://subdomain.example.com',
            '*'
        ]
        
        # Extract domain to use for same-site origin test
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Add same-site and subdomain origins for comparison
        test_origins.append(f'https://{domain}')
        
        if domain.startswith('www.'):
            base_domain = domain[4:]
            test_origins.append(f'https://{base_domain}')
            test_origins.append(f'https://api.{base_domain}')
        else:
            test_origins.append(f'https://www.{domain}')
            test_origins.append(f'https://api.{domain}')
        
        # Make initial request to check if CORS is implemented
        initial_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Origin': 'https://cors-test.com'
        }
        
        response = requests.get(url, headers=initial_headers, timeout=10, verify=False)
        
        # Check if CORS headers are present
        cors_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers',
            'Access-Control-Allow-Credentials',
            'Access-Control-Expose-Headers',
            'Access-Control-Max-Age'
        ]
        
        response_cors_headers = {}
        for header in cors_headers:
            if header in response.headers:
                response_cors_headers[header] = response.headers[header]
        
        # Store test results for each origin
        test_results = []
        issues = []
        
        # If initial response has CORS headers or to be thorough, test with all origins
        if response_cors_headers or True:  # Always test for thorough analysis
            result['has_cors'] = bool(response_cors_headers)
            result['cors_policy'] = json.dumps(response_cors_headers)
            
            # Test with different origins
            for origin in test_origins:
                preflight_headers = None
                preflight_response = None
                
                # Try to make a preflight OPTIONS request first
                try:
                    preflight_response = requests.options(
                        url,
                        headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                            'Origin': origin,
                            'Access-Control-Request-Method': 'GET',
                            'Access-Control-Request-Headers': 'Content-Type, Authorization'
                        },
                        timeout=10,
                        verify=False
                    )
                    
                    # Collect CORS headers from preflight response
                    preflight_headers = {}
                    for header in cors_headers:
                        if header in preflight_response.headers:
                            preflight_headers[header] = preflight_response.headers[header]
                except:
                    # Preflight request failed, continue with regular request
                    pass
                
                # Make a regular GET request with the test origin
                test_response = requests.get(
                    url,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                        'Origin': origin
                    },
                    timeout=10,
                    verify=False
                )
                
                # Collect CORS headers from the response
                test_cors_headers = {}
                for header in cors_headers:
                    if header in test_response.headers:
                        test_cors_headers[header] = test_response.headers[header]
                
                # Determine if the origin is allowed
                is_allowed = False
                allowed_origin = test_cors_headers.get('Access-Control-Allow-Origin')
                
                if allowed_origin:
                    if allowed_origin == '*' or allowed_origin == origin:
                        is_allowed = True
                
                # Store test result
                test_result = {
                    'origin': origin,
                    'is_allowed': is_allowed,
                    'response_headers': test_cors_headers,
                    'preflight_headers': preflight_headers
                }
                test_results.append(test_result)
                
                # Analyze for issues
                if allowed_origin:
                    # Check for wildcard origin
                    if allowed_origin == '*':
                        # Only flag as an issue if it's not already in the issues list
                        if not any(issue.get('title') == 'Wildcard CORS Origin' for issue in issues):
                            issues.append({
                                'title': 'Wildcard CORS Origin',
                                'description': 'The server allows CORS from any origin (*) which could lead to cross-origin attacks if sensitive data is exposed.',
                                'severity': 'high',
                                'recommendation': 'Restrict the allowed origins to only trusted domains.'
                            })
                    
                    # Check for null origin
                    elif allowed_origin == 'null' and origin == 'null':
                        issues.append({
                            'title': 'Null Origin Allowed',
                            'description': 'The server allows CORS from the "null" origin, which can be spoofed by attackers using iframes with data: URIs or sandbox attributes.',
                            'severity': 'high',
                            'recommendation': 'Remove "null" from allowed origins.'
                        })
                    
                    # Check for reflected origin
                    elif allowed_origin == origin and not is_same_site_or_subdomain(origin, domain):
                        # Check if this is a potentially malicious domain that was reflected
                        if any(malicious in origin for malicious in ['evil', 'attack', 'malicious', 'localhost']):
                            issues.append({
                                'title': 'Dangerous Origin Reflection Detected',
                                'description': f'The server reflects potentially malicious origins ({origin}) in the Access-Control-Allow-Origin header.',
                                'severity': 'critical',
                                'recommendation': 'Implement a whitelist of trusted origins instead of reflecting the Origin header.'
                            })
                        else:
                            issues.append({
                                'title': 'Origin Reflection Detected',
                                'description': f'The server reflects any origin ({origin}) in the Access-Control-Allow-Origin header.',
                                'severity': 'high',
                                'recommendation': 'Implement a whitelist of trusted origins instead of reflecting the Origin header.'
                            })
                    
                    # Check for Allow-Credentials with problematic origins
                    if 'Access-Control-Allow-Credentials' in test_cors_headers:
                        if test_cors_headers['Access-Control-Allow-Credentials'].lower() == 'true':
                            if allowed_origin == '*':
                                issues.append({
                                    'title': 'Credentials Allowed with Wildcard Origin',
                                    'description': 'The server allows credentials with a wildcard origin, which is insecure and not supported by browsers.',
                                    'severity': 'critical',
                                    'recommendation': 'Specify exact trusted origins when using Access-Control-Allow-Credentials: true.'
                                })
                            elif allowed_origin == origin and not is_same_site_or_subdomain(origin, domain):
                                issues.append({
                                    'title': 'Credentials Allowed with Reflected Origin',
                                    'description': f'The server allows credentials with a reflected origin ({origin}), which could lead to cross-site request forgery.',
                                    'severity': 'high',
                                    'recommendation': 'Restrict the allowed origins to only trusted domains when allowing credentials.'
                                })
                
                # Check preflight response if available
                if preflight_headers:
                    preflight_allowed_origin = preflight_headers.get('Access-Control-Allow-Origin')
                    preflight_allowed_methods = preflight_headers.get('Access-Control-Allow-Methods')
                    preflight_allowed_headers = preflight_headers.get('Access-Control-Allow-Headers')
                    
                    # Check for overly permissive methods
                    if preflight_allowed_methods and ('*' in preflight_allowed_methods or ','.join(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) in preflight_allowed_methods):
                        if not any(issue.get('title') == 'Overly Permissive Methods' for issue in issues):
                            issues.append({
                                'title': 'Overly Permissive Methods',
                                'description': 'The server allows all or many HTTP methods in CORS preflight responses, which may expose unnecessary functionality.',
                                'severity': 'medium',
                                'recommendation': 'Limit CORS allowed methods to only those that are necessary for the application.'
                            })
                    
                    # Check for overly permissive headers
                    if preflight_allowed_headers and '*' in preflight_allowed_headers:
                        if not any(issue.get('title') == 'Overly Permissive Headers' for issue in issues):
                            issues.append({
                                'title': 'Overly Permissive Headers',
                                'description': 'The server allows any request header in CORS requests, which may expose sensitive functionality.',
                                'severity': 'medium',
                                'recommendation': 'Limit CORS allowed headers to only those that are necessary for the application.'
                            })
            
            # Additional CORS security checks
            if response_cors_headers:
                # Check for missing or excessive Access-Control-Max-Age
                if 'Access-Control-Max-Age' in response_cors_headers:
                    try:
                        max_age = int(response_cors_headers['Access-Control-Max-Age'])
                        if max_age > 86400:  # More than 24 hours
                            issues.append({
                                'title': 'Excessive CORS Cache Time',
                                'description': 'The CORS preflight cache time is set to more than 24 hours, which may cause security policy changes to take longer to propagate.',
                                'severity': 'low',
                                'recommendation': 'Set Access-Control-Max-Age to a reasonable value (e.g., 7200 seconds / 2 hours).'
                            })
                    except ValueError:
                        pass
                
                # Check for overly permissive Expose-Headers
                if 'Access-Control-Expose-Headers' in response_cors_headers:
                    if '*' in response_cors_headers['Access-Control-Expose-Headers']:
                        issues.append({
                            'title': 'Overly Permissive Exposed Headers',
                            'description': 'The server exposes all response headers to CORS requests, which may leak sensitive information.',
                            'severity': 'medium',
                            'recommendation': 'Limit exposed headers to only those that are necessary for the application.'
                        })
            
            # Save results
            result['test_results'] = json.dumps(test_results)
            if issues:
                result['issues'] = json.dumps(issues)
    
    except requests.exceptions.RequestException as e:
        logging.error(f"CORS check request error: {str(e)}")
    except Exception as e:
        logging.error(f"Error in scan_cors: {str(e)}")
    
    return result

def is_same_site_or_subdomain(origin, domain):
    """
    Check if an origin is from the same site or a subdomain of the target domain
    
    Args:
        origin (str): The origin to check
        domain (str): The target domain
        
    Returns:
        bool: True if the origin is from the same site or a subdomain, False otherwise
    """
    try:
        if origin in ['null', '*']:
            return False
            
        # Parse the origin to get its domain
        parsed_origin = urlparse(origin)
        origin_domain = parsed_origin.netloc
        
        # Remove port if present
        if ':' in origin_domain:
            origin_domain = origin_domain.split(':')[0]
        
        # Check if domains match exactly
        if origin_domain == domain:
            return True
        
        # Check if origin is a subdomain of the target domain
        if origin_domain.endswith('.' + domain):
            return True
        
        # Handle www variants
        if domain.startswith('www.'):
            base_domain = domain[4:]
            if origin_domain == base_domain or origin_domain.endswith('.' + base_domain):
                return True
        else:
            if origin_domain == 'www.' + domain:
                return True
    
    except Exception as e:
        logging.error(f"Error in is_same_site_or_subdomain: {str(e)}")
    
    return False
