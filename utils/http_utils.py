import json
import requests
import logging
import re
from urllib.parse import urlparse

def scan_http_headers(url):
    """
    Scan HTTP headers for security issues
    
    Args:
        url (str): The URL to scan
        
    Returns:
        dict: Dictionary containing HTTP header information
    """
    result = {
        'headers': None,
        'missing_headers': None,
        'insecure_headers': None,
        'server_info': None,
        'csp_issues': None
    }
    
    # List of security headers to check
    security_headers = [
        {
            'name': 'Strict-Transport-Security',
            'description': 'HTTP Strict Transport Security (HSTS) forces browsers to use HTTPS.',
            'severity': 'high',
            'recommendation': 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header.'
        },
        {
            'name': 'Content-Security-Policy',
            'description': 'Content Security Policy (CSP) helps prevent XSS and data injection attacks.',
            'severity': 'high',
            'recommendation': 'Implement a strict Content Security Policy.'
        },
        {
            'name': 'X-Content-Type-Options',
            'description': 'X-Content-Type-Options prevents browsers from MIME-sniffing a response from the declared content-type.',
            'severity': 'medium',
            'recommendation': 'Add "X-Content-Type-Options: nosniff" header.'
        },
        {
            'name': 'X-Frame-Options',
            'description': 'X-Frame-Options protects against clickjacking attacks.',
            'severity': 'medium',
            'recommendation': 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" header.'
        },
        {
            'name': 'X-XSS-Protection',
            'description': 'X-XSS-Protection enables the cross-site scripting (XSS) filter in browsers.',
            'severity': 'medium',
            'recommendation': 'Add "X-XSS-Protection: 1; mode=block" header.'
        },
        {
            'name': 'Referrer-Policy',
            'description': 'Referrer-Policy controls how much referrer information is included with requests.',
            'severity': 'low',
            'recommendation': 'Add "Referrer-Policy: no-referrer" or "Referrer-Policy: same-origin" header.'
        },
        {
            'name': 'Feature-Policy',
            'description': 'Feature-Policy allows restricting which browser features can be used.',
            'severity': 'low',
            'recommendation': 'Implement a Feature-Policy header to restrict unnecessary browser features.'
        },
        {
            'name': 'Permissions-Policy',
            'description': 'Permissions-Policy (replacement for Feature-Policy) restricts which browser features can be used.',
            'severity': 'low',
            'recommendation': 'Implement a Permissions-Policy header to restrict unnecessary browser features.'
        }
    ]
    
    try:
        # Make HTTP request
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
        
        # Get response headers
        response_headers = dict(response.headers)
        result['headers'] = json.dumps(response_headers)
        
        # Check for missing security headers
        missing_headers = []
        for header in security_headers:
            # Special case for Content-Security-Policy - don't list it as missing if we have CSP-Report-Only
            if header['name'] == 'Content-Security-Policy':
                # Check different case variations of the Content-Security-Policy header
                csp_header_present = False
                for resp_header in response_headers.keys():
                    if resp_header.lower() == 'content-security-policy' or resp_header.lower() == 'content-security-policy-report-only':
                        csp_header_present = True
                        break
                if not csp_header_present:
                    missing_headers.append(header)
            elif header['name'] not in response_headers:
                # Check for case-insensitive matches for other headers
                header_present = False
                for resp_header in response_headers.keys():
                    if resp_header.lower() == header['name'].lower():
                        header_present = True
                        break
                if not header_present:
                    missing_headers.append(header)
        
        if missing_headers:
            result['missing_headers'] = json.dumps(missing_headers)
        
        # Check for insecure header configurations
        insecure_headers = []
        
        # Check HSTS configuration
        if 'Strict-Transport-Security' in response_headers:
            hsts_header = response_headers['Strict-Transport-Security']
            if 'max-age=' not in hsts_header.lower():
                insecure_headers.append({
                    'name': 'Strict-Transport-Security',
                    'description': 'HSTS header is missing max-age directive.',
                    'severity': 'medium',
                    'recommendation': 'Ensure the HSTS header includes a max-age directive with a value of at least 31536000 (1 year).'
                })
            elif 'includesubdomains' not in hsts_header.lower():
                insecure_headers.append({
                    'name': 'Strict-Transport-Security',
                    'description': 'HSTS header is missing includeSubDomains directive.',
                    'severity': 'low',
                    'recommendation': 'Add the includeSubDomains directive to the HSTS header to protect all subdomains.'
                })
        
        # Check X-Frame-Options configuration
        if 'X-Frame-Options' in response_headers:
            xfo_header = response_headers['X-Frame-Options'].upper()
            if xfo_header not in ['DENY', 'SAMEORIGIN']:
                insecure_headers.append({
                    'name': 'X-Frame-Options',
                    'description': f'Potentially insecure X-Frame-Options value: {xfo_header}',
                    'severity': 'medium',
                    'recommendation': 'Use either DENY or SAMEORIGIN for the X-Frame-Options header.'
                })
        
        # Check for Server header (information disclosure)
        if 'Server' in response_headers:
            result['server_info'] = response_headers['Server']
            insecure_headers.append({
                'name': 'Server',
                'description': f'Server header reveals version information: {response_headers["Server"]}',
                'severity': 'low',
                'recommendation': 'Configure the web server to not disclose version information in the Server header.'
            })
        
        # Check Content Security Policy configuration
        csp_issues = []
        
        # Find CSP header with case-insensitive match
        csp_header_key = None
        csp_report_only_key = None
        
        for header_key in response_headers.keys():
            if header_key.lower() == 'content-security-policy':
                csp_header_key = header_key
            elif header_key.lower() == 'content-security-policy-report-only':
                csp_report_only_key = header_key
        
        if csp_header_key:
            csp_header = response_headers[csp_header_key]
            csp_issues = analyze_csp(csp_header)
        elif csp_report_only_key:
            csp_header = response_headers[csp_report_only_key]
            csp_issues = analyze_csp(csp_header)
            csp_issues.append({
                'name': 'CSP-Report-Only',
                'description': 'Content Security Policy is in report-only mode and not enforced',
                'severity': 'medium',
                'recommendation': 'Switch from Content-Security-Policy-Report-Only to Content-Security-Policy for enforcement'
            })
            
        if csp_issues:
            result['csp_issues'] = json.dumps(csp_issues)
            
        if insecure_headers:
            result['insecure_headers'] = json.dumps(insecure_headers)
        
    except requests.exceptions.RequestException as e:
        logging.error(f"HTTP request error: {str(e)}")
    except Exception as e:
        logging.error(f"Error in scan_http_headers: {str(e)}")
    
    return result

def check_https_redirect(url):
    """
    Check if HTTP redirects to HTTPS
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: Dictionary containing redirect information
    """
    result = {
        'redirects_to_https': False
    }
    
    try:
        # Ensure URL uses HTTP
        parsed_url = urlparse(url)
        if parsed_url.scheme != 'http':
            http_url = url.replace('https://', 'http://')
        else:
            http_url = url
        
        # Make request and follow redirects
        response = requests.get(http_url, timeout=10, allow_redirects=True, verify=False)
        
        # Check if final URL uses HTTPS
        final_url = response.url
        if final_url.startswith('https://'):
            result['redirects_to_https'] = True
        
    except requests.exceptions.RequestException as e:
        logging.error(f"HTTP redirect check error: {str(e)}")
    except Exception as e:
        logging.error(f"Error in check_https_redirect: {str(e)}")
    
    return result


def analyze_csp(csp_header):
    """
    Analyze Content Security Policy (CSP) header for common misconfigurations
    
    Args:
        csp_header (str): The CSP header value to analyze
        
    Returns:
        list: List of CSP issues found
    """
    issues = []
    
    # Parse the CSP directives
    directives = {}
    for part in csp_header.split(';'):
        if not part.strip():
            continue
        
        parts = part.strip().split(' ', 1)
        directive = parts[0].strip().lower()
        
        if len(parts) > 1:
            values = parts[1].strip().split(' ')
            directives[directive] = values
        else:
            directives[directive] = []
    
    # Check for unsafe-inline in script-src or style-src
    for directive in ['script-src', 'script-src-elem', 'script-src-attr']:
        if directive in directives and "'unsafe-inline'" in [v.lower() for v in directives[directive]]:
            issues.append({
                'name': 'Unsafe Inline Scripts',
                'description': f"'{directive}' allows inline scripts with 'unsafe-inline', which can lead to XSS attacks",
                'severity': 'high',
                'recommendation': "Remove 'unsafe-inline' from script sources and use nonces or hashes instead"
            })
    
    for directive in ['style-src', 'style-src-elem', 'style-src-attr']:
        if directive in directives and "'unsafe-inline'" in [v.lower() for v in directives[directive]]:
            issues.append({
                'name': 'Unsafe Inline Styles',
                'description': f"'{directive}' allows inline styles with 'unsafe-inline', which increases XSS risk",
                'severity': 'medium',
                'recommendation': "Remove 'unsafe-inline' from style sources and use nonces or hashes instead"
            })
    
    # Check for unsafe-eval
    if 'script-src' in directives and "'unsafe-eval'" in [v.lower() for v in directives['script-src']]:
        issues.append({
            'name': 'Unsafe Eval Usage',
            'description': "script-src allows 'unsafe-eval', which can execute arbitrary code",
            'severity': 'high',
            'recommendation': "Remove 'unsafe-eval' and refactor code to avoid using eval(), new Function(), etc."
        })
    
    # Check for wildcards in critical directives
    critical_directives = ['script-src', 'script-src-elem', 'object-src', 'frame-src', 'connect-src']
    
    for directive in critical_directives:
        if directive in directives and '*' in directives[directive]:
            issues.append({
                'name': f'Wildcard in {directive}',
                'description': f"{directive} uses a wildcard (*), allowing resources from any domain",
                'severity': 'high',
                'recommendation': f"Replace the wildcard in {directive} with specific domain names"
            })
    
    # Check if default-src is missing or uses wildcards
    if 'default-src' not in directives:
        issues.append({
            'name': 'Missing default-src',
            'description': "No default-src directive specified, which may allow unintended content",
            'severity': 'medium',
            'recommendation': "Add 'default-src' directive with appropriate restrictions"
        })
    elif '*' in directives['default-src']:
        issues.append({
            'name': 'Permissive default-src',
            'description': "default-src uses a wildcard (*), allowing resources from any domain by default",
            'severity': 'high',
            'recommendation': "Replace the wildcard in default-src with specific domain names or 'self'"
        })
    
    # Check for missing object-src and base-uri directives
    if 'object-src' not in directives and 'default-src' not in directives:
        issues.append({
            'name': 'Missing object-src',
            'description': "No object-src directive specified, which may allow embedding of unwanted objects",
            'severity': 'medium',
            'recommendation': "Add 'object-src none' to block Flash and other plugins"
        })
    
    if 'base-uri' not in directives:
        issues.append({
            'name': 'Missing base-uri',
            'description': "No base-uri directive specified, which allows attackers to inject base tags",
            'severity': 'medium',
            'recommendation': "Add 'base-uri 'self'' or 'base-uri 'none'' to restrict base URI manipulation"
        })
    
    # Check for report-uri/report-to
    if 'report-uri' not in directives and 'report-to' not in directives:
        issues.append({
            'name': 'No Reporting Configured',
            'description': "No CSP violation reporting is configured (missing report-uri or report-to)",
            'severity': 'low',
            'recommendation': "Add 'report-to' or 'report-uri' directive to collect CSP violation reports"
        })
    
    # Check for upgrade-insecure-requests
    if 'upgrade-insecure-requests' not in directives:
        issues.append({
            'name': 'Missing upgrade-insecure-requests',
            'description': "No upgrade-insecure-requests directive, which automatically upgrades HTTP to HTTPS",
            'severity': 'medium',
            'recommendation': "Add 'upgrade-insecure-requests' directive to ensure secure connections"
        })
    
    return issues
