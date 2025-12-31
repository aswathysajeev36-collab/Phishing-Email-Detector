import sys
import re
from email import message_from_string
from urllib.parse import urlparse

def analyze_email(email_text):
    """
    Analyzes an email for phishing indicators.
    Returns a dictionary with detected indicators.
    """
    indicators = {
        'suspicious_urls': [],
        'sender_mismatches': [],
        'authentication_failures': [],
        'urgent_language': False,
        'suspicious_ips': [],
        'overall_risk': 'Low'
    }

    # Parse the email
    msg = message_from_string(email_text)

    # Extract headers
    from_header = msg.get('From', '')
    return_path = msg.get('Return-Path', '')
    received_headers = msg.get_all('Received', [])
    auth_results = msg.get('Authentication-Results', '')

    # Extract body
    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
            elif part.get_content_type() == 'text/html':
                body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
    else:
        body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

    # Check for suspicious URLs
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme == 'http':  # HTTP instead of HTTPS
            indicators['suspicious_urls'].append(f"HTTP URL: {url}")
        if 'secure-bank' in parsed.netloc and 'google' not in parsed.netloc:  # Example suspicious domain
            indicators['suspicious_urls'].append(f"Suspicious domain: {url}")

    # Check for sender mismatches
    from_domain = re.search(r'@([^\s>]+)', from_header)
    return_domain = re.search(r'@([^\s>]+)', return_path) if return_path else None
    if from_domain and return_domain and from_domain.group(1) != return_domain.group(1):
        indicators['sender_mismatches'].append(f"From domain ({from_domain.group(1)}) != Return-Path domain ({return_domain.group(1)})")

    # Check authentication results
    if 'spf=fail' in auth_results.lower():
        indicators['authentication_failures'].append("SPF Fail")
    if 'dkim=none' in auth_results.lower() or 'dkim=fail' in auth_results.lower():
        indicators['authentication_failures'].append("DKIM Fail")
    if 'dmarc=fail' in auth_results.lower():
        indicators['authentication_failures'].append("DMARC Fail")

    # Check for urgent language
    urgent_words = ['urgent', 'immediate', 'verify', 'suspension', 'account locked']
    if any(word in body.lower() for word in urgent_words):
        indicators['urgent_language'] = True

    # Check for suspicious IPs in Received headers
    for received in received_headers:
        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', received)
        if ip_match:
            ip = ip_match.group()
            # Example: flag IPs not from known providers
            if not ip.startswith('192.168.') and not ip.startswith('10.') and not ip.startswith('172.'):
                indicators['suspicious_ips'].append(ip)

    # Determine overall risk
    risk_score = 0
    if indicators['suspicious_urls']:
        risk_score += 2
    if indicators['sender_mismatches']:
        risk_score += 2
    if indicators['authentication_failures']:
        risk_score += 1
    if indicators['urgent_language']:
        risk_score += 1
    if indicators['suspicious_ips']:
        risk_score += 1

    if risk_score >= 4:
        indicators['overall_risk'] = 'High'
    elif risk_score >= 2:
        indicators['overall_risk'] = 'Medium'

    return indicators

def main():
    # Read email from stdin
    email_text = sys.stdin.read()
    results = analyze_email(email_text)

    print("Phishing Analysis Results:")
    print(f"Overall Risk: {results['overall_risk']}")
    print(f"Suspicious URLs: {results['suspicious_urls']}")
    print(f"Sender Mismatches: {results['sender_mismatches']}")
    print(f"Authentication Failures: {results['authentication_failures']}")
    print(f"Urgent Language Detected: {results['urgent_language']}")
    print(f"Suspicious IPs: {results['suspicious_ips']}")

if __name__ == "__main__":
    main()