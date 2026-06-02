import requests;

SECURITY_HEADERS = {
    "Content-Security-Policy": "Prevents XSS by controlling resource loading",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME type sniffing",
    "Strict-Transport-Security": "Forces HTTPS connections",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Controls browser feature access",

}
"""Checks for the presence of common security headers in the HTTP response."""
def check_headers(url):
    results = []
    try:
        
        response = requests.get(url, timeout=5)# Fetch the URL and get the response headers
        headers = response.headers
        # Check for the presence of each security header and add the results to the list
        for header, description in SECURITY_HEADERS.items():
            present = header in headers
            results.append({
                "header": header,
                "present": present,
                "description": description,
                "severity": "HIGH" if not present else "PASS",
            })
    except requests.RequestException as e:
        print(f"Error scanning {url}: {e}")

    return results