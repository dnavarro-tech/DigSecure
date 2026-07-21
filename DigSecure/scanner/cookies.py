import requests

COOKIE_FLAGS = {
    "HttpOnly": "Cookie inaccessible to JavaScript, reducing XSS risk",
    "Secure": "Cookie only transmitted over HTTPS connections",
    "SameSite": "Cookie protected against cross-site request forgery (CSRF)",
}

def check_cookies(url):
    """
    Audits cookies returned by a target URL for missing security flags.

    Sends a GET request to the provided URL and inspects each cookie
    in the response for the presence of HttpOnly, Secure, and SameSite
    security attributes.

    Parameters:
    ----------
    url : str
        The full URL of the target to scan.
        Example: "https://example.com"

    Returns:
    -------
    list[dict]
        A list of dictionaries, one per cookie found.
        Each dictionary contains:
            - cookie_name (str)  : Name of the cookie
            - flag (str)         : The security flag being checked
            - present (bool)     : True if flag found, False if missing
            - description (str)  : What the flag protects against
            - severity (str)     : "MEDIUM" if missing, "PASS" if present

    Raises:
    ------
    requests.RequestException
        If the URL is unreachable or times out. Caught internally
        and printed to console.

    Example:
    -------
    >>> results = check_cookies("https://example.com")
    >>> for r in results:
    ...     print(r["cookie_name"], r["flag"], r["severity"])
    session_id HttpOnly MEDIUM
    session_id Secure PASS
    """
    results = []
    try:
        response = requests.get(url, timeout=5)
        cookies = response.cookies

        if not cookies:
            print(f"   No cookies found on {url}")
            return results

        for cookie in cookies:
            for flag, description in COOKIE_FLAGS.items():
                if flag == "HttpOnly":
                    present = cookie.has_nonstandard_attr("HttpOnly") or cookie._rest.get("HttpOnly") is not None
                elif flag == "Secure":
                    present = cookie.secure
                elif flag == "SameSite":
                    present = cookie.has_nonstandard_attr("SameSite") or "SameSite" in cookie._rest

                results.append({
                    "cookie_name": cookie.name,
                    "flag": flag,
                    "present": present,
                    "description": description,
                    "severity": "PASS" if present else "MEDIUM",
                })

    except requests.RequestException as e:
        print(f"Error scanning cookies on {url}: {e}")

    return results