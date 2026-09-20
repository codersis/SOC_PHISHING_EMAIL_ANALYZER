import ipaddress
from urllib.parse import urlparse


# ==========================================================
# Known URL Shortening Services
# ==========================================================

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
}


# ==========================================================
# Potentially Suspicious TLDs
# ==========================================================

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".zip",
    ".mov",
    ".work",
    ".live",
    ".buzz",
}


# ==========================================================
# Dangerous URL Schemes
# ==========================================================

SUSPICIOUS_SCHEMES = {
    "javascript",
    "data",
    "file",
}


# ==========================================================
# Analyze One URL
# ==========================================================

def analyze_url(url):
    """
    Analyze a URL for common phishing-related indicators.

    This function does NOT determine whether a URL is
    malicious. It identifies characteristics that may
    increase suspicion.

    Returns:
        {
            "url": str,
            "hostname": str,
            "score": int,
            "findings": list
        }
    """

    findings = []
    score = 0

    # ------------------------------------------------------
    # Parse URL
    # ------------------------------------------------------

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname

        if not hostname:

            return {
                "url": url,
                "hostname": "",
                "score": 0,
                "findings": [
                    "Unable to determine URL hostname."
                ]
            }

        hostname = hostname.lower()

    except Exception:

        return {
            "url": url,
            "hostname": "",
            "score": 0,
            "findings": [
                "Unable to parse URL."
            ]
        }

    # ------------------------------------------------------
    # Check URL scheme
    # ------------------------------------------------------

    scheme = parsed.scheme.lower()

    if scheme in SUSPICIOUS_SCHEMES:

        score += 25

        findings.append(
            f"Suspicious URL scheme detected: {scheme}."
        )

    # ------------------------------------------------------
    # HTTP instead of HTTPS
    # ------------------------------------------------------

    if scheme == "http":

        score += 5

        findings.append(
            "URL uses HTTP instead of HTTPS."
        )

    # ------------------------------------------------------
    # IP address instead of domain
    # ------------------------------------------------------

    try:

        ipaddress.ip_address(hostname)

        score += 15

        findings.append(
            "URL uses an IP address instead of a domain name."
        )

    except ValueError:

        pass

    # ------------------------------------------------------
    # URL shortener
    # ------------------------------------------------------

    if hostname in URL_SHORTENERS:

        score += 10

        findings.append(
            "URL uses a known URL shortening service."
        )

    # ------------------------------------------------------
    # Suspicious TLD
    # ------------------------------------------------------

    for tld in SUSPICIOUS_TLDS:

        if hostname.endswith(tld):

            score += 10

            findings.append(
                f"Domain uses potentially suspicious TLD: {tld}."
            )

            break

    # ------------------------------------------------------
    # Punycode / IDN
    # ------------------------------------------------------

    if (
        hostname.startswith("xn--")
        or ".xn--" in hostname
    ):

        score += 15

        findings.append(
            "Domain contains Punycode/IDN encoding."
        )

    # ------------------------------------------------------
    # @ symbol
    # ------------------------------------------------------

    if "@" in url:

        score += 15

        findings.append(
            "URL contains '@', which can obscure the "
            "actual destination."
        )

    # ------------------------------------------------------
    # Excessive URL length
    # ------------------------------------------------------

    if len(url) > 200:

        score += 5

        findings.append(
            "URL is unusually long."
        )

    # ------------------------------------------------------
    # Excessive subdomains
    # ------------------------------------------------------

    hostname_parts = hostname.split(".")

    if len(hostname_parts) >= 5:

        score += 10

        findings.append(
            "Domain contains an unusually large number "
            "of subdomains."
        )

    # ------------------------------------------------------
    # Suspicious keywords in URL
    # ------------------------------------------------------

    suspicious_keywords = {
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "signin",
        "authenticate",
        "payment",
        "invoice",
        "confirm",
    }

    matched_keywords = []

    url_lower = url.lower()

    for keyword in suspicious_keywords:

        if keyword in url_lower:

            matched_keywords.append(
                keyword
            )

    if matched_keywords:

        # Limit the contribution so a URL containing
        # many keywords does not dominate the score.

        keyword_score = min(
            len(matched_keywords) * 2,
            8
        )

        score += keyword_score

        findings.append(
            "Potentially sensitive URL keywords detected: "
            + ", ".join(matched_keywords)
        )

    # ------------------------------------------------------
    # Final URL score
    # ------------------------------------------------------

    score = min(
        score,
        50
    )

    # ------------------------------------------------------
    # Return analysis
    # ------------------------------------------------------

    return {

        "url": url,

        "hostname": hostname,

        "score": score,

        "findings": findings

    }


# ==========================================================
# Analyze Multiple URLs
# ==========================================================

def analyze_urls(urls):
    """
    Analyze a list of URLs.

    Returns:
        [
            {
                "url": "...",
                "hostname": "...",
                "score": 20,
                "findings": [...]
            }
        ]
    """

    results = []

    for url in urls:

        result = analyze_url(
            url
        )

        results.append(
            result
        )

    return results