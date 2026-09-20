import re
from urllib.parse import urlparse


# ==========================================================
# URL Extraction
# ==========================================================

def extract_urls(text):
    """
    Extract URLs from email text.

    Returns:
        List of unique URLs
    """

    if not text:
        return []

    # Match common HTTP/HTTPS URLs
    url_pattern = re.compile(
        r"https?://[^\s<>\"]+",
        re.IGNORECASE
    )

    matches = url_pattern.findall(text)

    urls = []

    for url in matches:

        # Remove punctuation that may appear after a URL
        url = url.rstrip(
            ".,;:!?)]}'\""
        )

        if url not in urls:
            urls.append(url)

    return urls


# ==========================================================
# Domain Extraction
# ==========================================================

def extract_domains(urls):
    """
    Extract hostnames/domains from URLs.

    Example:

        https://login.example.com/account

    becomes:

        login.example.com
    """

    domains = []

    for url in urls:

        try:

            parsed = urlparse(url)

            hostname = parsed.hostname

            if not hostname:
                continue

            hostname = hostname.lower()

            if hostname not in domains:
                domains.append(hostname)

        except Exception:
            continue

    return domains


# ==========================================================
# IPv4 Extraction
# ==========================================================

def extract_ip_addresses(text):
    """
    Extract IPv4 addresses from text.

    Example:

        192.168.1.10

    """

    if not text:
        return []

    ip_pattern = re.compile(
        r"\b(?:"
        r"(?:25[0-5]|2[0-4][0-9]|"
        r"1[0-9]{2}|[1-9]?[0-9])\."
        r"){3}"
        r"(?:25[0-5]|2[0-4][0-9]|"
        r"1[0-9]{2}|[1-9]?[0-9])\b"
    )

    matches = ip_pattern.findall(text)

    return list(
        dict.fromkeys(matches)
    )


# ==========================================================
# Main IOC Extraction
# ==========================================================

def extract_iocs(email_body):
    """
    Extract all basic IOCs from an email body.

    Returns:

        {
            "urls": [],
            "domains": [],
            "ip_addresses": []
        }
    """

    urls = extract_urls(
        email_body
    )

    domains = extract_domains(
        urls
    )

    ip_addresses = extract_ip_addresses(
        email_body
    )

    return {

        "urls": urls,

        "domains": domains,

        "ip_addresses": ip_addresses

    }