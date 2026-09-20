import base64
import requests

from config import VT_API_KEY


# ==========================================================
# VirusTotal Configuration
# ==========================================================

VT_BASE_URL = "https://www.virustotal.com/api/v3"

REQUEST_TIMEOUT = 15


# ==========================================================
# Check API Configuration
# ==========================================================

def is_configured():
    """
    Check whether a VirusTotal API key is available.
    """

    return bool(
        VT_API_KEY
        and VT_API_KEY.strip()
    )


# ==========================================================
# Common HTTP Headers
# ==========================================================

def get_headers():
    """
    Return headers required by the VirusTotal API.
    """

    return {
        "x-apikey": VT_API_KEY
    }


# ==========================================================
# Extract Reputation Statistics
# ==========================================================

def extract_stats(data):
    """
    Extract VirusTotal reputation statistics.

    Example response:

        {
            "malicious": 5,
            "suspicious": 2,
            "undetected": 60,
            "harmless": 10
        }
    """

    attributes = (
        data
        .get("data", {})
        .get("attributes", {})
    )

    stats = attributes.get(
        "last_analysis_stats",
        {}
    )

    return {

        "malicious": stats.get(
            "malicious",
            0
        ),

        "suspicious": stats.get(
            "suspicious",
            0
        ),

        "undetected": stats.get(
            "undetected",
            0
        ),

        "harmless": stats.get(
            "harmless",
            0
        )

    }


# ==========================================================
# Determine Reputation
# ==========================================================

def determine_verdict(stats):
    """
    Convert VirusTotal statistics into a simple verdict.

    This is only a reputation summary. It does NOT mean
    VirusTotal has definitively classified the item as
    malicious.
    """

    malicious = stats.get(
        "malicious",
        0
    )

    suspicious = stats.get(
        "suspicious",
        0
    )

    if malicious > 0:

        return "MALICIOUS"

    if suspicious > 0:

        return "SUSPICIOUS"

    return "NO_MALICIOUS_DETECTION"


# ==========================================================
# Analyze URL with VirusTotal
# ==========================================================

def check_url(url):
    """
    Check a URL against VirusTotal.

    Returns a structured result.

    If the API key is missing, the function returns a
    graceful result instead of crashing the application.
    """

    if not is_configured():

        return {

            "indicator": url,

            "type": "url",

            "status": "NOT_CONFIGURED",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                "VirusTotal API key is not configured."
            )

        }

    # ------------------------------------------------------
    # VirusTotal URL identifier
    # ------------------------------------------------------
    #
    # VirusTotal uses URL-safe base64 without '=' padding.
    #

    try:

        encoded_url = (
            base64.urlsafe_b64encode(
                url.encode()
            )
            .decode()
            .rstrip("=")
        )

    except Exception as error:

        return {

            "indicator": url,

            "type": "url",

            "status": "ERROR",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                f"Unable to encode URL: {error}"
            )

        }

    endpoint = (
        f"{VT_BASE_URL}/urls/{encoded_url}"
    )

    # ------------------------------------------------------
    # Send request
    # ------------------------------------------------------

    try:

        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=REQUEST_TIMEOUT
        )

    except requests.RequestException as error:

        return {

            "indicator": url,

            "type": "url",

            "status": "ERROR",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                f"VirusTotal request failed: {error}"
            )

        }

    # ------------------------------------------------------
    # URL not found in VirusTotal
    # ------------------------------------------------------

    if response.status_code == 404:

        return {

            "indicator": url,

            "type": "url",

            "status": "NOT_FOUND",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                "URL was not found in the VirusTotal dataset."
            )

        }

    # ------------------------------------------------------
    # Authentication problem
    # ------------------------------------------------------

    if response.status_code in {
        401,
        403
    }:

        return {

            "indicator": url,

            "type": "url",

            "status": "AUTH_ERROR",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                "VirusTotal API authentication failed "
                "or access was denied."
            )

        }

    # ------------------------------------------------------
    # Rate limit
    # ------------------------------------------------------

    if response.status_code == 429:

        return {

            "indicator": url,

            "type": "url",

            "status": "RATE_LIMITED",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                "VirusTotal API rate limit was reached."
            )

        }

    # ------------------------------------------------------
    # Other HTTP errors
    # ------------------------------------------------------

    if response.status_code != 200:

        return {

            "indicator": url,

            "type": "url",

            "status": "HTTP_ERROR",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                f"VirusTotal returned HTTP "
                f"{response.status_code}."
            )

        }

    # ------------------------------------------------------
    # Parse response
    # ------------------------------------------------------

    try:

        data = response.json()

    except ValueError:

        return {

            "indicator": url,

            "type": "url",

            "status": "INVALID_RESPONSE",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                "VirusTotal returned an invalid response."
            )

        }

    # ------------------------------------------------------
    # Extract statistics
    # ------------------------------------------------------

    stats = extract_stats(
        data
    )

    verdict = determine_verdict(
        stats
    )

    return {

        "indicator": url,

        "type": "url",

        "status": "SUCCESS",

        "verdict": verdict,

        "stats": stats,

        "message": (
            "VirusTotal reputation retrieved successfully."
        )

    }


# ==========================================================
# Analyze Attachment Hash
# ==========================================================

def check_hash(sha256):
    """
    Check an attachment SHA-256 hash against VirusTotal.

    The file itself is NOT uploaded.

    Only the hash is queried.
    """

    if not is_configured():

        return {

            "indicator": sha256,

            "type": "file_hash",

            "status": "NOT_CONFIGURED",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                "VirusTotal API key is not configured."
            )

        }

    # ------------------------------------------------------
    # Validate basic SHA-256 format
    # ------------------------------------------------------

    if not sha256:

        return {

            "indicator": sha256,

            "type": "file_hash",

            "status": "INVALID_HASH",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                "No SHA-256 hash was provided."
            )

        }

    if len(sha256) != 64:

        return {

            "indicator": sha256,

            "type": "file_hash",

            "status": "INVALID_HASH",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                "Provided value is not a valid "
                "SHA-256 length."
            )

        }

    endpoint = (
        f"{VT_BASE_URL}/files/{sha256}"
    )

    # ------------------------------------------------------
    # Send request
    # ------------------------------------------------------

    try:

        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=REQUEST_TIMEOUT
        )

    except requests.RequestException as error:

        return {

            "indicator": sha256,

            "type": "file_hash",

            "status": "ERROR",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                f"VirusTotal request failed: {error}"
            )

        }

    # ------------------------------------------------------
    # Hash not found
    # ------------------------------------------------------

    if response.status_code == 404:

        return {

            "indicator": sha256,

            "type": "file_hash",

            "status": "NOT_FOUND",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                "File hash was not found in "
                "the VirusTotal dataset."
            )

        }

    # ------------------------------------------------------
    # Authentication error
    # ------------------------------------------------------

    if response.status_code in {
        401,
        403
    }:

        return {

            "indicator": sha256,

            "type": "file_hash",

            "status": "AUTH_ERROR",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                "VirusTotal API authentication failed "
                "or access was denied."
            )

        }

    # ------------------------------------------------------
    # Rate limit
    # ------------------------------------------------------

    if response.status_code == 429:

        return {

            "indicator": sha256,

            "type": "file_hash",

            "status": "RATE_LIMITED",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                "VirusTotal API rate limit was reached."
            )

        }

    # ------------------------------------------------------
    # Other errors
    # ------------------------------------------------------

    if response.status_code != 200:

        return {

            "indicator": sha256,

            "type": "file_hash",

            "status": "HTTP_ERROR",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                f"VirusTotal returned HTTP "
                f"{response.status_code}."
            )

        }

    # ------------------------------------------------------
    # Parse response
    # ------------------------------------------------------

    try:

        data = response.json()

    except ValueError:

        return {

            "indicator": sha256,

            "type": "file_hash",

            "status": "INVALID_RESPONSE",

            "verdict": "UNKNOWN",

            "stats": {},

            "message": (
                "VirusTotal returned an invalid response."
            )

        }

    # ------------------------------------------------------
    # Extract statistics
    # ------------------------------------------------------

    stats = extract_stats(
        data
    )

    verdict = determine_verdict(
        stats
    )

    return {

        "indicator": sha256,

        "type": "file_hash",

        "status": "SUCCESS",

        "verdict": verdict,

        "stats": stats,

        "message": (
            "VirusTotal file reputation retrieved successfully."
        )

    }


# ==========================================================
# Analyze Multiple URLs
# ==========================================================

def check_urls(urls):
    """
    Check multiple URLs against VirusTotal.
    """

    results = []

    for url in urls:

        result = check_url(
            url
        )

        results.append(
            result
        )

    return results


# ==========================================================
# Analyze Multiple File Hashes
# ==========================================================

def check_hashes(hashes):
    """
    Check multiple SHA-256 hashes against VirusTotal.
    """

    results = []

    for sha256 in hashes:

        result = check_hash(
            sha256
        )

        results.append(
            result
        )

    return results