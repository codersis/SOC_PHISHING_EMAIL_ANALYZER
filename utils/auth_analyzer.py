import re


# ==========================================================
# Normalize authentication result
# ==========================================================

def normalize_result(value):
    """
    Convert an authentication result into one of:

        PASS
        FAIL
        SOFTFAIL
        NEUTRAL
        NONE
        TEMPERROR
        PERMERROR
        UNKNOWN
    """

    if not value:
        return "UNKNOWN"

    value = value.upper().strip()

    valid_results = {
        "PASS",
        "FAIL",
        "SOFTFAIL",
        "NEUTRAL",
        "NONE",
        "TEMPERROR",
        "PERMERROR"
    }

    if value in valid_results:
        return value

    return "UNKNOWN"


# ==========================================================
# Extract SPF result
# ==========================================================

def extract_spf_result(authentication_results, received_spf):
    """
    Extract SPF result from Authentication-Results
    or Received-SPF headers.
    """

    text = (
        f"{authentication_results} "
        f"{received_spf}"
    ).lower()

    # Authentication-Results commonly contains:
    #
    # spf=pass
    # spf=fail
    # spf=softfail

    match = re.search(
        r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        text,
        re.IGNORECASE
    )

    if match:
        return normalize_result(
            match.group(1)
        )

    # Received-SPF may look like:
    #
    # pass (domain ...)
    # fail (domain ...)

    match = re.search(
        r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        received_spf,
        re.IGNORECASE
    )

    if match:
        return normalize_result(
            match.group(1)
        )

    return "UNKNOWN"


# ==========================================================
# Extract DKIM result
# ==========================================================

def extract_dkim_result(authentication_results):
    """
    Extract DKIM result from Authentication-Results.

    Example:

        dkim=pass
        dkim=fail
    """

    if not authentication_results:
        return "UNKNOWN"

    match = re.search(
        r"\bdkim\s*=\s*(pass|fail|neutral|none|temperror|permerror)\b",
        authentication_results,
        re.IGNORECASE
    )

    if match:
        return normalize_result(
            match.group(1)
        )

    return "UNKNOWN"


# ==========================================================
# Extract DMARC result
# ==========================================================

def extract_dmarc_result(authentication_results):
    """
    Extract DMARC result from Authentication-Results.

    Example:

        dmarc=pass
        dmarc=fail
    """

    if not authentication_results:
        return "UNKNOWN"

    match = re.search(
        r"\bdmarc\s*=\s*(pass|fail|neutral|none|temperror|permerror)\b",
        authentication_results,
        re.IGNORECASE
    )

    if match:
        return normalize_result(
            match.group(1)
        )

    return "UNKNOWN"


# ==========================================================
# Analyze Email Authentication
# ==========================================================

def analyze_authentication(authentication):
    """
    Analyze SPF, DKIM and DMARC results.

    Input example:

        {
            "authentication_results":
                "spf=fail dkim=fail dmarc=fail",

            "received_spf":
                "fail",

            "dkim_signature":
                "..."
        }

    Returns:

        {
            "spf": "FAIL",
            "dkim": "FAIL",
            "dmarc": "FAIL",
            "findings": [...]
        }
    """

    authentication_results = authentication.get(
        "authentication_results",
        ""
    )

    received_spf = authentication.get(
        "received_spf",
        ""
    )

    # ------------------------------------------------------
    # Extract results
    # ------------------------------------------------------

    spf = extract_spf_result(
        authentication_results,
        received_spf
    )

    dkim = extract_dkim_result(
        authentication_results
    )

    dmarc = extract_dmarc_result(
        authentication_results
    )

    findings = []

    # ------------------------------------------------------
    # SPF findings
    # ------------------------------------------------------

    if spf == "FAIL":

        findings.append(
            "SPF authentication failed."
        )

    elif spf == "SOFTFAIL":

        findings.append(
            "SPF returned SOFTFAIL."
        )

    elif spf == "PASS":

        findings.append(
            "SPF authentication passed."
        )

    # ------------------------------------------------------
    # DKIM findings
    # ------------------------------------------------------

    if dkim == "FAIL":

        findings.append(
            "DKIM authentication failed."
        )

    elif dkim == "PASS":

        findings.append(
            "DKIM authentication passed."
        )

    # ------------------------------------------------------
    # DMARC findings
    # ------------------------------------------------------

    if dmarc == "FAIL":

        findings.append(
            "DMARC authentication failed."
        )

    elif dmarc == "PASS":

        findings.append(
            "DMARC authentication passed."
        )

    # ------------------------------------------------------
    # Missing authentication information
    # ------------------------------------------------------

    if spf == "UNKNOWN":

        findings.append(
            "SPF result was not available in the email headers."
        )

    if dkim == "UNKNOWN":

        findings.append(
            "DKIM result was not available in the email headers."
        )

    if dmarc == "UNKNOWN":

        findings.append(
            "DMARC result was not available in the email headers."
        )

    # ------------------------------------------------------
    # Return results
    # ------------------------------------------------------

    return {

        "spf": spf,

        "dkim": dkim,

        "dmarc": dmarc,

        "findings": findings

    }