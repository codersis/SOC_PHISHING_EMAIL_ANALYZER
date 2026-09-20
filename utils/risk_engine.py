from email.utils import parseaddr


# ==========================================================
# Risk Engine Configuration
# ==========================================================

MAX_SCORE = 100

LOW_RISK_THRESHOLD = 30
MEDIUM_RISK_THRESHOLD = 60


# ==========================================================
# Helper: Add Finding
# ==========================================================

def add_finding(findings, message):
    """
    Add a finding while avoiding duplicate messages.
    """

    if message not in findings:
        findings.append(message)


# ==========================================================
# Main Risk Calculation
# ==========================================================

def calculate_risk(email_info):
    """
    Calculate an explainable phishing risk score.

    The score is based on multiple pieces of evidence:

    - From / Reply-To mismatch
    - Suspicious URLs
    - VirusTotal URL reputation
    - Suspicious keywords
    - Attachment risk
    - VirusTotal file reputation
    - SPF
    - DKIM
    - DMARC

    Returns:

        {
            "score": int,
            "verdict": str,
            "findings": list,
            "risk_breakdown": list
        }
    """

    score = 0

    findings = []

    risk_breakdown = []

    # ======================================================
    # Basic Email Information
    # ======================================================

    from_email = parseaddr(
        email_info.get("from", "")
    )[1].lower()

    reply_to = parseaddr(
        email_info.get("reply_to", "")
    )[1].lower()

    body = email_info.get(
        "body",
        ""
    ).lower()

    urls = email_info.get(
        "urls",
        []
    )

    url_analysis = email_info.get(
        "url_analysis",
        []
    )

    vt_results = email_info.get(
        "vt_results",
        []
    )

    attachments = email_info.get(
        "attachments",
        []
    )

    authentication_analysis = email_info.get(
        "authentication_analysis",
        {}
    )

    # ======================================================
    # 1. Reply-To Mismatch
    # ======================================================

    if (
        from_email
        and reply_to
        and from_email != reply_to
    ):

        points = 20

        score += points

        add_finding(
            findings,
            (
                "Reply-To address differs from "
                "the From address."
            )
        )

        risk_breakdown.append({

            "indicator": "Reply-To mismatch",

            "points": points

        })

    # ======================================================
    # 2. URLs Present
    # ======================================================

    if urls:

        points = 5

        score += points

        add_finding(
            findings,
            f"Email contains {len(urls)} URL(s)."
        )

        risk_breakdown.append({

            "indicator": "URLs present",

            "points": points

        })

    # ======================================================
    # 3. URL Analysis
    # ======================================================

    for analysis in url_analysis:

        url = analysis.get(
            "url",
            "Unknown URL"
        )

        url_score = analysis.get(
            "score",
            0
        )

        url_findings = analysis.get(
            "findings",
            []
        )

        # ----------------------------------------------
        # Add URL-specific findings
        # ----------------------------------------------

        for finding in url_findings:

            add_finding(
                findings,
                f"{finding} [{url}]"
            )

        # ----------------------------------------------
        # Add URL risk score
        # ----------------------------------------------

        if url_score > 0:

            # Limit contribution from one URL.
            points = min(
                url_score,
                30
            )

            score += points

            risk_breakdown.append({

                "indicator": (
                    f"Suspicious URL: {url}"
                ),

                "points": points

            })

    # ======================================================
    # 4. VirusTotal Results
    # ======================================================

    for result in vt_results:

        indicator = result.get(
            "indicator",
            "Unknown"
        )

        indicator_type = result.get(
            "type",
            ""
        )

        stats = result.get(
            "stats",
            {}
        )

        malicious = stats.get(
            "malicious",
            0
        )

        suspicious = stats.get(
            "suspicious",
            0
        )

        # ----------------------------------------------
        # Malicious detection
        # ----------------------------------------------

        if malicious >= 5:

            points = 35

            score += points

            add_finding(
                findings,
                (
                    f"VirusTotal reports "
                    f"{malicious} malicious detections "
                    f"for {indicator}."
                )
            )

            risk_breakdown.append({

                "indicator": (
                    f"VirusTotal malicious: {indicator}"
                ),

                "points": points

            })

        elif malicious > 0:

            points = 20

            score += points

            add_finding(
                findings,
                (
                    f"VirusTotal reports "
                    f"{malicious} malicious detection(s) "
                    f"for {indicator}."
                )
            )

            risk_breakdown.append({

                "indicator": (
                    f"VirusTotal malicious: {indicator}"
                ),

                "points": points

            })

        # ----------------------------------------------
        # Suspicious detection
        # ----------------------------------------------

        elif suspicious > 0:

            points = 10

            score += points

            add_finding(
                findings,
                (
                    f"VirusTotal reports "
                    f"{suspicious} suspicious detection(s) "
                    f"for {indicator}."
                )
            )

            risk_breakdown.append({

                "indicator": (
                    f"VirusTotal suspicious: {indicator}"
                ),

                "points": points

            })

    # ======================================================
    # 5. Suspicious Email Keywords
    # ======================================================

    suspicious_keywords = {

        "urgent",
        "verify",
        "verification",
        "password",
        "account",
        "login",
        "click here",
        "confirm",
        "immediately",
        "bank",
        "invoice",
        "payment",
        "security alert",
        "update your account"

    }

    matched_keywords = []

    for keyword in suspicious_keywords:

        if keyword in body:

            matched_keywords.append(
                keyword
            )

    if matched_keywords:

        # Keep keyword scoring limited.
        points = min(
            len(matched_keywords) * 2,
            10
        )

        score += points

        add_finding(
            findings,
            (
                "Suspicious keywords detected: "
                + ", ".join(
                    sorted(matched_keywords)
                )
            )
        )

        risk_breakdown.append({

            "indicator": "Suspicious email language",

            "points": points

        })

    # ======================================================
    # 6. Attachment Analysis
    # ======================================================

    for attachment in attachments:

        filename = attachment.get(
            "filename",
            "Unknown"
        )

        attachment_risk = attachment.get(
            "risk",
            "LOW"
        )

        reason = attachment.get(
            "reason",
            ""
        )

        # ----------------------------------------------
        # HIGH-risk attachment
        # ----------------------------------------------

        if attachment_risk == "HIGH":

            points = 15

            score += points

            add_finding(
                findings,
                (
                    f"Suspicious attachment: "
                    f"{filename} - {reason}."
                )
            )

            risk_breakdown.append({

                "indicator": (
                    f"Suspicious attachment: {filename}"
                ),

                "points": points

            })

        # ----------------------------------------------
        # Normal attachment
        # ----------------------------------------------

        else:

            points = 3

            score += points

            add_finding(
                findings,
                (
                    f"Attachment present: "
                    f"{filename}."
                )
            )

            risk_breakdown.append({

                "indicator": (
                    f"Attachment present: {filename}"
                ),

                "points": points

            })

    # ======================================================
    # 7. Authentication Results
    # ======================================================

    spf = authentication_analysis.get(
        "spf",
        "UNKNOWN"
    )

    dkim = authentication_analysis.get(
        "dkim",
        "UNKNOWN"
    )

    dmarc = authentication_analysis.get(
        "dmarc",
        "UNKNOWN"
    )

    # ------------------------------------------------------
    # SPF
    # ------------------------------------------------------

    if spf == "FAIL":

        points = 15

        score += points

        add_finding(
            findings,
            "SPF authentication failed."
        )

        risk_breakdown.append({

            "indicator": "SPF failure",

            "points": points

        })

    elif spf == "SOFTFAIL":

        points = 8

        score += points

        add_finding(
            findings,
            "SPF returned SOFTFAIL."
        )

        risk_breakdown.append({

            "indicator": "SPF softfail",

            "points": points

        })

    # ------------------------------------------------------
    # DKIM
    # ------------------------------------------------------

    if dkim == "FAIL":

        points = 15

        score += points

        add_finding(
            findings,
            "DKIM authentication failed."
        )

        risk_breakdown.append({

            "indicator": "DKIM failure",

            "points": points

        })

    # ------------------------------------------------------
    # DMARC
    # ------------------------------------------------------

    if dmarc == "FAIL":

        points = 20

        score += points

        add_finding(
            findings,
            "DMARC authentication failed."
        )

        risk_breakdown.append({

            "indicator": "DMARC failure",

            "points": points

        })

    # ======================================================
    # 8. Final Score
    # ======================================================

    score = min(
        max(score, 0),
        MAX_SCORE
    )

    # ======================================================
    # 9. Determine Verdict
    # ======================================================

    if score >= MEDIUM_RISK_THRESHOLD:

        verdict = "HIGH RISK"

    elif score >= LOW_RISK_THRESHOLD:

        verdict = "MEDIUM RISK"

    else:

        verdict = "LOW RISK"

    # ======================================================
    # 10. Return Result
    # ======================================================

    return {

        "score": score,

        "verdict": verdict,

        "findings": findings,

        "risk_breakdown": risk_breakdown

    }