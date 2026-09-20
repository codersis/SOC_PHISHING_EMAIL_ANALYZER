import os
import re
import hashlib
from email import policy
from email.parser import BytesParser


# ==========================================================
# Helper: Extract email body
# ==========================================================

def extract_body(email_message):
    """
    Extract the readable body from an email.

    Preference:
    1. Plain-text body
    2. HTML body
    """

    plain_text = None
    html_text = None

    if email_message.is_multipart():

        for part in email_message.walk():

            content_type = part.get_content_type()
            disposition = part.get_content_disposition()

            # Ignore attachments
            if disposition == "attachment":
                continue

            try:
                content = part.get_content()
            except Exception:
                continue

            if content_type == "text/plain":

                if plain_text is None:
                    plain_text = content

            elif content_type == "text/html":

                if html_text is None:
                    html_text = content

    else:

        try:
            content = email_message.get_content()
        except Exception:
            content = ""

        if email_message.get_content_type() == "text/plain":

            plain_text = content

        elif email_message.get_content_type() == "text/html":

            html_text = content

    # Prefer plain text
    if plain_text:
        return plain_text

    if html_text:
        return html_text

    return ""


# ==========================================================
# Helper: Extract authentication headers
# ==========================================================

def extract_authentication_results(email_message):
    """
    Extract email authentication-related headers.

    IMPORTANT:
    This function does NOT independently verify SPF, DKIM,
    or DMARC.

    It only retrieves authentication information reported
    by the receiving mail infrastructure.
    """

    authentication_results = email_message.get(
        "Authentication-Results",
        ""
    )

    received_spf = email_message.get(
        "Received-SPF",
        ""
    )

    dkim_signature = email_message.get(
        "DKIM-Signature",
        ""
    )

    return {
        "authentication_results": authentication_results,
        "received_spf": received_spf,
        "dkim_signature": dkim_signature
    }


# ==========================================================
# Helper: Check suspicious attachment name
# ==========================================================

def check_attachment_risk(filename):
    """
    Detect suspicious attachment names.

    This includes:
    - Double extensions
    - Dangerous executable/script extensions
    """

    filename_lower = filename.lower()

    # ------------------------------------------------------
    # Dangerous extensions
    # ------------------------------------------------------

    dangerous_extensions = {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".ps1",
        ".hta",
        ".msi",
        ".dll",
        ".jar",
        ".lnk"
    }

    # ------------------------------------------------------
    # Double extension detection
    # ------------------------------------------------------

    parts = filename_lower.split(".")

    if len(parts) >= 3:

        final_extension = "." + parts[-1]

        previous_extension = "." + parts[-2]

        common_document_extensions = {
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".txt",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".zip"
        }

        if (
            previous_extension
            in common_document_extensions
            and
            final_extension
            in dangerous_extensions
        ):

            return {
                "risk": "HIGH",
                "reason": "Double extension detected"
            }

    # ------------------------------------------------------
    # Dangerous final extension
    # ------------------------------------------------------

    extension = os.path.splitext(
        filename_lower
    )[1]

    if extension in dangerous_extensions:

        return {
            "risk": "HIGH",
            "reason": (
                f"Potentially dangerous attachment "
                f"extension detected: {extension}"
            )
        }

    # ------------------------------------------------------
    # Normal attachment
    # ------------------------------------------------------

    return {
        "risk": "LOW",
        "reason": "No suspicious attachment extension detected"
    }


# ==========================================================
# Helper: Extract attachments
# ==========================================================

def extract_attachments(email_message):
    """
    Extract attachment metadata.

    For every attachment we collect:

    - Filename
    - Extension
    - Size
    - SHA-256
    - Risk
    - Reason

    The attachment is NOT executed.
    """

    attachments = []

    for part in email_message.walk():

        filename = part.get_filename()

        if not filename:
            continue

        # --------------------------------------------------
        # Decode attachment safely
        # --------------------------------------------------

        try:
            data = part.get_payload(
                decode=True
            )
        except Exception:
            data = None

        if data is None:
            data = b""

        # --------------------------------------------------
        # SHA-256
        # --------------------------------------------------

        sha256 = hashlib.sha256(
            data
        ).hexdigest()

        # --------------------------------------------------
        # File extension
        # --------------------------------------------------

        extension = os.path.splitext(
            filename
        )[1].lower()

        # --------------------------------------------------
        # Attachment risk
        # --------------------------------------------------

        risk_info = check_attachment_risk(
            filename
        )

        # --------------------------------------------------
        # Build attachment information
        # --------------------------------------------------

        attachment = {

            "filename": filename,

            "extension": extension,

            "size": len(data),

            "sha256": sha256,

            "risk": risk_info["risk"],

            "reason": risk_info["reason"]

        }

        attachments.append(
            attachment
        )

    return attachments


# ==========================================================
# Main Parser
# ==========================================================

def parse_email(file_path):
    """
    Parse an .eml file and return structured information.

    The parser performs:

    - Email header extraction
    - Body extraction
    - URL extraction
    - Domain extraction
    - IP extraction
    - Attachment extraction
    - SHA-256 generation
    - Authentication header extraction
    """

    # ------------------------------------------------------
    # Read .eml file
    # ------------------------------------------------------

    with open(
        file_path,
        "rb"
    ) as email_file:

        email_message = BytesParser(
            policy=policy.default
        ).parse(email_file)

    # ------------------------------------------------------
    # Headers
    # ------------------------------------------------------

    from_header = email_message.get(
        "From",
        ""
    )

    to_header = email_message.get(
        "To",
        ""
    )

    cc_header = email_message.get(
        "Cc",
        ""
    )

    reply_to_header = email_message.get(
        "Reply-To",
        ""
    )

    subject = email_message.get(
        "Subject",
        ""
    )

    date = email_message.get(
        "Date",
        ""
    )

    message_id = email_message.get(
        "Message-ID",
        ""
    )

    # ------------------------------------------------------
    # Body
    # ------------------------------------------------------

    body = extract_body(
        email_message
    )

    # ------------------------------------------------------
    # Attachments
    # ------------------------------------------------------

    attachments = extract_attachments(
        email_message
    )

    # ------------------------------------------------------
    # Authentication
    # ------------------------------------------------------

    authentication = extract_authentication_results(
        email_message
    )

    # ------------------------------------------------------
    # Return structured email information
    # ------------------------------------------------------

    return {

        "from": from_header,

        "to": to_header,

        "cc": cc_header,

        "reply_to": reply_to_header,

        "subject": subject,

        "date": date,

        "message_id": message_id,

        "body": body,

        "attachments": attachments,

        "authentication": authentication,

        # These will be populated later by extractor.py
        "urls": [],

        "domains": [],

        "ip_addresses": [],

        # These will be populated later
        "url_analysis": [],

        "vt_results": [],

        "authentication_analysis": {},

        "risk": {}

    }