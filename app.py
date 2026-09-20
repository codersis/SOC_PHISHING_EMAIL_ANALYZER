from flask import Flask, render_template, request
import os

from utils.parser import parse_email
from utils.extractor import extract_iocs
from utils.url_analyzer import analyze_urls
from utils.auth_analyzer import analyze_authentication
from utils.virustotal import check_urls, check_hashes
from utils.risk_engine import calculate_risk
from utils.report_generator import generate_report

# ==========================================================
# Flask Application
# ==========================================================

app = Flask(__name__)

# Maximum email file size: 10 MB
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


# ==========================================================
# Home Page
# ==========================================================

@app.route("/")
def index():
    return render_template("index.html")


# ==========================================================
# Analyze Email
# ==========================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    # ------------------------------------------------------
    # Check uploaded file
    # ------------------------------------------------------

    if "email_file" not in request.files:

        return render_template(
            "index.html",
            error="No email file was uploaded."
        )

    uploaded_file = request.files["email_file"]

    if uploaded_file.filename == "":

        return render_template(
            "index.html",
            error="Please select an .eml file."
        )

    # ------------------------------------------------------
    # Validate extension
    # ------------------------------------------------------

    filename = uploaded_file.filename.lower()

    if not filename.endswith(".eml"):

        return render_template(
            "index.html",
            error="Only .eml email files are supported."
        )

    # ------------------------------------------------------
    # Create temporary upload directory
    # ------------------------------------------------------

    upload_dir = "temp_uploads"

    os.makedirs(
        upload_dir,
        exist_ok=True
    )

    file_path = os.path.join(
        upload_dir,
        uploaded_file.filename
    )

    try:

        # Save uploaded email temporarily
        uploaded_file.save(file_path)

        # ==================================================
        # STEP 1 — Parse Email
        # ==================================================

        email_info = parse_email(
            file_path
        )

        # ==================================================
        # STEP 2 — Extract IOCs
        # ==================================================

        iocs = extract_iocs(
            email_info.get("body", "")
        )

        # Add extracted IOCs to email information

        email_info["urls"] = iocs.get(
            "urls",
            []
        )

        email_info["domains"] = iocs.get(
            "domains",
            []
        )

        email_info["ip_addresses"] = iocs.get(
            "ip_addresses",
            []
        )

        # ==================================================
        # STEP 3 — Analyze URLs
        # ==================================================

        url_analysis = analyze_urls(
            email_info["urls"]
        )

        email_info["url_analysis"] = (
            url_analysis
        )
        # ==================================================
        # STEP 4 — Analyze Authentication
        # ==================================================

        authentication_data = email_info.get(        
    "authentication",
    {}
)
        
        # Debug output
        print("\n========== AUTHENTICATION DATA ==========")

        print(        
    "Authentication-Results:",
    authentication_data.get(
        "authentication_results",
        ""
    )
)

        print(        
    "Received-SPF:",
    authentication_data.get(
        "received_spf",
        ""
    )
)

        print(
              "DKIM-Signature:",
              authentication_data.get(
                  "dkim_signature",
                  ""
              )
        )

        print("=========================================\n")


        authentication_analysis = analyze_authentication(authentication_data)

        email_info["authentication_analysis"] = (authentication_analysis)

        
        # ==================================================
        # STEP 5 — VirusTotal URL Analysis
        # ==================================================

        vt_results = []

        if email_info["urls"]:

            vt_results = check_urls(
                email_info["urls"]
            )

        # ==================================================
        # STEP 6 — VirusTotal Attachment Hash Analysis
        # ==================================================

        attachment_hashes = []

        for attachment in email_info.get(
            "attachments",
            []
        ):

            sha256 = attachment.get(
                "sha256"
            )

            if sha256:

                attachment_hashes.append(
                    sha256
                )

        vt_file_results = []

        if attachment_hashes:

            vt_file_results = check_hashes(
                attachment_hashes
            )

        # Combine URL + file VirusTotal results

        email_info["vt_results"] = (
            vt_results + vt_file_results
        )

        # ==================================================
        # STEP 7 — Calculate Risk
        # ==================================================

        risk_result = calculate_risk(
            email_info
        )

        


        # ==================================================
        # STEP 8 — Generate SOC Report
        # ==================================================

        report = generate_report(
            email_info,
            risk_result
        )

        # ==================================================
        # STEP 9 — Display Result
        # ==================================================

        return render_template(
            "result.html",
            report=report
        )

    except Exception as error:

        return render_template(
            "index.html",
            error=(
                "An error occurred while analyzing "
                f"the email: {error}"
            )
        )

    finally:

        # --------------------------------------------------
        # Delete temporary email file
        # --------------------------------------------------

        if os.path.exists(file_path):

            try:
                os.remove(file_path)

            except OSError:
                pass


# ==========================================================
# Run Application
# ==========================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )