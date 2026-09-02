import base64
import ipaddress
import json
import os
import re
from urllib.parse import urlparse

import requests
import whois
from groq import Groq


# ============================================================
# API CONFIGURATION
# ============================================================

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"

GROQ_MODEL = "openai/gpt-oss-20b"


# ============================================================
# INPUT VALIDATION
# ============================================================

def validate_input(input_type, value):

    value = value.strip()

    if not value:
        return False, "Please enter a value."

    if input_type == "Domain":

        pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

        if not re.match(pattern, value):
            return False, "Please enter a valid domain."

    elif input_type == "URL":

        parsed = urlparse(value)

        if parsed.scheme not in ["http", "https"] or not parsed.netloc:
            return False, (
                "Please enter a valid URL beginning with "
                "http:// or https://"
            )

    elif input_type == "IP Address":

        try:
            ipaddress.ip_address(value)

        except ValueError:
            return False, "Please enter a valid IP address."

    return True, ""


# ============================================================
# GET HOSTNAME
# ============================================================

def get_hostname(value):

    if value.startswith(("http://", "https://")):
        return urlparse(value).hostname

    return value


# ============================================================
# VIRUSTOTAL
# ============================================================

def get_virustotal_data(input_type, value):

    if not VIRUSTOTAL_API_KEY:

        return {
            "success": False,
            "message": "VirusTotal API key is missing."
        }

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:

        if input_type == "Domain":

            endpoint = f"{VT_BASE_URL}/domains/{value}"

        elif input_type == "IP Address":

            endpoint = f"{VT_BASE_URL}/ip_addresses/{value}"

        else:

            url_id = base64.urlsafe_b64encode(
                value.encode()
            ).decode().strip("=")

            endpoint = f"{VT_BASE_URL}/urls/{url_id}"

        response = requests.get(
            endpoint,
            headers=headers,
            timeout=30
        )

        if response.status_code == 404:

            return {
                "success": False,
                "message": "No VirusTotal record was found."
            }

        response.raise_for_status()

        data = response.json()["data"]

        attributes = data.get("attributes", {})

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        return {
            "success": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation", 0),
            "categories": attributes.get("categories", {})
        }

    except requests.exceptions.RequestException as e:

        return {
            "success": False,
            "message": f"VirusTotal request failed: {str(e)}"
        }

    except Exception as e:

        return {
            "success": False,
            "message": f"VirusTotal error: {str(e)}"
        }


# ============================================================
# WHOIS
# ============================================================

def get_whois_data(input_type, value):

    try:

        hostname = get_hostname(value)

        result = whois.whois(hostname)

        creation_date = result.creation_date
        expiration_date = result.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        return {
            "success": True,
            "domain": hostname,
            "registrar": result.registrar or "Not available",
            "creation_date": (
                str(creation_date)
                if creation_date
                else "Not available"
            ),
            "expiration_date": (
                str(expiration_date)
                if expiration_date
                else "Not available"
            ),
            "name_servers": (
                list(result.name_servers)
                if result.name_servers
                else []
            )
        }

    except Exception as e:

        return {
            "success": False,
            "message": f"WHOIS information unavailable: {str(e)}"
        }


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_fallback_risk(virustotal):

    # --------------------------------------------------------
    # INSUFFICIENT DATA
    # --------------------------------------------------------

    if not virustotal.get("success"):

        return {
            "score": None,
            "verdict": "INSUFFICIENT DATA",
            "confidence": "Low"
        }

    malicious = virustotal.get("malicious", 0)
    suspicious = virustotal.get("suspicious", 0)
    harmless = virustotal.get("harmless", 0)
    undetected = virustotal.get("undetected", 0)

    total = (
        malicious
        + suspicious
        + harmless
        + undetected
    )

    if total == 0:

        return {
            "score": None,
            "verdict": "INSUFFICIENT DATA",
            "confidence": "Low"
        }


    # --------------------------------------------------------
    # RISK SCORE
    # --------------------------------------------------------
    # Malicious detections have the strongest influence.
    # Suspicious detections have a smaller influence.
    #
    # The score is NOT a probability.
    # It is an assessment based on VirusTotal detections.

    malicious_percentage = (
        malicious / total
    ) * 100

    suspicious_percentage = (
        suspicious / total
    ) * 100

    score = (
        malicious_percentage
        + (suspicious_percentage * 0.5)
    )

    score = min(round(score), 100)


    # --------------------------------------------------------
    # VERDICT
    # --------------------------------------------------------
    # The verdict gives priority to the actual number
    # of malicious detections instead of allowing a large
    # number of harmless/undetected engines to hide them.

    if malicious >= 5:

        verdict = "LIKELY MALICIOUS"

    elif malicious >= 1:

        verdict = "SUSPICIOUS"

    elif suspicious >= 3:

        verdict = "SUSPICIOUS"

    else:

        verdict = "LIKELY SAFE"


    # --------------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------------
    # Confidence represents how much VirusTotal evidence
    # is available, NOT how certain the target is safe.

    if total >= 50:

        confidence = "High"

    elif total >= 20:

        confidence = "Medium"

    else:

        confidence = "Low"


    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    return {
        "score": score,
        "verdict": verdict,
        "confidence": confidence
    }

# ============================================================
# GROQ AI ANALYSIS
# ============================================================

def get_gemini_analysis(
    input_type,
    value,
    skill_level,
    virustotal_data,
    whois_data,
    risk
):

    # Keep function name unchanged so app.py does not need changes.

    if not GROQ_API_KEY:

        return {
            "success": False,
            "message": "Groq API key is missing."
        }

    # --------------------------------------------------------
    # VIRUSTOTAL INFORMATION
    # --------------------------------------------------------

    if virustotal_data.get("success"):

        vt_info = f"""
Malicious detections: {virustotal_data.get("malicious", 0)}
Suspicious detections: {virustotal_data.get("suspicious", 0)}
Harmless detections: {virustotal_data.get("harmless", 0)}
Undetected: {virustotal_data.get("undetected", 0)}
VirusTotal reputation: {virustotal_data.get("reputation", 0)}
"""

    else:

        vt_info = "VirusTotal information is unavailable."


    # --------------------------------------------------------
    # WHOIS INFORMATION
    # --------------------------------------------------------

    if whois_data.get("success"):

        whois_info = f"""
Domain/Host: {whois_data.get("domain", "Not available")}
Registrar: {whois_data.get("registrar", "Not available")}
Creation date: {whois_data.get("creation_date", "Not available")}
Expiration date: {whois_data.get("expiration_date", "Not available")}
"""

    else:

        whois_info = "WHOIS information is unavailable."


    # --------------------------------------------------------
    # PROMPT
    # --------------------------------------------------------

    prompt = f"""
You are ThreatLens AI, a cybersecurity explanation assistant.

Analyze this {input_type}:

TARGET:
{value}

USER KNOWLEDGE LEVEL:
{skill_level}

VIRUSTOTAL:
{vt_info}

WHOIS:
{whois_info}

THREAT ASSESSMENT:
Risk score: {risk.get("score")}
Verdict: {risk.get("verdict")}
Confidence: {risk.get("confidence")}

Your task is to explain the assessment clearly.

IMPORTANT RULES:

1. Base your answer ONLY on the supplied information.
2. Do not invent facts.
3. Do not claim that a target is definitely safe.
4. Do not claim that a target is definitely malicious.
5. The risk score is an assessment, NOT a probability.
6. If malicious detections exist, explain that they increase concern.
7. If suspicious detections exist, explain that they increase concern.
8. If malicious = 0 and suspicious = 0, explain that this is reassuring but does NOT guarantee safety.
9. Adapt the explanation to the user's knowledge level.
10. Give exactly 3 concise reasons.
11. Give one practical recommendation.
12. Keep the explanation concise and useful.

Return ONLY valid JSON in exactly this format:

{{
    "summary": "Short explanation of the assessment.",
    "reasons": [
        "Reason 1",
        "Reason 2",
        "Reason 3"
    ],
    "recommendation": "Practical recommendation."
}}
"""


    # --------------------------------------------------------
    # CREATE GROQ CLIENT
    # --------------------------------------------------------

    try:

        client = Groq(
            api_key=GROQ_API_KEY
        )

    except Exception as e:

        print("GROQ CLIENT ERROR:", repr(e))

        return {
            "success": False,
            "message": f"Groq client could not be created: {str(e)}"
        }


    # --------------------------------------------------------
    # GROQ REQUEST
    # --------------------------------------------------------

    try:

        print(
            f"Groq analysis for {value}"
        )

        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are ThreatLens AI, a cybersecurity "
                        "explanation assistant."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
            max_completion_tokens=1000,
            response_format={
                "type": "json_object"
            }
        )

        raw_text = response.choices[0].message.content

        if not raw_text:

            raise Exception(
                "Groq returned an empty response."
            )

        raw_text = raw_text.strip()

        # Remove accidental markdown fences if present
        raw_text = re.sub(
            r"^```json\s*",
            "",
            raw_text,
            flags=re.IGNORECASE
        )

        raw_text = re.sub(
            r"\s*```$",
            "",
            raw_text
        )

        analysis = json.loads(raw_text)

        # Basic validation
        if not isinstance(analysis, dict):

            raise Exception(
                "Groq returned invalid JSON structure."
            )

        if "summary" not in analysis:
            analysis["summary"] = "No summary was generated."

        if "reasons" not in analysis:
            analysis["reasons"] = []

        if "recommendation" not in analysis:
            analysis["recommendation"] = ""

        return {
            "success": True,
            "analysis": analysis
        }


    except Exception as e:

        error_text = str(e)

        print(
            "GROQ ERROR:",
            repr(e)
        )

        # ----------------------------------------------------
        # RATE LIMIT
        # ----------------------------------------------------

        if (
            "429" in error_text
            or "rate_limit" in error_text.lower()
            or "rate limit" in error_text.lower()
        ):

            return {
                "success": False,
                "message": (
                    "Groq API rate limit reached. "
                    "Please wait a moment and try again."
                )
            }

        # ----------------------------------------------------
        # OTHER ERROR
        # ----------------------------------------------------

        return {
            "success": False,
            "message": (
                f"Groq analysis failed: {error_text}"
            )
        }


# ============================================================
# MAIN ANALYSIS
# ============================================================

def analyze_target(
    input_type,
    value,
    skill_level
):

    # --------------------------------------------------------
    # VALIDATE INPUT
    # --------------------------------------------------------

    valid, message = validate_input(
        input_type,
        value
    )

    if not valid:

        return {
            "success": False,
            "message": message
        }


    # --------------------------------------------------------
    # VIRUSTOTAL
    # --------------------------------------------------------

    virustotal = get_virustotal_data(
        input_type,
        value
    )


    # --------------------------------------------------------
    # WHOIS
    # --------------------------------------------------------

    whois_data = get_whois_data(
        input_type,
        value
    )


    # --------------------------------------------------------
    # CALCULATE RISK
    # --------------------------------------------------------

    risk = calculate_fallback_risk(
        virustotal
    )


    # --------------------------------------------------------
    # GROQ AI
    # --------------------------------------------------------

    gemini = get_gemini_analysis(
        input_type,
        value,
        skill_level,
        virustotal,
        whois_data,
        risk
    )


    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    return {
        "success": True,
        "risk": risk,
        "gemini": gemini,
        "virustotal": virustotal,
        "whois": whois_data
    }
