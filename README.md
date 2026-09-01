# 🛡️ ThreatLens AI

ThreatLens AI is an AI-powered cybersecurity analysis tool that helps users assess the potential risk of URLs, domains, and IP addresses.

The application combines *VirusTotal threat intelligence, WHOIS information, rule-based risk assessment, and AI-generated explanations* to provide an easy-to-understand security assessment.

---

## ✨ Features

* Analyze URLs
* Analyze domains
* Analyze IP addresses
* VirusTotal threat intelligence
* WHOIS information
* Automated risk score
* Threat assessment
* AI-powered security explanation using Groq
* Beginner, Intermediate, and Advanced knowledge levels
* Practical security recommendations
* Simple Streamlit web interface

---

## 🧠 How It Works

ThreatLens AI follows these steps:

1. The user enters a URL, domain, or IP address.
2. The input is validated.
3. VirusTotal is queried for available threat intelligence.
4. WHOIS information is retrieved when available.
5. A risk score is calculated using VirusTotal detection statistics.
6. Groq AI analyzes the collected information.
7. The application presents:

   * Risk Score
   * Threat Assessment
   * Confidence Level
   * AI-generated Summary
   * Reasons for the assessment
   * Security Recommendation
   * VirusTotal Details
   * WHOIS Details

---

## 🛠️ Technologies Used

* **Python**
* **Streamlit**
* **VirusTotal API**
* **Groq API**
* **WHOIS**
* **Requests**
* **Regular Expressions**
* **IP Address Validation**

---

## 📁 Project Structure

```text
ThreatLens-AI/
│
├── app.py
├── sources.py
├── requirements.txt
├── README.md

```

### `app.py`

Contains the Streamlit user interface and displays the analysis results.

### `sources.py`

Contains:

* Input validation
* VirusTotal API integration
* WHOIS lookup
* Risk calculation
* Groq AI analysis

### `requirements.txt`

Contains the Python packages required to run the application.

---

## 🔑 API Keys

ThreatLens AI requires API keys for:

* VirusTotal
* Groq

The application reads the keys from environment variables:

```python
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/IzzaMustafa/ThreatLens-AI.git
cd ThreatLens-AI
```

Install the required packages:

```bash
pip install -r requirements.txt
```

---

## 🔐 Configure API Keys

Set the required environment variables.

### Linux / macOS

```bash
export GROQ_API_KEY="your_groq_api_key"
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
```

### Windows PowerShell

```powershell
$env:GROQ_API_KEY="your_groq_api_key"
$env:VIRUSTOTAL_API_KEY="your_virustotal_api_key"
```

---

## ▶️ Run the Application

Start the Streamlit application:

```bash
streamlit run app.py
```

The application will normally be available at:

```text
http://localhost:8501
```

---

## 🤖 AI Model

ThreatLens AI uses **Groq** for AI-powered cybersecurity explanations.

### Current Model

```text
openai/gpt-oss-20b
```

The AI is instructed to:

* Base its explanation only on the information supplied by the application.
* Avoid inventing facts.
* Avoid claiming that a target is definitely safe.
* Avoid claiming that a target is definitely malicious.
* Adapt explanations to the user's knowledge level.
* Provide concise reasons and a practical recommendation.

---

## 📊 Risk Assessment

The application calculates a risk assessment score using **VirusTotal detection statistics**.

Malicious detections receive the highest weight, while suspicious detections contribute a lower weight.

The resulting assessment can be:

* **LIKELY SAFE**
* **SUSPICIOUS**
* **LIKELY MALICIOUS**
* **INSUFFICIENT DATA**

---

## ⚠️ Disclaimer

ThreatLens AI is intended for educational and informational purposes.

A clean VirusTotal result or a low risk score does not guarantee that a URL, domain, or IP address is completely safe.

Users should perform additional security checks before interacting with potentially suspicious resources.

---

## 🚀 Future Improvements

Possible future improvements include:

* Historical analysis
* Additional threat intelligence sources
* DNS analysis
* SSL/TLS certificate analysis
* URL reputation history
* More detailed security reports
* Threat intelligence visualizations
* Exportable PDF reports
* User authentication
* Production deployment

---

## 👩‍💻 Author

**Izza Mustafa Jadoon**

---

## 📄 License

This project is intended for educational and research purposes.
