# 📁 PII Redaction Model

**Live Demo:** [pii-redaction-solution-by-samokoye.streamlit.app](https://pii-redaction-solution-by-samokoye.streamlit.app)  
**Author:** Sam Okoye

---

## 📌 Overview
This project delivers a **privacy‑first, automated PII redaction pipeline** for call metadata and free‑form text.  
It detects and masks personally identifiable information (PII) using **lightweight, regex‑based detection patterns** — no heavy NLP models required — making it fast, portable, and easy to deploy.

The solution is designed for **both technical and non‑technical audiences**:
- **Non‑technical users** can upload files or test sentences via a simple Streamlit UI.
- **Technical users** can review the modular Python code, AWS integration points, and per‑session metrics tracking for audit and performance analysis.

---

## ✨ Features
- **Multi‑mode input**: Upload JSON/TXT files or enter a single sentence.
- **Regex‑based PII detection**: Emails, phone numbers, credit cards, dates, IPs, postal codes, and more.
- **Masking engine**: Replaces detected PII with format‑preserving placeholders.
- **Audit logging**: Generates tamper‑proof audit logs for compliance.
- **Metrics tracking**: Captures latency, PII density, and accuracy metrics per session.
- **Per‑session isolation**: Each user sees only their own metrics; data is cleared after inactivity.
- **Scalable architecture**: Designed for AWS S3, Lambda, EventBridge, DynamoDB, CloudWatch, IAM, and KMS.
- **Business‑friendly summaries**: Generates plain‑English summaries of redaction results.

---

## 🏗️ Architecture
**Core components:**
- **`app_v2.py`** – Streamlit UI, session management, and orchestration.
- **`redactor.py`** – Regex patterns and masking logic for PII detection.
- **`metrics.py`** – Per‑session metrics storage, retrieval, and summarization.
- **AWS Services (optional)** – For production deployment:  
  - S3 (Raw, Curated, Audit zones)  
  - EventBridge (file detection)  
  - Lambda (redaction)  
  - DynamoDB (search index)  
  - CloudWatch (monitoring)  
  - IAM & KMS (security)

### Compact Architecture Diagram:
```User Upload (JSON/TXT or Single Sentence)
    -->
Secure Storage (S3 Raw Zone)
    -->
Regex Masking Engine (Lambda or Local Processing)
    --> Sanitized Data Storage (S3 Curated Zone) --> Analytics / Search / AI
    --> Audit Log Storage (S3 Audit Zone) --> Compliance Review
```
---

## 🚀 Getting Started

### 1️⃣ Clone the repository
```bash
git clone https://github.com/ineuralworks/pii_redaction_model.git
cd pii_redaction_model
```

### 2️⃣ Install dependencies
```bash
pip install -r requirements.txt
```

### 3️⃣ Run locally
```bash
streamlit run app_v2.py
```

---

## 🖥️ Usage

### **Single Sentence Mode**
1. Select *Single Sentence Mode* in the UI.
2. Enter a sentence containing dummy PII.
3. View the masked output and metrics.

**Example:**
```
Our support email is icochran@example.org, but you can also call 637.872.5738x038 if Allen Barton isn't online.
```

### **File Upload Mode**
1. Upload a `.json` or `.txt` file containing call metadata.
2. The app will detect and mask PII in each sentence.
3. Download sanitized output and audit logs.

---

## 📊 Metrics & Audit
- **File Metrics**: PII count, density, latency, audit generation time.
- **Text Metrics**: Latency and PII count for single sentences.
- **Accuracy Metrics**: Precision, recall, F1 score (when ground truth is available).
- **Audit Logs**: CSV reports of detected and masked entities.

Metrics are **per‑session** and automatically cleared after inactivity.

---

## 🛡️ Privacy & Compliance
- All processing is in‑memory; no user data is stored persistently in the demo.
- Audit logs are stored separately for compliance review.
- Designed to meet enterprise privacy and governance requirements.

---

## 📦 Deployment Notes
- **Local**: Run via Streamlit for testing and demos.
- **Cloud**: Deploy to Streamlit Cloud or integrate with AWS Lambda + S3 for production.
- **Security**: Use IAM roles with least privilege and KMS for encryption.

---

## 📜 License
This project is released under the MIT License.

---

## 🙌 Acknowledgements
- Python `re` module for regex‑based detection.
- [Streamlit](https://streamlit.io/) for the interactive UI.

---
