<p align="center">
<img src="banner.png" alt="SINGHAM Banner" width="100%">
</p>

<h1 align="center">
🛡️ SINGHAM
</h1>

<h3 align="center">
Secure Intelligence for Network Guarding, Hazard Analysis & Monitoring
</h3>

<p align="center">

<img src="https://readme-typing-svg.herokuapp.com?font=Orbitron&weight=700&size=24&duration=3000&pause=1200&color=00E6A8&center=true&vCenter=true&width=900&lines=AI-Powered+Cybersecurity+Platform;Detect+Phishing+Emails;Analyze+Malicious+URLs;Scan+Fake+QR+Codes;Identify+Malware+Downloads;Explain+Threats+Using+AI" />

</p>

<p align="center">

<img src="https://img.shields.io/badge/Status-Under%20Development-orange?style=for-the-badge">

<img src="https://img.shields.io/badge/Backend-Flask-blue?style=for-the-badge">

<img src="https://img.shields.io/badge/Frontend-VanillaJS-yellow?style=for-the-badge">

<img src="https://img.shields.io/badge/Machine%20Learning-XGBoost-success?style=for-the-badge">

<img src="https://img.shields.io/badge/License-MIT-red?style=for-the-badge">

<img src="https://img.shields.io/github/stars/USERNAME/REPOSITORY?style=for-the-badge">

<img src="https://img.shields.io/github/issues/USERNAME/REPOSITORY?style=for-the-badge">

</p>

---

# 🚀 Overview

**SINGHAM** is an AI-powered cybersecurity platform designed to help everyday internet users detect and understand digital threats before they become victims.

Instead of relying on multiple disconnected security tools, SINGHAM brings email analysis, malicious URL detection, fake QR code verification, malware detection, and AI-powered explanations into a single intelligent platform.

The goal is to make cybersecurity simple, understandable, and accessible for everyone.

---

# ❗ Problem Statement

Modern cyber attacks have become increasingly sophisticated.

Every day, users receive phishing emails, click malicious links, scan fake QR codes, and unknowingly download malware.

Most existing security tools focus on only one threat category, forcing users to switch between multiple services while still lacking a complete understanding of why something is dangerous.

For non-technical users, distinguishing legitimate content from malicious content has become extremely difficult.

SINGHAM addresses this challenge by providing one unified platform capable of analyzing multiple cyber threats while explaining every prediction in simple language.

---

# 💡 Solution

SINGHAM combines Machine Learning and Large Language Models to analyze different cybersecurity threats through a single web interface.

Instead of simply labeling something as "Safe" or "Dangerous", the platform also explains **why** the prediction was made using Explainable AI (XAI).

Users receive actionable recommendations that help them make safer online decisions while gradually improving their cybersecurity awareness.

---

# ✨ Core Features

## 📧 AI Email Phishing Detection

- Analyze suspicious emails
- Detect phishing attempts
- LLM + RAG powered reasoning
- Explain why an email is dangerous

---

## 🌐 Scam URL Detection

- Detect malicious websites
- Analyze URL structure
- Domain feature analysis
- Machine Learning classification

---

## 📱 Fake QR Code Detection

- Decode QR codes
- Validate destination URLs
- Detect phishing redirections
- Warn before opening websites

---

## 🦠 Malware Detection

- Scan uploaded files
- Analyze executable files
- Compare file hashes
- Detect known malware signatures

---

## 🤖 Explainable AI (XAI)

Unlike traditional security software,

SINGHAM explains

- Why a threat was detected
- Which indicators were suspicious
- Risk level
- Recommended actions

making AI decisions understandable for everyone.

---

# 🏗️ System Architecture

```text
                     User
                       │
                       ▼
              SINGHAM Web Platform
                       │
 ┌──────────────┬──────────────┬──────────────┬──────────────┐
 ▼              ▼              ▼              ▼
Email       URL Scanner     QR Scanner    File Scanner
Analyzer
 │              │              │              │
 └──────────────┴──────────────┴──────────────┘
                ▼
      Machine Learning Models
      (XGBoost + Random Forest)
                │
                ▼
        Gemini LLM + RAG Engine
                │
                ▼
     Explainable AI (SHAP + LLM)
                │
                ▼
         Threat Report Dashboard
```

---

# 🛠 Technology Stack

## Frontend

- HTML5
- CSS3
- Vanilla JavaScript

---

## Backend

- Flask
- Gunicorn

---

## Machine Learning

- XGBoost
- Random Forest
- Scikit-learn
- SHAP

---

## AI

- Gemini 3.5 Flash
- Gemini Embeddings
- LangChain
- Retrieval Augmented Generation (RAG)

---

## Vector Database

- FAISS

---

## Libraries

- Pandas
- NumPy
- pefile
- PyMuPDF

---

## Deployment

- Render

---

## Version Control

- Git
- GitHub

---

# 📂 Project Structure

```
SINGHAM/

│

├── backend/

├── frontend/

├── models/

├── rag/

├── datasets/

├── uploads/

├── static/

├── templates/

├── utils/

├── docs/

├── tests/

├── requirements.txt

├── .env.example

└── README.md
```

---

# 📸 Screenshots

> 🚧 Screenshots will be added as development progresses.

```
Dashboard

Email Detection

URL Scanner

QR Scanner

Malware Scanner

Threat Report

History Page
```

---

# 🎯 Development Roadmap

- ✅ Project Planning
- ✅ System Design
- ✅ Dataset Collection
- ⏳ Frontend Development
- ⏳ Backend APIs
- ⏳ Email Detection
- ⏳ URL Detection
- ⏳ QR Detection
- ⏳ Malware Detection
- ⏳ AI Explanation Engine
- ⏳ Dashboard
- ⏳ Deployment

---

# 📌 Current Status

🚧 This project is currently under active development.

Features, UI, documentation, and APIs will continue to evolve as the project progresses.

---

# ⚙️ Setup

> 🚧 The setup guide will be published once the first stable version of SINGHAM is released.

The setup section will include:

- Running the project locally
- Environment variables
- Backend configuration
- Frontend configuration
- API keys
- Production deployment guide
- Docker support *(planned)*
