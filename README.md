# 🛡️ CYBER RAKSHA AI

**Public AI-Powered Cyber Fraud Detection & Prevention Portal**

A free, fully client-side cybersecurity web portal that detects spam messages from strangers, software bugs & vulnerabilities, and malicious links — all running locally in your browser with zero backend or server required.

## 🚀 Live Demo

Deployed on Vercel → [https://cyber-raksha-ai.vercel.app](https://cyber-raksha-ai.vercel.app)

## ✨ Features

### 🔍 AI Spam & Fraud Message Detector
- Analyzes SMS, WhatsApp, Telegram, email, and social media messages sent by strangers
- Detects phishing, KYC/OTP theft, crypto scams, fake job offers, parcel fee smishing
- Highlights exact manipulation trigger phrases in the message
- Scores risk `0–100` with 6 independent signal dimensions
- Auto-redacts PII before community reporting

### 🐛 Bug, Vulnerability & Malicious Link Scanner
- Static code scanner covering **CWE-89** (SQL Injection), **CWE-79** (XSS), **CWE-94** (eval/RCE), **CWE-78** (OS command injection), **CWE-798** (hardcoded secrets), **CWE-506** (obfuscated payloads), **CWE-502** (unsafe deserialization), weak crypto, prototype pollution, and logic bugs
- URL anatomy inspector: punycode/homograph spoofing, raw IP hosts, disposable TLDs, `@` authority tricks, open-redirect parameters, and executable download links
- Gives per-finding secure remediation guidance

### 📡 Public Threat Feed
- Community-submitted scam/malware advisories with auto-redacted PII
- Searchable and filterable by category and severity
- Upvote confirmations and citizen report submission

### 🎓 Prevention & Citizen Defense Hub
- Interactive **Spot-the-Scam** drill (real-world test scenarios)
- Emergency **Incident Response Playbooks** (Clicked a link / Shared OTP / Sent money / Ran code)
- Official cybercrime reporting links for India, USA, UK, and EU

### 🤖 Optional Live AI Copilot
- Works 100% offline with built-in heuristic AI by default
- Optional: connect **local Ollama** (llama3.2, mistral, etc.) for LLM explanations
- Optional: use **Google Gemini API** (bring your own key — stored only in-session)

## 🔒 Privacy

> **Zero-Trust Privacy**: All scans run locally in your browser. No data is sent to any server unless you explicitly click "Report to Public Threat Feed", which auto-strips emails, phone numbers, card numbers, and API keys before saving.

## 📁 Project Structure

```
CYBER-RAKSHA-AI/
├── index.html          # Multi-tab portal UI
├── styles.css          # Dark cyber-defense responsive styles
├── vercel.json         # Vercel static deployment config
└── js/
    ├── spam-engine.js  # AI spam/phishing/scam message analyzer
    ├── bug-engine.js   # Static code vulnerability & URL scanner
    ├── community.js    # Threat feed, quiz questions & playbooks
    └── app.js          # Main UI controller & tab router
```

## 🛠️ Local Development

No build step needed. Just open `index.html` in any modern browser:

```bash
# Option 1: Direct file open
start index.html

# Option 2: Serve locally with Python
python -m http.server 3000
# Then open http://localhost:3000

# Option 3: VS Code Live Server extension
# Right-click index.html → Open with Live Server
```

## 🌐 Deploy to Vercel

```bash
# Install Vercel CLI
npm install -g vercel

# Deploy from project root
vercel

# Or connect GitHub repo in Vercel dashboard for auto-deploy
```

## 📋 Reporting Real Cybercrime

| Country | Portal |
|---------|--------|
| 🇮🇳 India | [cybercrime.gov.in](https://cybercrime.gov.in) · Helpline **1930** |
| 🇺🇸 USA | [ic3.gov](https://ic3.gov) · [reportfraud.ftc.gov](https://reportfraud.ftc.gov) |
| 🇬🇧 UK | [actionfraud.police.uk](https://actionfraud.police.uk) · Text scams to **7726** |
| 🌍 EU/Global | [Europol](https://europol.europa.eu) · [apwg.org](https://apwg.org) |

---

*Built with ❤️ for public cyber safety. All detection runs client-side — no backend, no tracking.*
