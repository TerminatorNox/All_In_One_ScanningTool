# All_In_One_ScanningTool
It supports Fast scanning and Totally based on GUI Mode with cool feature , Must try it at Once , you will enjoy it

# OmniScanner Pro

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red)
![Status](https://img.shields.io/badge/Status-Experimental-orange)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

> **Advanced Cybersecurity & Network Analysis Toolkit**  
> **Status:** Demo / Experimental Release

---

## 🛡️ About
**OmniScanner Pro** is a professional-grade, GUI-based cybersecurity toolkit developed in **Python (Tkinter)**. It consolidates essential **network scanning, reconnaissance, auditing, and cracking utilities** into a single unified interface.

This project is designed for:
- Cybersecurity students
- Ethical hackers
- Network administrators
- Academic labs & demonstrations

⚠️ **Legal Notice:** OmniScanner Pro must be used **only on systems and networks you own or have explicit authorization to test**. Unauthorized usage may violate local or international laws.

---

## 🚀 Key Features

- Port Scanner
- Ping Scanner
- Subdomain Enumeration
- Vulnerability Banner Grabbing
- Web Header Auditing
- Network Packet Sniffer (Root/Admin)
- Hash Cracker (MD5, SHA1, SHA256)
- ZIP File Password Cracker
- IP Geo‑Location Lookup
- Execution Mode Detection
- Creator Scratchpad

---


## 🧰 Requirements

### System Requirements
- OS: Linux / macOS / Windows
- Python: **3.8+**
- Root/Admin access *(required for packet sniffing)*

### Python Dependencies
```bash
pip install requests scapy
```

> Note: Tkinter is bundled with standard Python installations.

---

## ⚙️ Installation Guide

### 1️⃣ Clone Repository
```bash

git clone https://github.com/TerminatorNox/All_In_One_ScanningTool.git

cd omni-scanner-pro

```

### 2️⃣ (Recommended) Create Virtual Environment
```bash

python -m venv venv

source venv/bin/activate      # Linux / macOS

venv\Scripts\activate         # Windows
```

### 3️⃣ Install Dependencies
```bash
pip install requests scapy
```

### 4️⃣ Launch Application
```bash
python main.py
```

For full functionality (packet capture):
```bash
sudo python main.py
```

---

## 📖 Usage Overview

### ▶ Execution Mode
- Automatically detects **Normal** or **Root/Admin** mode
- Displays privilege status in the *Mode* tab

### ▶ Port Scanner
1. Enter target IP
2. Click **Scan**
3. Review open ports

### ▶ Ping Scanner
1. Enter base IP (e.g., `192.168.1`)
2. Scan range for active hosts

### ▶ Reconnaissance
- Input domain name
- Enumerate common subdomains

### ▶ Network Analyzer
- Requires Root/Admin
- Apply BPF filters (`ip`, `tcp`, `udp`)
- Inspect packets and payloads

### ▶ Hash Cracker
- Provide hash value
- Select algorithm
- Load wordlist
- Start dictionary attack

### ▶ ZIP File Cracker
- Select protected ZIP
- Load wordlist
- Attempt password recovery

### ▶ IP Utilities
- Geo-locate public IP addresses

---

## 🔮 Roadmap (Planned Enhancements)
- Support for additional hash algorithms
- Multi-threaded cracking engine
- Advanced vulnerability detection
- Report export (PDF/HTML)
- Plugin-based module system
- Improved UI/UX & performance

---

## 📌 Conclusion
**OmniScanner Pro** serves as a comprehensive **learning and experimentation platform** for cybersecurity operations. While not intended for production pentesting, it provides strong foundational exposure to real-world security concepts and tooling.

🔬 This is an **experimental project** — features will evolve, improve, and expand over time.

---

## ⭐ Support & Contribution
- Fork the repository
- Submit issues or pull requests
- Suggestions and improvements are welcome

---

### 🙏 Thank You
Use responsibly. Learn continuously. Secure ethically.

