#  Sniffer

**Sniffer** is a powerful Python-based tool for real-time packet sniffing and traffic manipulation. It's designed for cybersecurity professionals and ethical hackers to analyze, intercept, and modify network traffic — especially in **Man-in-the-Middle (MITM)** attack scenarios.

---

##  Project Idea

The goal of this project is to provide a simple yet powerful framework to:
- Intercept network traffic (HTTP)
- Extract sensitive data (usernames, passwords, URLs)
- Inject malicious code (like JavaScript)
- Demonstrate how tools like **SSLStrip** can downgrade HTTPS to HTTP

All for educational and penetration testing purposes.

---

##  Features

- Real-time packet sniffing using `scapy`  
- Extract credentials and other sensitive info  
- Modify HTTP responses on the fly  
- Inject JavaScript into web pages  
- Simulate SSLStrip attacks  
- Easy CLI interface

---

##  Requirements

- Python 3.6 or higher
- Linux OS (recommended)
- Run as **root** or with `sudo` for full functionality

### Python dependencies:
- `scapy`
- `netfilterqueue`
- Standard modules: `os`, `sys`, `re`, `subprocess`

You can install missing modules using:

```bash
pip install -r requirements.txt
