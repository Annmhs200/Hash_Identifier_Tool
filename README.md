# Hash Type Detector 
a web-based tool that identifies hashing algorithms from hash strings. Built with Flask 

## Features 
- Detects MD5, NTLM SHA-1, SHA-256, SHA-512, bcrypt, and Argon2
- Shows multiple possible algorithms when ambiguous (e.g., MD5 + NTLM FOR 32-character hashes)
- Provides reasoning for each detection
- Export results to JSON, CSV, or PDF
- Clean, professional web interface

## Installation 
```bash
pip install flask reportlab

