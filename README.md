# DEATH 13A

## Evidence-Driven Web Reconnaissance & Security Change Analysis Framework

DEATH 13A is a Python-based defensive web reconnaissance and security
change-analysis framework designed to collect publicly observable
information, preserve evidence, create historical snapshots, detect
changes, and generate security-focused reports.

## Features

- Target validation
- DNS reconnaissance
- HTTP reconnaissance
- TLS analysis
- WHOIS/domain information
- Security header analysis
- robots.txt analysis
- Sitemap analysis
- Evidence collection
- Evidence confidence
- Fingerprint generation
- Snapshot storage
- Historical comparison
- Change detection
- Change classification
- Impact analysis
- Evidence-backed reporting

## Project Structure

DEATH-13A/
│
├── core/
│   ├── analyzer.py
│   ├── change_analyzer.py
│   ├── change_detector.py
│   ├── change_report.py
│   ├── evidence.py
│   ├── fingerprint.py
│   ├── impact_analyzer.py
│   ├── storage.py
│   └── validator.py
│
├── recon/
│   ├── dns.py
│   ├── http.py
│   ├── robots.py
│   ├── security_headers.py
│   ├── sitemap.py
│   ├── tls.py
│   └── whois.py
│
├── report/
├── snapshots/
├── main.py
└── .gitignore

## Installation

Clone the repository:

git clone https://github.com/axiomcodex/DEATH-13A.git

Move into the project:

cd DEATH-13A

Install the required dependencies:

pip install -r requirements.txt

## Usage

Run the main program:

python main.py

Enter a domain that you are authorized to test.

## How It Works

DEATH 13A first validates the target and performs reconnaissance
using multiple modules.

The collected observations are converted into structured evidence.
A fingerprint is generated and the complete state is stored as a
snapshot.

When a previous snapshot exists, the framework compares the current
and previous states and identifies observable changes.

Each detected change can be linked to supporting evidence and
evaluated for severity, confidence and potential impact.

## Evidence Model

Evidence records provide traceability between observations and
detected changes.

Example:

EVD-001
Source: DNS
Confidence: HIGH

EVD-003
Source: DNS
Observation: AAAA record detected
Confidence: HIGH

## Change Detection

Example:

CHG-001

Source: DNS
Category: IPv6 Address
Change Type: CHANGED
Severity: LOW
Confidence: HIGH

## Ethical Use

DEATH 13A is intended for authorized defensive security testing,
security monitoring and reconnaissance.

Only use this framework against systems and domains that you own
or have explicit permission to test.

Do not use it for unauthorized access, exploitation or attacks.

## Author

Sheerin Parvin Noorjehan

B.Tech CSE (Cyber Security)

GitHub:
https://github.com/axiomcodex/DEATH-13A
