# Phishing Email Parser

A Python command-line tool for parsing suspicious `.eml` email files and extracting key artifacts commonly reviewed during phishing email investigations.

This project was built to make phishing email review faster, more organized, and easier to document. It takes a saved email file, extracts useful information from the headers and body, displays the results in the terminal, and saves a structured JSON report for later review.

---

## Overview

The Phishing Email Parser reads saved `.eml` files and collects important artifacts that are useful during email triage. Instead of manually searching through the raw email source, the tool organizes the most relevant information into a cleaner report.

The parser does not automatically decide whether an email is malicious. Its purpose is to support analyst review by extracting and organizing evidence such as sender information, authentication results, URLs, domains, and a preview of the message body.

---

## Features

- Parses saved `.eml` email files
- Extracts basic email metadata
- Extracts selected email header fields
- Parses authentication results for SPF, DKIM, DMARC, and CompAuth
- Extracts sender-related domains
- Extracts URLs from the email body
- Cleans and formats extracted URLs
- Counts total and unique URLs
- Displays a preview of the message body
- Generates a structured JSON report
- Saves report output to a local `reports/` folder

---

## What the Tool Extracts

The parser extracts and organizes information such as:

- Subject
- From address
- To address
- Date
- Reply-To header
- Return-Path header
- Message-ID
- Received headers
- Authentication-Results
- SPF result
- DKIM result
- DMARC result
- CompAuth result
- Sender-related domains
- URLs found in the message body
- Unique URL count
- Body preview
- JSON report output

---

## Why I Built This

This project started with the question: Can I build my own 'Report Phishing' button? 

When reviewing suspicious emails, important evidence is often spread across multiple parts of the message source. This tool helps collect that information into one organized output so the email can be reviewed more efficiently.

The project gave me practice working with:

- Python file handling
- Email parsing
- String processing
- Regular expressions
- URL extraction
- JSON report generation
- Command-line tool design

---

## Project Structure
```
Phishing-Report-Parser/
│
├── README.md
├── .gitignore
│
├── report_phishing.py
├── analyze_report.py
│
├── sample_data/
│   └── sample .eml files
│
├── reports/
│   ├── raw/
│   │   └── generated JSON reports
│   │
│   └── analyzed/
│       └── generated text analysis reports
│
└── screenshots/
    └── project screenshots and example output
```

---

## How It Works

The script `report_phishing.py` takes a saved `.eml` file as input.

It then:

1. Opens and reads the email file.
2. Parses the message using Python's email parsing tools.
3. Extracts key header fields.
4. Searches the body for URLs.
5. Cleans and organizes the extracted URLs.
6. Parses authentication results when available.
7. Extracts sender-related domains.
8. Displays the results in the terminal.
9. Saves the findings to a JSON report.

The script `analyze_report.py` takes the JSON report created by `report_phishing.py` as input.

It then:

1. Opens and reads the saved JSON report.
2. Reviews the extracted authentication results.
3. Checks for sender-related domain mismatches.
4. Reviews extracted URL and URL domain information.
5. Reviews attachment findings when available.
6. Builds a list of key findings for analyst review.
7. Calculates a basic risk score based on the report data.
8. Assigns a risk level such as Informational, Low, Medium, or High.
9. Displays a clean analyst-style summary in the terminal.
10. Saves the analyzed findings to a text report.

---

## Workflow

Run the script from the command line and provide the path to the `.eml` file:

```bash
python report_phishing.py sample_data/sample-1.eml
python analyze_report.py reports/raw/sample-1_report.json
```

The first command creates a raw JSON report and saves it in `reports/raw`.
The second command analyzes that JSON report and creates a more human-readable analysis file and saves it in `reports/analyzed`.

---

## Example Terminal Output

```text
=== Phishing Email Report ===

Subject: Example Suspicious Email
From: Example Sender <sender@example.com>
To: user@example.com
Date: Mon, 10 Jun 2026 14:30:00 -0500

=== Authentication Results ===
SPF: pass
DKIM: pass
DMARC: pass
CompAuth: pass

=== Sender Domains ===
From Domain: example.com
Return-Path Domain: example.com
Reply-To Domain: example.com

=== URLs Found ===
Total URLs: 3
Unique URLs: 2

1. https://example.com/login
2. https://tracking.example.com/click

=== Body Preview ===
This is a preview of the email body...
```

---

## Example JSON Report

```json
{
    "subject": "Example Suspicious Email",
    "from": "Example Sender <sender@example.com>",
    "to": "user@example.com",
    "date": "Mon, 10 Jun 2026 14:30:00 -0500",
    "authentication_results": {
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
        "compauth": "pass"
    },
    "sender_domains": {
        "from_domain": "example.com",
        "return_path_domain": "example.com",
        "reply_to_domain": "example.com"
    },
    "urls": [
        "https://example.com/login",
        "https://tracking.example.com/click"
    ],
    "unique_url_count": 2,
    "body_preview": "This is a preview of the email body..."
}
```

## Example Analyzed Report Output 

```text

Phishing Report Analysis
========================

Email Summary:
From: BANCO DO BRADESCO LIVELO <banco.bradesco@atendimento.com.br>
Subject: CLIENTE PRIME - BRADESCO LIVELO: Seu cartão tem 92.990 pontos LIVELO expirando hoje!
Date: Tue, 19 Sep 2023 18:35:49 +0000

Risk Assessment:
Risk Level: High
Risk Score: 9

Key Findings:
- SPF did not pass. Result: temperror
- DKIM did not pass. Result: none
- DMARC did not pass. Result: temperror
- CompAuth did not pass. Result: fail
- Sender-related domain mismatch was found.
- From domain 'atendimento.com.br' does not match Return-Path domain 'ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06'.
- Email contains 3 URL(s).
- Email contains 3 unique URL domain(s).

Notable Domains:
- From Domain: atendimento.com.br
- Return-Path Domain: ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06
- URL Domain: blog1seguimentmydomaine2bra.me
- URL Domain: fonts.gstatic.com
- URL Domain: fonts.googleapis.com

Recommended Action:
Treat this email as suspicious. Do not interact with links or attachments. Escalate for further review.

Analysis saved to: reports/analyzed/sample-1_analysis.txt
```

---

## Skills Demonstrated

This project demonstrates hands-on experience with:

- Python scripting
- Command-line tool development
- Email header analysis
- Phishing email artifact extraction
- URL parsing
- JSON report creation
- Basic SOC analyst investigation workflow
- Project documentation

---

## Limitations

This tool is designed to support email review, not replace analyst judgment.

Current limitations include:

- It does not determine if an email is malicious automatically.
- It does not perform live threat intelligence lookups.
- It does not sandbox links or files.
- It depends on the information available inside the `.eml` file.
- Some email clients may export messages differently, which may affect parsing results.

---

## Future Improvements

Planned or possible future improvements include:

- Add hash generation for attachments
- Add support for threat intelligence lookups
- Add domain reputation checks
- Add URL defanging for safer reporting
- Add CSV report output
- Add HTML report output
- Improve handling of multipart emails
- Add unit tests
- Add batch parsing for multiple `.eml` files

---

## Example Use Case

A user receives a suspicious email and saves it as an `.eml` file. The analyst runs the parser against the file and quickly receives a structured report showing the sender information, authentication results, extracted links, sender domains, and a preview of the email body.

The analyst can then use that information to support a phishing investigation, document findings, and decide whether further review is needed.

**SIEM Alerting:** Because the parser saves findings in structured JSON format, the output could be monitored by a SIEM and used to trigger alerts. Rules could be written to detect failed SPF/DKIM/DMARC results, sender domain mismatches, suspicious URLs, or risky attachment types.

---

## Disclaimer

This tool is for educational and defensive security purposes only. It is intended to help review suspicious emails in a safe and organized way.

Do not open suspicious links or attachments unless they are being handled in a controlled analysis environment.
