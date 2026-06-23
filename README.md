# Phishing Email Parser

A Python command-line tool for parsing suspicious `.eml` email files and extracting key artifacts used during phishing email investigations.

This project was built to practice SOC analyst-style email triage, artifact extraction, and basic investigation workflow automation.

---

## Overview

The Phishing Email Parser reads saved `.eml` files, extracts useful information from the email headers and body, and generates a structured JSON report. The goal is to make phishing email review faster and more organized by collecting important artifacts in both terminal output and a saved report file.

This tool does not determine whether an email is malicious on its own. It is designed to support analyst review by organizing evidence that can be used during a phishing investigation.

---

## Features

- Parses saved `.eml` email files
- Extracts basic email metadata
- Extracts selected email header fields
- Extracts URLs from the email body
- Counts unique URLs found in the message
- Cleans and formats URL output
- Parses authentication results for SPF, DKIM, DMARC, and CompAuth
- Extracts domains from sender-related headers
- Displays a body preview
- Saves results to a structured JSON report
- Automatically creates a `reports/` directory for output files
- Supports manual phishing email triage workflows

---

## Extracted Artifacts

The parser currently extracts the following artifacts:

- From address
- To address
- Reply-To address
- Subject
- Date
- Message-ID
- Return-Path
- Authentication-Results
- SPF result
- DKIM result
- DMARC result
- CompAuth result
- Received-SPF
- Sender IP, when available
- Content-Type
- Content-Transfer-Encoding
- From domain
- Reply-To domain
- Return-Path domain
- URLs found in the email body
- URL count
- Body preview

---

## Purpose

Phishing investigations often require analysts to review email metadata, sender information, authentication results, domain relationships, links, and body content. This project helps automate part of that process by extracting important artifacts from a suspicious email file and saving them in a structured report.

This project demonstrates:

- Python scripting for cybersecurity tasks
- Email artifact extraction
- Basic phishing triage workflow
- Command-line tool development
- JSON report generation
- Git and GitHub version control
- SOC analyst-style evidence gathering

---

## Technologies Used

- Python
- Python built-in `email` module
- Python `argparse`
- Python `pathlib`
- Python `json`
- Regular expressions
- Git
- GitHub
- Command line

---

## How It Works

The script takes a saved `.eml` file as a command-line argument, parses the email, extracts key artifacts, prints the results to the terminal, and saves a JSON report in the `reports/` directory.

Current workflow:

1. Load the `.eml` file.
2. Parse the email using Python's email parser.
3. Extract header fields and metadata.
4. Extract the plain text or HTML body.
5. Find unique URLs in the email body.
6. Parse authentication results.
7. Extract sender-related domains.
8. Build a structured report.
9. Save the report as a JSON file.
10. Print a readable summary to the terminal.

---

## Example Command

    python report_phishing.py suspicious_email.eml

---

## Example Terminal Output

    Email parsed successfully.

    From: sender@example.com
    To: user@example.com
    Subject: Example Security Alert
    Date: Mon, 22 Jun 2026 10:30:00 -0500
    Message-ID: <example-message-id@example.com>
    Return-Path: <sender@example.com>
    Authentication-Results: spf=pass dkim=pass dmarc=pass
    Received-SPF: pass
    Sender IP: 192.0.2.10
    Content-Type: text/html
    Content-Transfer-Encoding: quoted-printable

    Body Preview:
    Example email body preview text...

    URLs Found: 2
    - https://example.com/login
    - https://example.com/reset-password

    Report saved to: reports/suspicious_email_report.json

---

## Example JSON Report Structure

    {
        "from": "sender@example.com",
        "to": "user@example.com",
        "reply_to": "reply@example.com",
        "subject": "Example Security Alert",
        "date": "Mon, 22 Jun 2026 10:30:00 -0500",
        "message_id": "<example-message-id@example.com>",
        "return_path": "<sender@example.com>",
        "authentication_results": "spf=pass dkim=pass dmarc=pass",
        "authentication_summary": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "compauth": ""
        },
        "received_spf": "pass",
        "sender_ip": "192.0.2.10",
        "content_type": "text/html",
        "content_transfer_encoding": "quoted-printable",
        "domain_summary": {
            "from_domain": "example.com",
            "reply_to_domain": "example.com",
            "return_path_domain": "example.com"
        },
        "urls": [
            "https://example.com/login",
            "https://example.com/reset-password"
        ],
        "url_count": 2,
        "body_preview": "Example email body preview text..."
    }

---

## Current Status

This project is currently in progress.

Completed so far:

- Initial parser script created
- Command-line argument handling added
- `.eml` file loading added
- Basic email metadata extraction added
- Email body extraction added
- URL extraction added
- Duplicate URL cleanup added
- Authentication result parsing added
- Domain extraction added
- JSON report generation added
- Automatic report folder creation added
- Terminal summary output added
- Git feature branch workflow practiced
- Pull request and merge workflow practiced

Planned improvements:

- Add support for multiple email files
- Improve handling for malformed or unusual email formats
- Improve HTML body cleanup
- Extract attachment metadata
- Add attachment hash extraction
- Add optional CSV or Markdown report export
- Add sanitized sample emails for testing
- Add unit tests
- Add URL reputation lookup integration
- Add sender domain mismatch detection

---

## Key Takeaways

This project helped reinforce how phishing email investigations are performed from a SOC analyst perspective. It also showed how Python can be used to automate repetitive parts of security analysis while still requiring analyst judgment.

Key takeaways:

- Email headers contain important investigation artifacts
- Authentication results help provide context about sender legitimacy
- Sender, Reply-To, and Return-Path domains should be reviewed carefully
- URLs should be extracted and reviewed during phishing triage
- JSON output makes results easier to save, review, and expand later
- Automation can make phishing triage faster and more consistent
- Clear output formatting makes security tools easier to use
- Git branches and pull requests help keep project development organized

---

## Future Goals

The long-term goal is to continue improving this into a more complete phishing triage helper.

Possible future features:

- JSON, CSV, or Markdown export options
- Attachment metadata and hash extraction
- URL reputation lookup integration
- URL shortener detection
- Sender domain mismatch detection
- Improved authentication result analysis
- Basic phishing indicator summary
- Batch processing for multiple `.eml` files
- Unit tests for parser functions

---

## Disclaimer

This tool is for educational and defensive cybersecurity purposes only. It is intended to support phishing email analysis and SOC analyst training.
