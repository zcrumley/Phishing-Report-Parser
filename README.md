# Phishing Email Parser

A Python command-line tool for parsing suspicious email files and extracting key artifacts used during phishing email investigations.

This project was built to practice SOC analyst-style email triage, artifact extraction, and basic investigation workflow automation.

---

## Overview

The Phishing Email Parser reads saved `.eml` files and extracts useful information from the email headers and body. The goal is to make phishing email review faster and more organized by pulling important artifacts into a readable terminal format.

This tool does not determine whether an email is malicious on its own. It is designed to support analyst review by organizing evidence that can be used during a phishing investigation.

---

## Features

- Parses `.eml` email files
- Extracts sender, recipient, subject, and date fields
- Extracts URLs from the email body
- Cleans and formats URL output
- Displays selected email header information
- Organizes artifacts into readable sections
- Supports manual phishing email triage

---

## Purpose

Phishing investigations often require analysts to review email metadata, sender information, header details, links, and body content. This project helps automate part of that process by extracting important artifacts from a suspicious email file.

This project demonstrates:

- Python scripting for cybersecurity tasks
- Email artifact extraction
- Basic phishing triage workflow
- Command-line tool development
- Git and GitHub version control
- SOC analyst-style evidence gathering

---

## Technologies Used

- Python
- Python built-in `email` module
- Regular expressions
- Git
- GitHub
- Command line

---

## How It Works

The script loads a saved email file, parses the message content, and prints key artifacts in a structured format.

Current output includes:

- Subject
- From address
- To address
- Date sent
- Extracted URLs
- Selected header fields

---

## Example Use Case

A user reports a suspicious email. Instead of manually reviewing the raw email file, an analyst can run the parser against the saved `.eml` file to quickly collect important investigation artifacts.

Basic workflow:

1. Save the suspicious email as an `.eml` file.
2. Run the parser against the email file.
3. Review the extracted metadata.
4. Review any URLs found in the message body.
5. Use the results to support a phishing investigation write-up.

---

## Example Command

    python report_phishing.py suspicious_email.eml

---

## Example Output

    ==============================
    Email Metadata
    ==============================
    Subject: Example Security Alert
    From: sender@example.com
    To: user@example.com
    Date: Mon, 22 Jun 2026 10:30:00 -0500

    ==============================
    Extracted URLs
    ==============================
    https://example.com/login
    https://example.com/reset-password

    ==============================
    Header Information
    ==============================
    Authentication-Results: ...
    Received: ...
    Return-Path: ...

---

## Current Status

This project is currently in progress.

Completed so far:

- Initial parser script created
- Basic email metadata extraction added
- URL extraction added
- URL output cleaned and improved
- Git feature branch workflow practiced
- Pull request and merge workflow practiced

Planned improvements:

- Improve command-line argument handling
- Add support for multiple email files
- Export results to a report file
- Extract attachment metadata
- Parse SPF, DKIM, and DMARC results more clearly
- Add error handling for malformed email files
- Add sanitized sample emails for testing

---

## Key Takeaways

This project helped reinforce how phishing email investigations are performed from a SOC analyst perspective. It also showed how Python can be used to automate repetitive parts of security analysis while still requiring analyst judgment.

Key takeaways:

- Email metadata can provide important investigation context
- URLs should be extracted and reviewed carefully
- Automation can make phishing triage faster and more consistent
- Clear output formatting makes security tools easier to use
- Git branches and pull requests help keep project development organized

---

## Future Goals

The long-term goal is to continue improving this into a more complete phishing triage tool.

Possible future features:

- JSON or CSV export
- Markdown report generation
- Attachment hash extraction
- URL reputation lookup integration
- URL shortener detection
- Sender domain mismatch detection
- Basic phishing indicator summary

---

## Disclaimer

This tool is for educational and defensive cybersecurity purposes only. It is intended to support phishing email analysis and SOC analyst training.
