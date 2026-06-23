from email import policy
from email.parser import BytesParser
from pathlib import Path
from email.utils import parseaddr
from urllib.parse import urlparse
import argparse
import re
import json
import hashlib


def load_email(file_path):
    """
    Loads a raw .eml file and parses it into an email message object.
    """
    with open(file_path, "rb") as file:
        message = BytesParser(policy=policy.default).parse(file)

    return message


def get_header(message, header_name):
    """
    Safely gets a header value from the email.
    """
    return str(message.get(header_name, ""))


def extract_domain(email_value):
    """
    Extracts the domain from an email address or header value.
    """
    if not email_value:
        return ""

    _, email_address = parseaddr(email_value)

    if "@" not in email_address:
        return ""

    return email_address.split("@")[-1].lower()


def analyze_domain_mismatches(from_domain, reply_to_domain, return_path_domain):
    """
    Compares sender-related domains and identifies mismatches.
    """
    mismatches = []

    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        mismatches.append({
            "type": "from_reply_to_mismatch",
            "description": "From domain does not match Reply-To domain.",
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain
        })

    if from_domain and return_path_domain and from_domain != return_path_domain:
        mismatches.append({
            "type": "from_return_path_mismatch",
            "description": "From domain does not match Return-Path domain.",
            "from_domain": from_domain,
            "return_path_domain": return_path_domain
        })

    return mismatches


def extract_body(message):
    """
    Extracts the text or HTML body from the email.
    """
    body_parts = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()

            if content_type in ["text/plain", "text/html"]:
                body_parts.append(part.get_content())
    else:
        body_parts.append(message.get_content())

    return "\n".join(body_parts)


def extract_urls(text):
    """
    Finds unique URLs in the email body.
    """
    url_pattern = r"https?://[^\s\"'<>]+"
    urls = re.findall(url_pattern, text)

    return list(dict.fromkeys(urls))


def extract_url_domains(urls):
    """
    Extracts unique domains from a list of URLs.
    """
    domains = []

    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()

        if domain.startswith("www."):
            domain = domain[4:]

        if domain and domain not in domains:
            domains.append(domain)

    return domains


def analyze_urls(urls):
    """
    Reviews extracted URLs for simple suspicious characteristics.
    """
    suspicious_urls = []

    for url in urls:
        reasons = []

        # Checks for an @ symbol before the path.
        # Example: https://trusted-site.com@malicious-site.com/login
        if re.search(r"https?://[^/]*@", url, re.IGNORECASE):
            reasons.append("URL contains @ symbol before the domain/path")

        if url.count("-") >= 3:
            reasons.append("URL contains multiple hyphens")

        if len(url) > 100:
            reasons.append("URL is unusually long")

        if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
            reasons.append("URL uses an IP address instead of a domain")

        if re.search(r"(login|verify|account|secure|update|password)", url, re.IGNORECASE):
            reasons.append("URL contains common credential-themed wording")

        if reasons:
            suspicious_urls.append({
                "url": url,
                "reasons": reasons
            })

    return suspicious_urls


def extract_attachments(message):
    """
    Extracts attachment metadata from the email without opening or executing files.
    """
    attachments = []

    for part in message.walk():
        content_disposition = part.get_content_disposition()
        filename = part.get_filename()

        if content_disposition == "attachment" or filename:
            payload = part.get_payload(decode=True)

            if payload is None:
                file_size = 0
                sha256_hash = ""
            else:
                file_size = len(payload)
                sha256_hash = hashlib.sha256(payload).hexdigest()

            attachment_info = {
                "filename": filename or "",
                "content_type": part.get_content_type(),
                "size_bytes": file_size,
                "sha256": sha256_hash
            }

            attachments.append(attachment_info)

    return attachments


def analyze_attachments(attachments):
    """
    Reviews attachments for file types commonly used in phishing or malware delivery.
    """
    risky_extensions = [
        ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1",
        ".zip", ".rar", ".iso", ".img", ".docm", ".xlsm"
    ]

    attachment_findings = []

    for attachment in attachments:
        filename = attachment["filename"].lower()
        reasons = []

        for extension in risky_extensions:
            if filename.endswith(extension):
                reasons.append(f"Attachment uses potentially risky file extension: {extension}")

        if attachment["size_bytes"] == 0:
            reasons.append("Attachment has no decoded payload or size could not be determined")

        if reasons:
            attachment_findings.append({
                "filename": attachment["filename"],
                "content_type": attachment["content_type"],
                "size_bytes": attachment["size_bytes"],
                "sha256": attachment["sha256"],
                "reasons": reasons
            })

    return attachment_findings


def parse_authentication_results(auth_results):
    """
    Extracts SPF, DKIM, DMARC, and CompAuth results from Authentication-Results.
    """
    auth_summary = {
        "spf": "",
        "dkim": "",
        "dmarc": "",
        "compauth": ""
    }

    lower_auth = auth_results.lower()

    spf_match = re.search(r"spf=([a-zA-Z0-9_-]+)", lower_auth)
    dkim_match = re.search(r"dkim=([a-zA-Z0-9_-]+)", lower_auth)
    dmarc_match = re.search(r"dmarc=([a-zA-Z0-9_-]+)", lower_auth)
    compauth_match = re.search(r"compauth=([a-zA-Z0-9_-]+)", lower_auth)

    if spf_match:
        auth_summary["spf"] = spf_match.group(1)

    if dkim_match:
        auth_summary["dkim"] = dkim_match.group(1)

    if dmarc_match:
        auth_summary["dmarc"] = dmarc_match.group(1)

    if compauth_match:
        auth_summary["compauth"] = compauth_match.group(1)

    return auth_summary


def build_triage_summary(authentication_summary, domain_mismatches, suspicious_urls, attachment_findings):
    """
    Builds a simple analyst-focused summary of notable findings.
    """
    findings = []

    if authentication_summary["spf"] and authentication_summary["spf"] != "pass":
        findings.append(f"SPF result was {authentication_summary['spf']}")

    if authentication_summary["dkim"] and authentication_summary["dkim"] != "pass":
        findings.append(f"DKIM result was {authentication_summary['dkim']}")

    if authentication_summary["dmarc"] and authentication_summary["dmarc"] != "pass":
        findings.append(f"DMARC result was {authentication_summary['dmarc']}")

    if authentication_summary["compauth"] and authentication_summary["compauth"] != "pass":
        findings.append(f"CompAuth result was {authentication_summary['compauth']}")

    if domain_mismatches:
        findings.append("Sender-related domain mismatch found")

    if suspicious_urls:
        findings.append("Suspicious URL characteristics found")

    if attachment_findings:
        findings.append("Potentially risky attachment characteristics found")

    if not findings:
        findings.append("No obvious suspicious characteristics identified by basic checks")

    return findings


def build_report(message, body, urls, attachments):
    """
    Builds a structured phishing report from parsed email data.
    """
    from_header = get_header(message, "From")
    reply_to_header = get_header(message, "Reply-To")
    return_path_header = get_header(message, "Return-Path")
    authentication_results = get_header(message, "Authentication-Results")

    from_domain = extract_domain(from_header)
    reply_to_domain = extract_domain(reply_to_header)
    return_path_domain = extract_domain(return_path_header)

    authentication_summary = parse_authentication_results(authentication_results)

    domain_mismatches = analyze_domain_mismatches(
        from_domain,
        reply_to_domain,
        return_path_domain
    )

    url_domains = extract_url_domains(urls)
    suspicious_urls = analyze_urls(urls)
    attachment_findings = analyze_attachments(attachments)

    triage_summary = build_triage_summary(
        authentication_summary,
        domain_mismatches,
        suspicious_urls,
        attachment_findings
    )

    report = {
        "from": from_header,
        "to": get_header(message, "To"),
        "reply_to": reply_to_header,
        "subject": get_header(message, "Subject"),
        "date": get_header(message, "Date"),
        "message_id": get_header(message, "Message-Id"),
        "return_path": return_path_header,
        "authentication_results": authentication_results,
        "authentication_summary": authentication_summary,
        "received_spf": get_header(message, "Received-SPF"),
        "sender_ip": get_header(message, "X-Sender-IP"),
        "content_type": get_header(message, "Content-Type"),
        "content_transfer_encoding": get_header(message, "Content-Transfer-Encoding"),
        "domain_summary": {
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain
        },
        "domain_mismatches": domain_mismatches,
        "urls": urls,
        "url_count": len(urls),
        "url_domains": url_domains,
        "url_domain_count": len(url_domains),
        "suspicious_urls": suspicious_urls,
        "suspicious_url_count": len(suspicious_urls),
        "body_preview": body[:500],
        "attachments": attachments,
        "attachment_count": len(attachments),
        "attachment_findings": attachment_findings,
        "triage_summary": triage_summary
    }

    return report


def save_report(report, output_file):
    """
    Saves the phishing report to a JSON file.
    """
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)


def parse_arguments():
    """
    Gets the email file path from the command line.
    """
    parser = argparse.ArgumentParser(
        description="Parse a reported phishing email from a .eml file."
    )

    parser.add_argument(
        "email_file",
        help="Path to the .eml file to analyze"
    )

    return parser.parse_args()


def main():
    args = parse_arguments()
    email_file = Path(args.email_file)

    if not email_file.exists():
        print(f"Error: File not found: {email_file}")
        return

    message = load_email(email_file)
    body = extract_body(message)
    urls = extract_urls(body)
    attachments = extract_attachments(message)

    report = build_report(message, body, urls, attachments)

    reports_dir = Path("reports")
    raw_reports_dir = reports_dir / "raw"
    raw_reports_dir.mkdir(parents=True, exist_ok=True)

    output_file = raw_reports_dir / f"{email_file.stem}_report.json"
    save_report(report, output_file)

    print("Email parsed successfully.")
    print()
    print("Email Metadata:")
    print(f"From: {report['from']}")
    print(f"To: {report['to']}")
    print(f"Subject: {report['subject']}")
    print(f"Date: {report['date']}")
    print(f"Message-ID: {report['message_id']}")
    print(f"Return-Path: {report['return_path']}")

    print()
    print("Authentication:")
    print(f"Authentication-Results: {report['authentication_results']}")
    print(f"Received-SPF: {report['received_spf']}")
    print(f"SPF: {report['authentication_summary']['spf']}")
    print(f"DKIM: {report['authentication_summary']['dkim']}")
    print(f"DMARC: {report['authentication_summary']['dmarc']}")
    print(f"CompAuth: {report['authentication_summary']['compauth']}")

    print()
    print("Technical Headers:")
    print(f"Sender IP: {report['sender_ip']}")
    print(f"Content-Type: {report['content_type']}")
    print(f"Content-Transfer-Encoding: {report['content_transfer_encoding']}")

    print()
    print("Domain Summary:")
    print(f"From Domain: {report['domain_summary']['from_domain']}")
    print(f"Reply-To Domain: {report['domain_summary']['reply_to_domain']}")
    print(f"Return-Path Domain: {report['domain_summary']['return_path_domain']}")

    print()
    print(f"Domain Mismatches Found: {len(report['domain_mismatches'])}")

    for mismatch in report["domain_mismatches"]:
        print(f"- {mismatch['description']}")

    print()
    print("Body Preview:")
    print(report["body_preview"])

    print()
    print(f"URLs Found: {report['url_count']}")

    for url in report["urls"]:
        print(f"- {url}")

    print()
    print(f"URL Domains Found: {report['url_domain_count']}")

    for domain in report["url_domains"]:
        print(f"- {domain}")

    print()
    print(f"Suspicious URLs Found: {report['suspicious_url_count']}")

    for suspicious_url in report["suspicious_urls"]:
        print(f"- {suspicious_url['url']}")

        for reason in suspicious_url["reasons"]:
            print(f"  Reason: {reason}")

    print()
    print(f"Attachments Found: {report['attachment_count']}")

    for attachment in report["attachments"]:
        print(f"- Filename: {attachment['filename']}")
        print(f"  Content-Type: {attachment['content_type']}")
        print(f"  Size: {attachment['size_bytes']} bytes")
        print(f"  SHA-256: {attachment['sha256']}")

    print()
    print(f"Attachment Findings: {len(report['attachment_findings'])}")

    for finding in report["attachment_findings"]:
        print(f"- {finding['filename']}")

        for reason in finding["reasons"]:
            print(f"  Reason: {reason}")

    print()
    print("Triage Summary:")

    for finding in report["triage_summary"]:
        print(f"- {finding}")

    print()
    print(f"Report saved to: {output_file}")


if __name__ == "__main__":
    main()