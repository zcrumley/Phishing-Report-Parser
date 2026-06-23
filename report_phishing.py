from email import policy
from email.parser import BytesParser
from pathlib import Path
from email.utils import parseaddr
import argparse
import re
import json


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


def build_report(message, body, urls, attachments ):
    """
    Builds a structured phishing report from parsed email data.
    """
    from_header = get_header(message, "From")
    reply_to_header = get_header(message, "Reply-To")
    return_path_header = get_header(message, "Return-Path")
    authentication_results = get_header(message, "Authentication-Results")

    report = {
        "from": from_header,
        "to": get_header(message, "To"),
        "reply_to": reply_to_header,
        "subject": get_header(message, "Subject"),
        "date": get_header(message, "Date"),
        "message_id": get_header(message, "Message-Id"),
        "return_path": return_path_header,
        "authentication_results": authentication_results,
        "authentication_summary": parse_authentication_results(authentication_results),
        "received_spf": get_header(message, "Received-SPF"),
        "sender_ip": get_header(message, "X-Sender-IP"),
        "content_type": get_header(message, "Content-Type"),
        "content_transfer_encoding": get_header(message, "Content-Transfer-Encoding"),
        "domain_summary": {
            "from_domain": extract_domain(from_header),
            "reply_to_domain": extract_domain(reply_to_header),
            "return_path_domain": extract_domain(return_path_header)
        },
        "urls": urls,
        "url_count": len(urls),
        "body_preview": body[:500],
        "attachments": attachments,
        "attachment_count": len(attachments),
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
    reports_dir.mkdir(exist_ok=True)

    output_file = reports_dir / f"{email_file.stem}_report.json"
    save_report(report, output_file)

    print("Email parsed successfully.")
    print()
    print(f"From: {get_header(message, 'From')}")
    print(f"To: {get_header(message, 'To')}")
    print(f"Subject: {get_header(message, 'Subject')}")
    print(f"Date: {get_header(message, 'Date')}")
    print(f"Message-ID: {get_header(message, 'Message-Id')}")
    print(f"Return-Path: {get_header(message, 'Return-Path')}")
    print(f"Authentication-Results: {get_header(message, 'Authentication-Results')}")
    print(f"Received-SPF: {get_header(message, 'Received-SPF')}")
    print(f"Sender IP: {get_header(message, 'X-Sender-IP')}")
    print(f"Content-Type: {get_header(message, 'Content-Type')}")
    print(f"Content-Transfer-Encoding: {get_header(message, 'Content-Transfer-Encoding')}")
    print()
    print("Body Preview:")
    print(body[:500])

    print()
    print(f"URLs Found: {len(urls)}")

    for url in urls:
        print(f"- {url}")    

    print()
    print(f"Report saved to: {output_file}")    

    print()
    print(f"Attachments Found: {len(attachments)}")

    for attachment in attachments:
        print(f"- Filename: {attachment['filename']}")
        print(f"  Content-Type: {attachment['content_type']}")
        print(f"  Size: {attachment['size_bytes']} bytes")
        print(f"  SHA-256: {attachment['sha256']}")


if __name__ == "__main__":
    main()