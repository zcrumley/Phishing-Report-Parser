from email import policy
from email.parser import BytesParser
from pathlib import Path
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
    Finds URLs in the email body.
    """
    url_pattern = r"https?://[^\s\"'<>]+"
    return re.findall(url_pattern, text)


def build_report(message, body, urls):
    """
    Builds a structured phishing report from parsed email data.
    """
    report = {
        "from": get_header(message, "From"),
        "to": get_header(message, "To"),
        "subject": get_header(message, "Subject"),
        "date": get_header(message, "Date"),
        "message_id": get_header(message, "Message-Id"),
        "return_path": get_header(message, "Return-Path"),
        "authentication_results": get_header(message, "Authentication-Results"),
        "received_spf": get_header(message, "Received-SPF"),
        "sender_ip": get_header(message, "X-Sender-IP"),
        "content_type": get_header(message, "Content-Type"),
        "content_transfer_encoding": get_header(message, "Content-Transfer-Encoding"),
        "urls": urls,
        "url_count": len(urls),
        "body_preview": body[:500]
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

    report = build_report(message, body, urls)
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


if __name__ == "__main__":
    main()