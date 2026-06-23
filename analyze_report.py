from pathlib import Path
import argparse
import json


def load_report(report_file):
    """
    Loads a JSON phishing report created by report_phishing.py.
    """
    with open(report_file, "r", encoding="utf-8") as file:
        report = json.load(file)

    return report


def get_authentication_findings(report):
    """
    Reviews authentication results and returns notable findings.
    """
    findings = []

    auth_summary = report.get("authentication_summary", {})

    spf = auth_summary.get("spf", "")
    dkim = auth_summary.get("dkim", "")
    dmarc = auth_summary.get("dmarc", "")
    compauth = auth_summary.get("compauth", "")

    if spf and spf != "pass":
        findings.append(f"SPF did not pass. Result: {spf}")

    if dkim and dkim != "pass":
        findings.append(f"DKIM did not pass. Result: {dkim}")

    if dmarc and dmarc != "pass":
        findings.append(f"DMARC did not pass. Result: {dmarc}")

    if compauth and compauth != "pass":
        findings.append(f"CompAuth did not pass. Result: {compauth}")

    return findings


def get_domain_findings(report):
    """
    Reviews sender-related domain information.
    """
    findings = []

    domain_summary = report.get("domain_summary", {})
    domain_mismatches = report.get("domain_mismatches", [])

    from_domain = domain_summary.get("from_domain", "")
    reply_to_domain = domain_summary.get("reply_to_domain", "")
    return_path_domain = domain_summary.get("return_path_domain", "")

    if domain_mismatches:
        findings.append("Sender-related domain mismatch was found.")

    if from_domain and return_path_domain and from_domain != return_path_domain:
        findings.append(
            f"From domain '{from_domain}' does not match Return-Path domain '{return_path_domain}'."
        )

    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        findings.append(
            f"From domain '{from_domain}' does not match Reply-To domain '{reply_to_domain}'."
        )

    return findings


def get_url_findings(report):
    """
    Reviews URL-related artifacts.
    """
    findings = []

    url_count = report.get("url_count", 0)
    url_domains = report.get("url_domains", [])
    suspicious_urls = report.get("suspicious_urls", [])

    if url_count > 0:
        findings.append(f"Email contains {url_count} URL(s).")

    if url_domains:
        findings.append(f"Email contains {len(url_domains)} unique URL domain(s).")

    if suspicious_urls:
        findings.append(f"{len(suspicious_urls)} suspicious URL(s) were identified.")

    return findings


def get_attachment_findings(report):
    """
    Reviews attachment-related artifacts.
    """
    findings = []

    attachment_count = report.get("attachment_count", 0)
    attachment_findings = report.get("attachment_findings", [])

    if attachment_count > 0:
        findings.append(f"Email contains {attachment_count} attachment(s).")

    if attachment_findings:
        findings.append(f"{len(attachment_findings)} potentially risky attachment(s) were identified.")

    return findings


def calculate_risk_score(report):
    """
    Calculates a simple risk score based on report findings.
    """
    score = 0

    auth_summary = report.get("authentication_summary", {})
    domain_mismatches = report.get("domain_mismatches", [])
    suspicious_urls = report.get("suspicious_urls", [])
    attachment_findings = report.get("attachment_findings", [])
    url_count = report.get("url_count", 0)

    spf = auth_summary.get("spf", "")
    dkim = auth_summary.get("dkim", "")
    dmarc = auth_summary.get("dmarc", "")
    compauth = auth_summary.get("compauth", "")

    if spf and spf != "pass":
        score += 1

    if dkim and dkim != "pass":
        score += 1

    if dmarc and dmarc != "pass":
        score += 2

    if compauth and compauth != "pass":
        score += 2

    if domain_mismatches:
        score += 2

    if url_count > 0:
        score += 1

    if suspicious_urls:
        score += 2

    if attachment_findings:
        score += 3

    return score


def determine_risk_level(score):
    """
    Converts a numeric score into a basic risk level.
    """
    if score >= 7:
        return "High"

    if score >= 4:
        return "Medium"

    if score >= 1:
        return "Low"

    return "Informational"


def get_recommended_action(risk_level):
    """
    Returns a recommended analyst action based on the risk level.
    """
    if risk_level == "High":
        return "Treat this email as suspicious. Do not interact with links or attachments. Escalate for further review."

    if risk_level == "Medium":
        return "Review the sender, authentication results, URLs, and attachments before taking action."

    if risk_level == "Low":
        return "No major malicious indicators were identified, but the message should still be reviewed carefully."

    return "No obvious suspicious characteristics were identified by the available checks."


def print_analysis(report, risk_score, risk_level, findings, recommended_action):
    """
    Prints a clean analyst-style summary.
    """
    print("Phishing Report Analysis")
    print("========================")
    print()

    print("Email Summary:")
    print(f"From: {report.get('from', '')}")
    print(f"Subject: {report.get('subject', '')}")
    print(f"Date: {report.get('date', '')}")
    print()

    print("Risk Assessment:")
    print(f"Risk Level: {risk_level}")
    print(f"Risk Score: {risk_score}")
    print()

    print("Key Findings:")

    if findings:
        for finding in findings:
            print(f"- {finding}")
    else:
        print("- No notable findings identified.")

    print()

    print("Notable Domains:")

    domain_summary = report.get("domain_summary", {})
    url_domains = report.get("url_domains", [])

    from_domain = domain_summary.get("from_domain", "")
    reply_to_domain = domain_summary.get("reply_to_domain", "")
    return_path_domain = domain_summary.get("return_path_domain", "")

    if from_domain:
        print(f"- From Domain: {from_domain}")

    if reply_to_domain:
        print(f"- Reply-To Domain: {reply_to_domain}")

    if return_path_domain:
        print(f"- Return-Path Domain: {return_path_domain}")

    for domain in url_domains:
        print(f"- URL Domain: {domain}")

    print()

    print("Recommended Action:")
    print(recommended_action)


def parse_arguments():
    """
    Gets the JSON report path from the command line.
    """
    parser = argparse.ArgumentParser(
        description="Analyze a phishing JSON report created by report_phishing.py."
    )

    parser.add_argument(
        "report_file",
        help="Path to the JSON report file to analyze"
    )

    return parser.parse_args()


def main():
    args = parse_arguments()
    report_file = Path(args.report_file)

    if not report_file.exists():
        print(f"Error: File not found: {report_file}")
        return

    report = load_report(report_file)

    findings = []
    findings.extend(get_authentication_findings(report))
    findings.extend(get_domain_findings(report))
    findings.extend(get_url_findings(report))
    findings.extend(get_attachment_findings(report))

    risk_score = calculate_risk_score(report)
    risk_level = determine_risk_level(risk_score)
    recommended_action = get_recommended_action(risk_level)

    print_analysis(
        report,
        risk_score,
        risk_level,
        findings,
        recommended_action
    )


if __name__ == "__main__":
    main()