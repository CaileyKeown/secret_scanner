import argparse
import logging
import re
from pathlib import Path

logging.basicConfig(
    filename="secret_scanner.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

SECRET_PATTERNS = {
    # Patterns based on the regextokens GitHub resource
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Google OAuth Access Token": r"ya29\.[0-9A-Za-z-_]+",
    "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth Token": r"gho_[a-zA-Z0-9]{36}",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "Shopify Access Token": r"shpat_[a-fA-F0-9]{32}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "NPM Access Token": r"npm_[A-Za-z0-9]{36}",
    "Slack Bot Token": r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}",

    # Extra common secret patterns
    "Password Assignment": r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]",
    "Private Key": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
}

def scan_file(file_path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line_number, line in enumerate(file, start=1):
                for secret_type, pattern in SECRET_PATTERNS.items():
                    matches = re.finditer(pattern, line)

                    for match in matches:
                        findings.append({
                            "file": str(file_path),
                            "line": line_number,
                            "type": secret_type,
                            "match": match.group()
                        })

    except Exception as error:
        logging.error(f"Could not scan {file_path}: {error}")

    return findings

def scan_path(path):
    all_findings = []
    path = Path(path)

    if path.is_file():
        logging.info(f"Scanning file: {path}")
        all_findings.extend(scan_file(path))

    elif path.is_dir():
        logging.info(f"Scanning directory: {path}")

        for file_path in path.rglob("*"):
            if file_path.is_file():
                all_findings.extend(scan_file(file_path))

    else:
        print("Error: The path does not exist.")
        logging.error(f"Invalid path entered: {path}")

    return all_findings

def print_report(findings):
    print("\nSecret Scanner Report")
    print("=" * 50)

    if not findings:
        print("No possible secrets found.")
        return

    for finding in findings:
        print(f"File: {finding['file']}")
        print(f"Line: {finding['line']}")
        print(f"Type: {finding['type']}")
        print(f"Match: {finding['match']}")
        print("-" * 50)

    print(f"\nTotal findings: {len(findings)}")

def main():
    parser = argparse.ArgumentParser(
        description="Scan a file or directory for possible hardcoded secrets."
    )

    parser.add_argument(
        "path",
        help="Enter the file or directory path to scan."
    )

    args = parser.parse_args()

    findings = scan_path(args.path)
    print_report(findings)

if __name__ == "__main__":
    main()