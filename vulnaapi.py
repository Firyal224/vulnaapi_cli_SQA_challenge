import json
import sys
import argparse
import time
import os
import logging
import hashlib

from rich.console import Console
from rich.table import Table
from rich import box
from rich.progress import track

# Setup console and logger
console = Console()
logging.basicConfig(filename='validator.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def compute_file_hash(filepath):
    """Compute SHA-256 hash for integrity checking."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        console.print(f"[red]❌ Error hashing file: {e}[/red]")
        logging.error(f"File hash error: {e}")
        return None


def secure_file_path_check(file_path):
    """Prevent path traversal or unauthorized access (OWASP A5: Broken Access Control)."""
    absolute_path = os.path.abspath(file_path)
    base_dir = os.getcwd()
    if not absolute_path.startswith(base_dir):
        raise ValueError("Attempted path traversal or invalid file path")


def load_sarif_file(file_path):
    """Load SARIF JSON file with proper error handling and secure practices."""
    try:
        secure_file_path_check(file_path)
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logging.info(f"Loaded SARIF file: {file_path}")
        return data
    except FileNotFoundError:
        console.print("[red]❌ File not found.[/red]")
        logging.warning(f"File not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        console.print("[red]❌ Invalid JSON format.[/red]")
        logging.warning(f"Invalid JSON in file: {file_path}")
        sys.exit(1)
    except ValueError as ve:
        console.print(f"[red]❌ {ve}[/red]")
        logging.warning(f"Security violation: {ve}")
        sys.exit(1)


def validate_findings(data, expectations):
    """Perform all validation assertions with logging and secure error handling."""
    try:
        findings = data['runs'][0]['results']
    except (KeyError, IndexError):
        console.print("[red]❌ SARIF format is invalid or incomplete.[/red]")
        logging.error("SARIF structure error.")
        sys.exit(1)

    messages = []
    console.print(f"✅ File loaded successfully. Total findings: {len(findings)}")
    assert len(findings) == expectations['expected_total'], f"Expected {expectations['expected_total']} findings, got {len(findings)}"
    messages.append("✅ Total findings is as expected")

    table = Table(title="Findings Validation Summary", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Check", style="bold cyan", no_wrap=True)
    table.add_column("Result", style="green")

    # SQL Injection check
    sql_finding = next((f for f in findings if f['ruleId'] == expectations['sql_rule']), None)
    assert sql_finding, "SQL Injection finding not found"
    table.add_row("SQL Injection finding found", "✅")
    messages.append("✅ SQL Injection finding found")

    assert sql_finding['level'] == expectations['sql_level']
    table.add_row("SQL Injection level is correct", "✅")
    messages.append(f"✅ SQL Injection level is '{expectations['sql_level']}'")

    severity = float(sql_finding['properties'].get('security-severity', 0))
    assert severity > expectations['sql_min_severity']
    table.add_row(f"SQL severity > {expectations['sql_min_severity']}", "✅")
    messages.append(f"✅ SQL Injection severity is {severity} (> {expectations['sql_min_severity']})")

    assert sql_finding['properties'].get('issue_owner') == expectations['sql_owner']
    table.add_row("SQL Injection issue owner is valid", "✅")
    messages.append(f"✅ SQL Injection issue owner is '{expectations['sql_owner']}'")

    file_uri = sql_finding['locations'][0]['physicalLocation']['artifactLocation']['uri']
    assert file_uri == expectations['sql_file']
    table.add_row("SQL finding file is correct", "✅")
    messages.append(f"✅ SQL Injection finding is in '{file_uri}'")

    # package.json findings
    package_findings = [f for f in findings if f['ruleId'] == expectations['package_rule']]
    assert len(package_findings) > 0
    table.add_row("package.json findings found", "✅")
    messages.append(f"✅ Found {len(package_findings)} package.json findings")

    for pf in package_findings:
        assert pf['properties'].get('issue_owner') == expectations['package_owner']
    table.add_row("All package.json owners are correct", "✅")
    messages.append(f"✅ All package.json findings owned by '{expectations['package_owner']}'")

    console.print(table)
    for m in messages:
        console.print(m)

    console.print("🎉 [bold green]All validations passed successfully![/bold green]")
    logging.info("Validation passed.")


def show_loading():
    """Simulate a loading animation."""
    for _ in track(range(14), description="[cyan]Loading SARIF scan results..."):
        time.sleep(0.05)


def main():
    """Main CLI handler with secure argument parsing and auditing."""
    parser = argparse.ArgumentParser(description="Secure SARIF Validator (with OWASP & ISO27001 compliance)")
    parser.add_argument("command", choices=["scan"], help="Command to run")
    parser.add_argument("file", help="Path to SARIF JSON file")

    args = parser.parse_args()

    if args.command == "scan":
        show_loading()
        file_hash = compute_file_hash(args.file)
        logging.info(f"SHA-256 hash of file: {file_hash}")
        sarif_data = load_sarif_file(args.file)

        expectations = {
            "expected_total": 6,
            "sql_rule": "php.lang.security.injection.tainted-sql-string.tainted-sql-string",
            "sql_level": "error",
            "sql_min_severity": 8.0,
            "sql_owner": "tmalbos",
            "sql_file": "index.php",
            "package_rule": "json.npm.security.package-dependencies-check.package-dependencies-check",
            "package_owner": "Jose"
        }

        try:
            validate_findings(sarif_data, expectations)
        except AssertionError as ae:
            console.print(f"[red]❌ Validation failed: {ae}[/red]")
            logging.error(f"Validation failed: {ae}")
            sys.exit(1)
    else:
        console.print("[red]Unknown command. Use 'scan'.[/red]")
        logging.warning(f"Unknown command used: {args.command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
