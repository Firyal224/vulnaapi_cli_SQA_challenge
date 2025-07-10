# VulnaAPI CLI — SARIF API Findings Validator

This command-line tool validates a SARIF findings JSON file from an API response, built as part of the **Plexicus SQA challenge**.

It helps in validating the structure and correctness of security findings, ensuring compliance with defined rules such as SQL Injection detection and rule ownership.

## ✨ Features
- ✅ Checks total findings count
- ✅ Validates specific SQL Injection rule
- ✅ Verifies `package.json` rule ownership
- ✅ Pretty CLI output using [Rich](https://github.com/Textualize/rich)
- ✅ Includes assertion-based validation
- ✅ Graceful error handling with human-readable output

## 📦 Requirements
- Python 3.6 or higher
- [`rich`](https://pypi.org/project/rich/) Python module

## 📥 Installation
Clone the repository and install dependencies:

```bash
git clone https://github.com/Firyal224/vulnaapi_cli_SQA_challenge.git
cd vulnaapi_cli_SQA_challenge
pip install -r requirements.txt
```

## 🚀 Usage
To run the validator on a SARIF JSON file:

```bash
python vulnaapi.py scan findings.json
```

Make sure the `findings.json` file is located in the same directory or provide the full path to it.

## 📤 Output
- ⏳ Animated CLI progress while processing
- 📄 Console logs for each validation step
- ✅ Final result summary: human-readable success or failure
- ❌ Informative error messages if validation fails

## 📁 Sample SARIF Format Expected
The tool expects SARIF JSON in the format similar to GitHub Advanced Security output or SARIF-standard security tools.

## 🛠️ Author
Developed by **Firyal Dalilah Ihsani**  
GitHub: [@Firyal224](https://github.com/Firyal224)
