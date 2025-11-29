# Security CI/CD Pipeline

A comprehensive security scanning pipeline that automates security checks across multiple tools and enforces quality gates in your CI/CD workflow.

## Overview

This project provides automated security scanning for Python applications using industry-standard security tools. The pipeline runs multiple security scanners and enforces configurable thresholds to catch vulnerabilities before they reach production.

## Features

- Static Application Security Testing (SAST) with Bandit and Semgrep
- Dependency vulnerability scanning with pip-audit
- Container and filesystem scanning with Trivy
- Secret detection with Gitleaks
- Dynamic Application Security Testing (DAST) with OWASP ZAP
- Automated threshold enforcement
- Detailed security reports in JSON format

## Security Tools Included

- **Bandit**: Python code security scanner that identifies common security issues
- **Semgrep**: Fast, lightweight static analysis for finding bugs and security issues
- **pip-audit**: Scans Python dependencies for known vulnerabilities
- **Trivy**: Comprehensive container and filesystem vulnerability scanner
- **Gitleaks**: Detects hardcoded secrets and credentials in your codebase
- **OWASP ZAP**: Dynamic security testing for web applications

## Prerequisites

- Python 3.x
- Docker (for containerized scanning)
- GitHub repository with Actions enabled

## Installation

1. Clone this repository
2. Copy the workflow file to your project:
   ```
   mkdir -p .github/workflows
   cp .github/workflows/secure-pipeline.yml .github/workflows/
   ```
3. Copy the report checker script:
   ```
   mkdir -p scripts
   cp scripts/check_reports.py scripts/
   ```

## Usage

### Running in GitHub Actions

The pipeline automatically runs on:
- Push to main branch
- Pull requests to main branch
- Manual workflow dispatch

The workflow will:
1. Run all security scans in parallel
2. Generate JSON reports for each tool
3. Check reports against defined thresholds
4. Fail the pipeline if any critical issues are found
5. Upload reports as workflow artifacts

## Threshold Configuration

The pipeline enforces the following thresholds by default:

- **Bandit**: Fails on HIGH severity issues
- **Semgrep**: Fails on ERROR level findings (warnings are allowed)
- **pip-audit**: Fails on any dependency vulnerabilities
- **Trivy**: Fails on HIGH or CRITICAL vulnerabilities
- **Gitleaks**: Fails if any secrets are detected
- **OWASP ZAP**: Fails on MEDIUM or HIGH risk alerts

To modify thresholds, edit the checker functions in `scripts/check_reports.py`.

## Project Structure

```
.github/workflows/
  secure-pipeline.yml    # GitHub Actions workflow definition
app/
  app.py                 # Main application code (place yours here)
scripts/
  check_reports.py       # Security report analyzer and threshold enforcer
Dockerfile               # Container definition for deployment
requirements.txt         # Python dependencies (place yours here)
```

## Report Artifacts

After each workflow run, security reports are available as artifacts.
Download these from the Actions tab to review detailed findings.

## Customization

### Adding New Security Tools

1. Add the tool installation and scan steps to the workflow
2. Create a new checker function in `check_reports.py`
3. Register the checker in the `checkers` dictionary
4. Add a verification step in the workflow

### Adjusting Severity Levels

Edit the checker functions in `check_reports.py` to modify which severity levels trigger pipeline failures.

## Troubleshooting

**Pipeline fails with "Report file not found"**
- Ensure the security tool successfully generated its report
- Check the tool's output in the workflow logs

**False positives in security scans**
- Review the specific finding in the artifact report
- Add suppressions to tool-specific configuration files
- Consider adjusting thresholds if appropriate for your risk tolerance

**ZAP scan times out**
- Reduce scan depth or scope in the workflow
- Increase timeout values
- Consider running ZAP scans separately for large applications
