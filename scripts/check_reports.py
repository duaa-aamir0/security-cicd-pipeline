# this script checks security scan reports and enforce thresholds

import sys
import json
import os
from pathlib import Path

def check_bandit_report(report_path):
    if not os.path.exists(report_path):
        print(f"Report file not found: {report_path}")
        return True  # Pass if no report
    
    # bandit severity levels: low, medium, high
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        high_issues = [issue for issue in data.get('results', []) if issue.get('issue_severity') == 'HIGH']
        
        print(f"----- Bandit Results -----")
        print(f"Total issues: {len(data.get('results', []))}")
        print(f"HIGH severity: {len(high_issues)}")
        
        if high_issues:
            print("\nHIGH severity issues found:")
            for issue in high_issues[:5]:  # Show first 5
                print(f" - {issue.get('test_id')}: {issue.get('issue_text')}")
                print(f"   File: {issue.get('filename')}:{issue.get('line_number')}")
            return False
        
        print("No HIGH severity issues found in Bandit report.")
        return True
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return False
    except Exception as e:
        print(f"Error reading report: {e}")
        return False
    
def check_semgrep_report(report_path):
    if not os.path.exists(report_path):
        print(f"Report file not found: {report_path}")
        return True
    
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        # semgrep uses: info, warning, error
        results = data.get('results', [])
        error_issues = [r for r in results if r.get('extra', {}).get('severity') == 'ERROR']
        
        print(f"----- Semgrep Results -----")
        print(f"Total issues: {len(results)}")
        print(f"ERROR severity: {len(error_issues)}")
        
        if error_issues:
            print("\nERROR severity issues found:")
            for issue in error_issues[:5]:
                print(f" - {issue.get('check_id')}")
                print(f"   File: {issue.get('path')}:{issue.get('start', {}).get('line')}")
            return False
        
        print("No ERROR severity issues found in Semgrep report")
        return True
    except Exception as e:
        print(f"Error processing Semgrep report: {e}")
        return False
    
def check_pip_audit_report(report_path):
    if not os.path.exists(report_path):
        print(f"Report file not found: {report_path}")
        return True
    
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        # pip-audit reports known CVEs in dependencies
        vulnerabilities = data.get('vulnerabilities', [])
        
        print(f"----- pip-audit Results -----")
        print(f"Total vulnerabilities: {len(vulnerabilities)}")
        
        if vulnerabilities:
            print("\n⚠️  Vulnerabilities found:")
            for vuln in vulnerabilities[:5]:
                print(f" - {vuln.get('id')}: {vuln.get('description', 'No description')[:60]}...")
                print(f" Package: {vuln.get('name')} {vuln.get('version')}")
            return False
        
        print("No vulnerabilities found in pip-audit report")
        return True
    except Exception as e:
        print(f"Error processing pip-audit report: {e}")
        return False

def check_trivy_report(report_path):
    if not os.path.exists(report_path):
        print(f"Report file not found: {report_path}")
        return True
    
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        high_critical = []
        
        # trivy scans containers for vulnerabilities
        for result in data.get('Results', []):
            vulns = result.get('Vulnerabilities', [])
            if vulns:
                for vuln in vulns:
                    severity = vuln.get('Severity', '')
                    if severity in ['HIGH', 'CRITICAL']:
                        high_critical.append(vuln)
        
        print(f"----- Trivy Results -----")
        print(f"HIGH/CRITICAL vulnerabilities: {len(high_critical)}")
        
        if high_critical:
            print("\nHIGH/CRITICAL vulnerabilities found:")
            for vuln in high_critical[:5]:
                print(f" - {vuln.get('VulnerabilityID')}: {vuln.get('Severity')}")
                print(f" Package: {vuln.get('PkgName')}")
            return False
        
        print("No HIGH/CRITICAL vulnerabilities found in Trivy report")
        return True
    except Exception as e:
        print(f"Error processing Trivy report: {e}")
        return False

def check_gitleaks_report(report_path):
    if not os.path.exists(report_path):
        print(f"Report file not found: {report_path}")
        return True
    
    try:
        with open(report_path, 'r') as f:
            content = f.read().strip()
        
        # Gitleaks outputs JSON array or empty
        if not content or content == '[]' or content == '':
            print("No secrets found in Gitleaks report")
            return True
        
        data = json.loads(content)
        
        if isinstance(data, list) and len(data) > 0:
            print(f"\n{len(data)} secret(s) found:")
            for secret in data[:5]:
                print(f" - Rule: {secret.get('RuleID')}")
                print(f"   File: {secret.get('File')}:{secret.get('StartLine')}")
            return False
        
        print("No secrets found in Gitleaks report")
        return True
    except Exception as e:
        print(f"Error processing Gitleaks report: {e}")
        return False
    
def main():
    if len(sys.argv) < 3:
        print("Try: python check_reports.py <report-file> <tool-name>")
        sys.exit(1)
    
    report_path = sys.argv[1]
    tool_name = sys.argv[2].lower()

    checkers = {
        'bandit': check_bandit_report,
        'semgrep': check_semgrep_report,
        'pip-audit': check_pip_audit_report,
        'trivy': check_trivy_report,
        'gitleaks': check_gitleaks_report,
    }

    checker = checkers.get(tool_name)

    if not checker:
        print(f"Unknown tool: {tool_name}")
        sys.exit(1)
    
    passed = checker(report_path)

    if passed:
        print("==== Security check PASSED ====")
        sys.exit(0)
    else:
        print("==== Security check FAILED ====")
        sys.exit(1)

if __name__ == '__main__':
    main()