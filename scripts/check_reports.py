# this script checks security scan reports and enforce thresholds

import sys
import json
import os
from pathlib import Path

def checkBanditReport(report_path):
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
    
def checkSemgrepReport(report_path):
    if not os.path.exists(report_path):
        print(f"Report file not found: {report_path}")
        return True
    
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)

        results = data.get('results', [])
        error_issues = [
            r for r in results
            if r.get('extra', {}).get('severity') == 'ERROR'
        ]

        print(f"----- Semgrep Results -----")
        print(f"Total issues: {len(results)}")
        print(f"ERROR severity: {len(error_issues)}")

        if error_issues:
            print("\nERROR severity issues found:")
            for issue in error_issues[:5]:
                print(f" - {issue.get('check_id')}")
                print(f"   File: {issue.get('path')}:{issue.get('start', {}).get('line')}")
            return False

        print("No ERROR-level issues found (warnings OK)")
        return True

    except Exception as e:
        print(f"Error processing Semgrep report: {e}")
        return False
    
def checkPipAuditReport(report_path):
    if not os.path.exists(report_path):
        print(f"Report file not found: {report_path}")
        return True
    
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        # pip-audit reports vulnerabilities inside each dependency's 'vulns' list
        vulnerabilities = []
        for dep in data.get('dependencies', []):
            vulns = dep.get('vulns', [])
            for v in vulns:
                v['name'] = dep.get('name')
                v['version'] = dep.get('version')
                vulnerabilities.append(v)
        
        print(f"----- pip-audit Results -----")
        print(f"Total vulnerabilities: {len(vulnerabilities)}")
        
        if vulnerabilities:
            print("\nVulnerabilities found:")
            for vuln in vulnerabilities[:5]:  # show first 5
                print(f" - {vuln.get('id')}: {vuln.get('description', 'No description')[:60]}...")
                print(f"   Package: {vuln.get('name')} {vuln.get('version')}")
            return False  # fail pipeline
        
        print("No vulnerabilities found in pip-audit report")
        return True
    except Exception as e:
        print(f"Error processing pip-audit report: {e}")
        return False

def checkTrivyReport(report_path):
    if not os.path.exists(report_path):
        print(f"Report file not found: {report_path}")
        return True
    
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        high_critical = []
        
        # Check OS package vulnerabilities
        for result in data.get('Results', []):
            # Check regular vulnerabilities
            vulns = result.get('Vulnerabilities', [])
            if vulns:
                for vuln in vulns:
                    severity = vuln.get('Severity', '')
                    if severity in ['HIGH', 'CRITICAL']:
                        high_critical.append(vuln)
            
            # Check secrets (these are in a different section)
            secrets = result.get('Secrets', [])
            if secrets:
                for secret in secrets:
                    severity = secret.get('Severity', '')
                    if severity in ['HIGH', 'CRITICAL']:
                        high_critical.append(secret)
        
        print(f"----- Trivy Results -----")
        print(f"HIGH/CRITICAL vulnerabilities: {len(high_critical)}")
        
        if high_critical:
            print("\nHIGH/CRITICAL vulnerabilities found:")
            for issue in high_critical[:5]:
                vuln_id = issue.get('VulnerabilityID') or issue.get('RuleID', 'SECRET')
                severity = issue.get('Severity', 'UNKNOWN')
                pkg_name = issue.get('PkgName') or issue.get('Title', 'Secret detected')
                print(f" - {vuln_id}: {severity}")
                print(f"   Issue: {pkg_name}")
            return False
        
        print("No HIGH/CRITICAL vulnerabilities found in Trivy report")
        return True
    except Exception as e:
        print(f"Error processing Trivy report: {e}")
        return False

def checkGitleaksReport(report_path):
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

def checkZapReport(report_path):
    if not os.path.exists(report_path):
        print(f"Report file not found: {report_path}")
        return True
    
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        # ZAP report structure: contains sites with alerts
        # Risk codes: 0=Info, 1=Low, 2=Medium, 3=High
        high_medium_alerts = []
        all_alerts = []
        ignored_alerts = ["HTTP Only Site"]
        
        for site in data.get('site', []):
            site_alerts = site.get('alerts', [])
            all_alerts.extend(site_alerts)
            # Filter for High (3) and Medium (2) risk alerts only
            high_medium_alerts.extend([alert for alert in site_alerts 
                if alert.get('riskcode') in ['2', '3'] and alert.get('alert') not in ignored_alerts
            ])
        
        print(f"----- OWASP ZAP Results -----")
        print(f"Total security alerts: {len(all_alerts)}")
        print(f"HIGH/MEDIUM risk alerts: {len(high_medium_alerts)}")
        
        if high_medium_alerts:
            print("\nHIGH/MEDIUM risk alerts found:")
            for alert in high_medium_alerts[:5]:  # Show first 5 high/medium alerts
                risk_level = alert.get('riskcode', '0')
                risk_map = {'0': 'Info', '1': 'Low', '2': 'Medium', '3': 'High'}  
                risk_text = risk_map.get(risk_level, 'Unknown')
                
                print(f" - {alert.get('alert')} [{risk_text}]")
                print(f"   Alert: {alert.get('name')}")
                if alert.get('instances'):
                    print(f"   Instances: {len(alert.get('instances', []))}")
            return False
        
        print("No HIGH/MEDIUM risk alerts found in OWASP ZAP report")
        return True
    except Exception as e:
        print(f"Error processing ZAP report: {e}")
        return False
    
def main():
    if len(sys.argv) < 3:
        print("Try: python check_reports.py <report-file> <tool-name>")
        sys.exit(1)
    
    report_path = sys.argv[1]
    tool_name = sys.argv[2].lower()

    checkers = {
        'bandit': checkBanditReport,
        'semgrep': checkSemgrepReport,
        'pip-audit': checkPipAuditReport,
        'trivy': checkTrivyReport,
        'gitleaks': checkGitleaksReport,
        'zap': checkZapReport,
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