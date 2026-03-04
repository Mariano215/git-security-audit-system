#!/usr/bin/env python3
"""
Enhanced Email Notification System for Security Audit
Supports both critical alerts and regular summary emails via GraphQL
"""

import json
import sys
import os
import requests
from datetime import datetime
from pathlib import Path

# Try to load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # If python-dotenv not available, use os.environ directly
    pass

# Configuration from environment variables - Microsoft Graph API
MICROSOFT_GRAPH_CLIENT_ID = os.getenv('MICROSOFT_GRAPH_CLIENT_ID', '')
MICROSOFT_GRAPH_CLIENT_SECRET = os.getenv('MICROSOFT_GRAPH_CLIENT_SECRET', '')
MICROSOFT_GRAPH_TENANT_ID = os.getenv('MICROSOFT_GRAPH_TENANT_ID', '')
MICROSOFT_GRAPH_USER_EMAIL = os.getenv('MICROSOFT_GRAPH_USER_EMAIL', '')

EMAIL_FROM = os.getenv('EMAIL_FROM', 'eccalonauto@eccalon.com')
EMAIL_TO = os.getenv('EMAIL_TO', 'mariano.mattei@eccalon.com')
EMAIL_CC = os.getenv('EMAIL_CC', '')
EMAIL_BCC = os.getenv('EMAIL_BCC', '')

SEND_SUMMARY_EMAILS = os.getenv('SEND_SUMMARY_EMAILS', 'true').lower() == 'true'
SEND_ONLY_ON_FINDINGS = os.getenv('SEND_ONLY_ON_FINDINGS', 'false').lower() == 'true'
ALERT_THRESHOLD = os.getenv('ALERT_THRESHOLD', 'MEDIUM')

def load_report(report_file):
    """Load and parse the security audit report"""
    try:
        with open(report_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading report: {e}")
        return None

def classify_findings(findings, threshold="MEDIUM"):
    """Classify findings by severity level"""
    severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    threshold_level = severity_order.get(threshold.upper(), 2)

    critical_findings = [
        f for f in findings
        if severity_order.get(f.get('risk_level', 'LOW'), 1) >= threshold_level
    ]

    return critical_findings

def create_alert_email(report_data, critical_findings):
    """Create critical security alert email"""
    subject = f"🚨 SECURITY ALERT - {len(critical_findings)} Critical Findings Detected"

    body = f"""
SECURITY ALERT - GitLab Audit Report
=====================================

Critical security findings have been detected in your GitLab projects!

📊 SUMMARY:
- Total Findings: {len(report_data.get('findings', []))}
- Critical/High Risk: {len(critical_findings)}
- Projects Scanned: {len(report_data.get('projects_scanned', []))}
- Scan Date: {report_data.get('scan_metadata', {}).get('timestamp', 'Unknown')}

🚨 CRITICAL FINDINGS:
"""

    for i, finding in enumerate(critical_findings[:5], 1):
        body += f"""
{i}. {finding.get('risk_level', 'UNKNOWN')} RISK
   Location: {finding.get('file_path', 'Unknown')}
   Issue: {finding.get('description', 'No description')}
   Line: {finding.get('line_number', 'N/A')}
"""

    if len(critical_findings) > 5:
        body += f"\n... and {len(critical_findings) - 5} more findings\n"

    body += f"""

📋 RECOMMENDED ACTIONS:
1. Review the full report immediately
2. Rotate any exposed credentials
3. Update .gitignore to prevent future exposures
4. Run remediation tools if available

📁 Full Report Location:
{os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else 'See audit logs'}

⚡ This is an automated alert. Please take immediate action.
"""

    return subject, body

def create_summary_email(report_data):
    """Create regular audit summary email"""
    scan_meta = report_data.get('scan_metadata', {})
    projects = report_data.get('projects_scanned', [])
    findings_count = len(report_data.get('findings', []))

    if findings_count == 0:
        subject = f"✅ Weekly Security Audit - All Clear (Score: {report_data.get('security_score', {}).get('overall_score', 'N/A')}/100)"
        status_emoji = "✅"
        status_text = "SECURE"
    else:
        subject = f"⚠️ Weekly Security Audit - {findings_count} Issues Found"
        status_emoji = "⚠️"
        status_text = "ATTENTION NEEDED"

    body = f"""
Weekly Git Security Audit Report
===================================

{status_emoji} STATUS: {status_text}

📊 SCAN SUMMARY:
- Security Score: {report_data.get('security_score', {}).get('overall_score', 'N/A')}/100
- Total Findings: {findings_count}
- Projects Scanned: {len(projects)}
- Execution Time: {scan_meta.get('execution_time', 'N/A')} seconds
- Scan Date: {scan_meta.get('timestamp', 'Unknown')}

📁 PROJECTS AUDITED:
"""

    for project in projects:
        body += f"  • {project}\n"

    if findings_count == 0:
        body += f"""

🎯 EXCELLENT! No security issues detected.
Your GitLab projects maintain a perfect security posture.

🔄 NEXT SCAN: Next Sunday at 3:00 AM
📧 NOTIFICATIONS: You'll only receive emails if issues are found
"""
    else:
        body += f"""

⚠️ FINDINGS BREAKDOWN:
- Critical: {len([f for f in report_data.get('findings', []) if f.get('risk_level') == 'CRITICAL'])}
- High: {len([f for f in report_data.get('findings', []) if f.get('risk_level') == 'HIGH'])}
- Medium: {len([f for f in report_data.get('findings', []) if f.get('risk_level') == 'MEDIUM'])}
- Low: {len([f for f in report_data.get('findings', []) if f.get('risk_level') == 'LOW'])}

📋 RECOMMENDED ACTIONS:
1. Review detailed findings in the full report
2. Prioritize Critical and High-risk items
3. Run auto-remediation if appropriate
"""

    body += f"""

🔧 AUDIT SYSTEM INFO:
- Tools Used: gitleaks, semgrep, trufflehog
- Analysis: Cross-tool correlation with false-positive filtering
- Automation: Fully automated weekly scans

This is an automated report from your Git Security Audit System.
"""

    return subject, body

def get_microsoft_graph_access_token():
    """Get access token for Microsoft Graph API"""
    if not all([MICROSOFT_GRAPH_CLIENT_ID, MICROSOFT_GRAPH_CLIENT_SECRET, MICROSOFT_GRAPH_TENANT_ID]):
        print("⚠️  Microsoft Graph credentials not configured")
        return None

    token_url = f"https://login.microsoftonline.com/{MICROSOFT_GRAPH_TENANT_ID}/oauth2/v2.0/token"

    data = {
        'grant_type': 'client_credentials',
        'client_id': MICROSOFT_GRAPH_CLIENT_ID,
        'client_secret': MICROSOFT_GRAPH_CLIENT_SECRET,
        'scope': 'https://graph.microsoft.com/.default'
    }

    try:
        response = requests.post(token_url, data=data, timeout=30)

        if response.status_code == 200:
            token_data = response.json()
            return token_data.get('access_token')
        else:
            print(f"❌ Failed to get access token: {response.status_code} {response.text}")
            return None

    except Exception as e:
        print(f"❌ Error getting Microsoft Graph access token: {e}")
        return None

def send_email_microsoft_graph(subject, body):
    """Send email via Microsoft Graph API"""
    access_token = get_microsoft_graph_access_token()
    if not access_token:
        return False

    # Convert plain text body to HTML for better formatting
    html_body = body.replace('\n', '<br>\n')

    # Build recipients list
    recipients = [{"emailAddress": {"address": EMAIL_TO, "name": EMAIL_TO}}]

    cc_recipients = []
    if EMAIL_CC:
        cc_recipients = [{"emailAddress": {"address": EMAIL_CC, "name": EMAIL_CC}}]

    bcc_recipients = []
    if EMAIL_BCC:
        bcc_recipients = [{"emailAddress": {"address": EMAIL_BCC, "name": EMAIL_BCC}}]

    # Microsoft Graph API email payload
    email_data = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "HTML",
                "content": html_body
            },
            "toRecipients": recipients
        }
    }

    # Add CC/BCC if provided
    if cc_recipients:
        email_data["message"]["ccRecipients"] = cc_recipients
    if bcc_recipients:
        email_data["message"]["bccRecipients"] = bcc_recipients

    # Send email via Microsoft Graph
    send_url = f"https://graph.microsoft.com/v1.0/users/{MICROSOFT_GRAPH_USER_EMAIL}/sendMail"

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(send_url, json=email_data, headers=headers, timeout=30)

        if response.status_code == 202:  # Microsoft Graph returns 202 for successful email send
            print(f"✅ Email sent successfully via Microsoft Graph API!")
            return True
        else:
            print(f"❌ Microsoft Graph email sending failed: {response.status_code} {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error sending email via Microsoft Graph: {e}")
        return False

def log_email_to_file(subject, body):
    """Log email to file as backup"""
    log_file = Path("logs/email_notifications.log")
    log_file.parent.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(log_file, 'a') as f:
        f.write(f"""
=====================================
{timestamp}
=====================================
TO: {EMAIL_TO}
FROM: {EMAIL_FROM}
SUBJECT: {subject}

{body}

=====================================

""")

def send_email(subject, body):
    """Send email via Microsoft Graph API or log to file as fallback"""

    # Always log to file for audit trail
    log_email_to_file(subject, body)

    print(f"📧 Subject: {subject}")
    print(f"📧 From: {EMAIL_FROM}")
    print(f"📧 To: {EMAIL_TO}")

    # Try Microsoft Graph API first
    if all([MICROSOFT_GRAPH_CLIENT_ID, MICROSOFT_GRAPH_CLIENT_SECRET, MICROSOFT_GRAPH_TENANT_ID]):
        if send_email_microsoft_graph(subject, body):
            print(f"📧 Email delivered via Microsoft Graph API!")
            return True
        else:
            print("📧 Microsoft Graph sending failed, email saved to log file")
    else:
        print("📧 Microsoft Graph not configured, email saved to log file")
        print("   Configure Microsoft Graph credentials in .env file")

    return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 email_notifier.py <report_file> [threshold] [--summary]")
        sys.exit(1)

    report_file = sys.argv[1]
    threshold = sys.argv[2] if len(sys.argv) > 2 else "MEDIUM"
    send_summary = "--summary" in sys.argv

    # Load report
    report_data = load_report(report_file)
    if not report_data:
        sys.exit(1)

    findings = report_data.get('findings', [])
    critical_findings = classify_findings(findings, threshold)

    if critical_findings:
        # Send critical alert
        subject, body = create_alert_email(report_data, critical_findings)
        send_email(subject, body)
        print(f"🚨 CRITICAL ALERT sent: {len(critical_findings)} findings detected!")
    elif send_summary:
        # Send regular summary
        subject, body = create_summary_email(report_data)
        send_email(subject, body)
        print(f"📊 Summary email sent: {len(findings)} total findings")
    else:
        print(f"✅ No critical findings detected (threshold: {threshold})")
        print("   Use --summary flag to send summary email anyway")

if __name__ == "__main__":
    main()