#!/bin/bash
# Notification script for security findings

REPORT_FILE="$1"
THRESHOLD="${2:-MEDIUM}"  # Alert on MEDIUM+ findings by default

if [ ! -f "$REPORT_FILE" ]; then
    echo "Report file not found: $REPORT_FILE"
    exit 1
fi

# Check if there are findings at or above threshold
if python3 -c "
import json
import sys

try:
    with open('$REPORT_FILE') as f:
        data = json.load(f)

    severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    threshold_level = severity_order.get('$THRESHOLD', 2)

    critical_findings = [
        f for f in data.get('findings', [])
        if severity_order.get(f.get('risk_level', 'LOW'), 1) >= threshold_level
    ]

    if critical_findings:
        print(f'ALERT: {len(critical_findings)} security findings detected!')
        for finding in critical_findings[:3]:  # Show first 3
            print(f'- {finding.get(\"risk_level\", \"UNKNOWN\")}: {finding.get(\"description\", \"No description\")}')
        sys.exit(1)  # Exit with error to trigger alert
    else:
        print('No significant security findings detected.')
        sys.exit(0)

except Exception as e:
    print(f'Error checking report: {e}')
    sys.exit(1)
"; then
    echo "Security audit completed successfully - no critical findings"
else
    echo "SECURITY ALERT: Critical findings detected in audit report!"
    echo "Report location: $REPORT_FILE"

    # Optional: Send email notification (requires mailutils or similar)
    echo "Critical security findings detected. Report: $REPORT_FILE" | mail -s "Security Alert - GitLab Audit" mariano.mattei@eccalon.com

    # Optional: Slack notification (requires webhook URL)
    # curl -X POST -H 'Content-type: application/json' --data '{"text":"Security Alert: Critical findings in GitLab audit"}' YOUR_SLACK_WEBHOOK_URL
fi
