#!/bin/bash
# Git Security Audit - Cronjob Setup Script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_SCRIPT="$SCRIPT_DIR/run_audit.sh"
LOG_DIR="$SCRIPT_DIR/logs"
REPORT_DIR="$SCRIPT_DIR/reports"

# Create necessary directories
mkdir -p "$LOG_DIR" "$REPORT_DIR"

# Make scripts executable
chmod +x "$AUDIT_SCRIPT"

echo "Setting up Git Security Audit for automated execution..."

# Example cronjob entries (uncomment and customize as needed)
echo ""
echo "Add one of these cronjob entries using 'crontab -e':"
echo ""
echo "# Daily security audit at 2 AM"
echo "0 2 * * * cd $SCRIPT_DIR && ./run_audit.sh --format json markdown --output-dir $REPORT_DIR >> $LOG_DIR/audit.log 2>&1"
echo ""
echo "# Weekly comprehensive audit on Sundays at 3 AM"
echo "0 3 * * 0 cd $SCRIPT_DIR && ./run_audit.sh --format json markdown html --output-dir $REPORT_DIR --verbose >> $LOG_DIR/weekly-audit.log 2>&1"
echo ""
echo "# Hourly quick scan (recent changes only)"
echo "0 * * * * cd $SCRIPT_DIR && ./run_audit.sh --format json --output-dir $REPORT_DIR --quick-scan >> $LOG_DIR/hourly-audit.log 2>&1"
echo ""

# Create log rotation config
cat > "$SCRIPT_DIR/logrotate.conf" << 'EOF'
# Log rotation for security audit logs
$SCRIPT_DIR/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 $USER $USER
}
EOF

echo "Created logrotate config at: $SCRIPT_DIR/logrotate.conf"
echo ""
echo "To enable log rotation, add to root crontab:"
echo "0 0 * * * /usr/sbin/logrotate $SCRIPT_DIR/logrotate.conf"
echo ""

# Create notification script for critical findings
cat > "$SCRIPT_DIR/notify_on_findings.sh" << 'EOF'
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
    # echo "Critical security findings detected. Report: $REPORT_FILE" | mail -s "Security Alert - GitLab Audit" admin@example.com

    # Optional: Slack notification (requires webhook URL)
    # curl -X POST -H 'Content-type: application/json' --data '{"text":"Security Alert: Critical findings in GitLab audit"}' YOUR_SLACK_WEBHOOK_URL
fi
EOF

chmod +x "$SCRIPT_DIR/notify_on_findings.sh"

echo "Created notification script at: $SCRIPT_DIR/notify_on_findings.sh"
echo ""
echo "Example cronjob with notifications:"
echo "0 2 * * * cd $SCRIPT_DIR && ./run_audit.sh --format json --output-dir $REPORT_DIR > $LOG_DIR/audit.log 2>&1 && ./notify_on_findings.sh $REPORT_DIR/\$(date +%Y%m%d)-security-audit.json MEDIUM"
echo ""

echo "Setup complete! Configure your preferred cronjob schedule above."