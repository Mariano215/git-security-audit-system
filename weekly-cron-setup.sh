#!/bin/bash
# Weekly Security Audit - Cronjob Installation

set -euo pipefail

AUDIT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔒 Setting up weekly Git Security Audit cronjob..."

# Weekly comprehensive audit: Sundays at 3 AM
WEEKLY_CRON_ENTRY="0 3 * * 0 cd $AUDIT_PATH && ./run_audit_cron.sh --format json markdown html --verbose 2>&1"

# Check if cron entry already exists
if crontab -l 2>/dev/null | grep -F "$AUDIT_PATH/run_audit_cron.sh" >/dev/null; then
    echo "⚠️  Security audit cronjob already exists. Current crontab:"
    echo "────────────────────────────────────────────────────────"
    crontab -l 2>/dev/null | grep -F "$AUDIT_PATH"
    echo "────────────────────────────────────────────────────────"
    echo ""
    read -p "Replace existing entry? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Cancelled. No changes made."
        exit 0
    fi

    # Remove existing entries
    crontab -l 2>/dev/null | grep -v "$AUDIT_PATH" | crontab -
    echo "🗑️  Removed existing security audit entries"
fi

# Add new weekly entry
(crontab -l 2>/dev/null; echo "$WEEKLY_CRON_ENTRY") | crontab -

echo "✅ Weekly security audit cronjob installed!"
echo ""
echo "📅 Schedule: Every Sunday at 3:00 AM"
echo "📁 Reports: $AUDIT_PATH/reports/"
echo "📋 Logs: $AUDIT_PATH/logs/"
echo ""
echo "🔔 Features enabled:"
echo "   • Comprehensive scanning (all tools)"
echo "   • Multi-format reports (JSON, Markdown, HTML)"
echo "   • Detailed logging with timestamps"
echo "   • Automatic notifications for findings"
echo "   • Log rotation to prevent disk bloat"
echo ""

# Verify crontab was updated
echo "📋 Current crontab entries:"
echo "────────────────────────────────────────────────────────"
crontab -l | grep -F "$AUDIT_PATH" || echo "No audit entries found"
echo "────────────────────────────────────────────────────────"
echo ""

# Test permissions
echo "🧪 Testing permissions and setup..."

if [ ! -x "$AUDIT_PATH/run_audit_cron.sh" ]; then
    echo "❌ run_audit_cron.sh is not executable"
    chmod +x "$AUDIT_PATH/run_audit_cron.sh"
    echo "✅ Fixed executable permission"
fi

if [ ! -d "$AUDIT_PATH/logs" ]; then
    mkdir -p "$AUDIT_PATH/logs"
    echo "✅ Created logs directory"
fi

if [ ! -d "$AUDIT_PATH/reports" ]; then
    mkdir -p "$AUDIT_PATH/reports"
    echo "✅ Created reports directory"
fi

echo ""
echo "🎯 Next Steps:"
echo "1. The audit will run automatically every Sunday at 3 AM"
echo "2. Check logs: tail -f $AUDIT_PATH/logs/audit_status.log"
echo "3. View reports: ls $AUDIT_PATH/reports/"
echo "4. Test now: cd $AUDIT_PATH && ./run_audit_cron.sh --test"
echo ""
echo "📧 Optional: Configure email notifications in notify_on_findings.sh"
echo "🚨 Optional: Add Slack webhook for instant alerts"
echo ""
echo "✨ Setup complete! Your GitLab projects will be monitored weekly."