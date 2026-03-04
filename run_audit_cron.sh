#!/bin/bash
# Git Security Audit - Cron-Optimized Version
# Designed for automated execution with better logging and error handling

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
LOG_DIR="$SCRIPT_DIR/logs"
REPORT_DIR="$SCRIPT_DIR/reports"
LOCKFILE="$SCRIPT_DIR/.audit_running"

# Create directories
mkdir -p "$LOG_DIR" "$REPORT_DIR"

# Function to cleanup on exit
cleanup() {
    local exit_code=$?
    [ -f "$LOCKFILE" ] && rm -f "$LOCKFILE"

    if [ $exit_code -eq 0 ]; then
        echo "$(date): Security audit completed successfully" >> "$LOG_DIR/audit_status.log"
    else
        echo "$(date): Security audit failed with exit code $exit_code" >> "$LOG_DIR/audit_status.log"
    fi

    exit $exit_code
}

trap cleanup EXIT

# Prevent overlapping executions
if [ -f "$LOCKFILE" ]; then
    echo "$(date): Another audit is already running (lockfile exists: $LOCKFILE)" >> "$LOG_DIR/audit_status.log"
    exit 1
fi

# Create lockfile
echo "$$" > "$LOCKFILE"

# Log start
echo "$(date): Starting security audit (PID: $$)" >> "$LOG_DIR/audit_status.log"

# Change to script directory
cd "$SCRIPT_DIR"

# Set default options for cron execution
DEFAULT_ARGS=(
    "--format" "json" "markdown"
    "--output-dir" "$REPORT_DIR"
    "/home/mmattei/Projects/dms" "/home/mmattei/Projects/ps-cmmc-v3"
)

# Add any additional arguments passed to this script
AUDIT_ARGS=("${DEFAULT_ARGS[@]}" "$@")

# Run the audit with comprehensive logging
echo "$(date): Executing audit with args: ${AUDIT_ARGS[*]}" >> "$LOG_DIR/audit_status.log"

python3 security_audit_main.py "${AUDIT_ARGS[@]}" \
    > "$LOG_DIR/audit_${TIMESTAMP}.log" 2>&1

# Log completion
echo "$(date): Audit execution completed" >> "$LOG_DIR/audit_status.log"

# Optional: Run notification check if report was generated
REPORT_FILE=$(ls -t "$REPORT_DIR"/security_audit_report_*.json 2>/dev/null | head -1)
if [ -f "$REPORT_FILE" ]; then
    echo "$(date): Running notification check on $REPORT_FILE" >> "$LOG_DIR/audit_status.log"

    # Check for findings and optionally notify
    if [ -x "$SCRIPT_DIR/notify_on_findings.sh" ]; then
        "$SCRIPT_DIR/notify_on_findings.sh" "$REPORT_FILE" "MEDIUM" \
            >> "$LOG_DIR/audit_status.log" 2>&1 || true
    fi
fi

echo "$(date): Security audit process completed successfully" >> "$LOG_DIR/audit_status.log"