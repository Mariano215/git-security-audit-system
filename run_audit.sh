#!/bin/bash
# run_audit.sh - Execute comprehensive security audit

set -e

echo "🔍 Starting Comprehensive GitLab Security Audit"
echo "=============================================="

# Ensure we're in the right directory
cd "$(dirname "$0")"

# Step 1: Setup scanners
echo "📦 Installing security scanning tools..."
./setup_scanners_local.sh

# Export local bin to PATH for this session
export PATH="$HOME/.local/bin:$PATH"

# Step 2: Create required directories
mkdir -p reports logs

# Step 3: Install Python dependencies
echo "🐍 Installing Python dependencies..."
pip install -r requirements.txt

# Step 4: Run the comprehensive audit
echo "🔍 Running security audit on GitLab projects..."
echo "Scanning DMS and PS-CMMC-V3 projects..."

# Use absolute paths to the projects in main Projects directory
python security_audit_main.py \
    ../../../../dms ../../../../ps-cmmc-v3 \
    --auto-remediate

echo ""
echo "✅ Security audit completed!"
echo "📊 Check the reports/ directory for detailed results"
echo "🔄 Review remediation outputs for rotation recommendations"
echo ""

# Display summary of generated reports
echo "Generated Reports:"
echo "=================="
ls -la reports/ 2>/dev/null || echo "No reports directory found"
echo ""

# Show brief summary if available
echo "Audit Summary:"
echo "=============="
find reports/ -name "security_audit_summary_*.md" -exec head -20 {} \; 2>/dev/null || echo "No summary report found"