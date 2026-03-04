#!/bin/bash
# setup_scanners_local.sh - Install security scanning tools locally without sudo
#
# This script installs gitleaks, semgrep, and truffleHog security scanners
# to a local bin directory for the current user.

set -e
set -o pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Tool versions (update these as needed)
readonly GITLEAKS_VERSION="8.18.2"
readonly TRUFFLEHOG_VERSION="3.63.7"

# Local installation directory
readonly LOCAL_BIN_DIR="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN_DIR"

# Temporary directory for downloads
readonly TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO] $(date +'%Y-%m-%d %H:%M:%S')${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS] $(date +'%Y-%m-%d %H:%M:%S')${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING] $(date +'%Y-%m-%d %H:%M:%S')${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR] $(date +'%Y-%m-%d %H:%M:%S')${NC} $1"
}

# Check system requirements
check_system_requirements() {
    log_info "Checking system requirements..."

    # Check for required commands
    local required_commands=("curl" "tar" "pip" "python3")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command '$cmd' is not installed"
            case "$cmd" in
                "curl")
                    log_info "Install with: sudo apt-get install curl (Ubuntu/Debian) or sudo yum install curl (RHEL/CentOS)"
                    ;;
                "tar")
                    log_info "Install with: sudo apt-get install tar (Ubuntu/Debian) or sudo yum install tar (RHEL/CentOS)"
                    ;;
                "pip"|"python3")
                    log_info "Install with: sudo apt-get install python3-pip (Ubuntu/Debian) or sudo yum install python3-pip (RHEL/CentOS)"
                    ;;
            esac
            exit 1
        fi
    done

    # Ensure local bin directory is in PATH
    if [[ ":$PATH:" != *":$LOCAL_BIN_DIR:"* ]]; then
        log_warning "Local bin directory $LOCAL_BIN_DIR is not in PATH"
        log_info "Adding to PATH for this session"
        export PATH="$LOCAL_BIN_DIR:$PATH"
    fi

    log_success "System requirements check passed"
}

# Install gitleaks locally
install_gitleaks() {
    log_info "Installing gitleaks v$GITLEAKS_VERSION to $LOCAL_BIN_DIR..."

    if command -v gitleaks &> /dev/null && [[ "$PATH" == *"$LOCAL_BIN_DIR"* ]]; then
        local current_version
        current_version=$(gitleaks version 2>/dev/null | grep -oP 'v\K[\d.]+' || echo "unknown")
        if [ "$current_version" = "$GITLEAKS_VERSION" ]; then
            log_success "gitleaks v$GITLEAKS_VERSION is already installed"
            return 0
        else
            log_warning "gitleaks v$current_version is installed, upgrading to v$GITLEAKS_VERSION"
        fi
    fi

    local download_url="https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    local archive_file="$TEMP_DIR/gitleaks.tar.gz"

    log_info "Downloading gitleaks from $download_url"
    if ! curl -sL "$download_url" -o "$archive_file"; then
        log_error "Failed to download gitleaks"
        return 1
    fi

    log_info "Extracting gitleaks..."
    if ! tar -xzf "$archive_file" -C "$TEMP_DIR"; then
        log_error "Failed to extract gitleaks archive"
        return 1
    fi

    log_info "Installing gitleaks binary to $LOCAL_BIN_DIR"
    if ! cp "$TEMP_DIR/gitleaks" "$LOCAL_BIN_DIR/gitleaks"; then
        log_error "Failed to install gitleaks binary"
        return 1
    fi

    chmod +x "$LOCAL_BIN_DIR/gitleaks"

    # Verify installation
    if "$LOCAL_BIN_DIR/gitleaks" version &>/dev/null; then
        log_success "gitleaks v$GITLEAKS_VERSION installed successfully"
    else
        log_error "gitleaks installation verification failed"
        return 1
    fi
}

# Install truffleHog locally
install_trufflehog() {
    log_info "Installing truffleHog v$TRUFFLEHOG_VERSION to $LOCAL_BIN_DIR..."

    if command -v trufflehog &> /dev/null && [[ "$PATH" == *"$LOCAL_BIN_DIR"* ]]; then
        local current_version
        current_version=$(trufflehog --version 2>/dev/null | grep -oP 'trufflehog \K[\d.]+' || echo "unknown")
        if [ "$current_version" = "$TRUFFLEHOG_VERSION" ]; then
            log_success "truffleHog v$TRUFFLEHOG_VERSION is already installed"
            return 0
        else
            log_warning "truffleHog v$current_version is installed, upgrading to v$TRUFFLEHOG_VERSION"
        fi
    fi

    local download_url="https://github.com/trufflesecurity/trufflehog/releases/download/v$TRUFFLEHOG_VERSION/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz"
    local archive_file="$TEMP_DIR/trufflehog.tar.gz"

    log_info "Downloading truffleHog from $download_url"
    if ! curl -sL "$download_url" -o "$archive_file"; then
        log_error "Failed to download truffleHog"
        return 1
    fi

    log_info "Extracting truffleHog..."
    if ! tar -xzf "$archive_file" -C "$TEMP_DIR"; then
        log_error "Failed to extract truffleHog archive"
        return 1
    fi

    log_info "Installing truffleHog binary to $LOCAL_BIN_DIR"
    if ! cp "$TEMP_DIR/trufflehog" "$LOCAL_BIN_DIR/trufflehog"; then
        log_error "Failed to install truffleHog binary"
        return 1
    fi

    chmod +x "$LOCAL_BIN_DIR/trufflehog"

    # Verify installation
    if "$LOCAL_BIN_DIR/trufflehog" --version &>/dev/null; then
        log_success "truffleHog v$TRUFFLEHOG_VERSION installed successfully"
    else
        log_error "truffleHog installation verification failed"
        return 1
    fi
}

# Check and install semgrep
install_semgrep() {
    log_info "Checking semgrep installation..."

    if command -v semgrep &> /dev/null; then
        local current_version
        current_version=$(semgrep --version 2>/dev/null | head -1 || echo "unknown")
        log_success "semgrep is already available: $current_version"
        return 0
    fi

    log_info "Installing semgrep via pip..."
    if ! pip install --user semgrep; then
        log_error "Failed to install semgrep via pip"
        return 1
    fi

    # Verify installation
    if command -v semgrep &>/dev/null; then
        log_success "semgrep installed successfully"
    else
        log_error "semgrep installation verification failed"
        return 1
    fi
}

# Verify all tools are working
verify_installation() {
    log_info "Verifying tool installations..."

    local tools_to_check=("gitleaks" "trufflehog" "semgrep")
    local all_good=true

    for tool in "${tools_to_check[@]}"; do
        local tool_path
        if command -v "$tool" &> /dev/null; then
            tool_path=$(command -v "$tool")
            log_success "$tool is available at $tool_path"

            # Test basic functionality
            case "$tool" in
                "gitleaks")
                    if "$tool_path" version &>/dev/null; then
                        log_success "$tool basic test passed"
                    else
                        log_error "$tool basic test failed"
                        all_good=false
                    fi
                    ;;
                "trufflehog")
                    if "$tool_path" --version &>/dev/null; then
                        log_success "$tool basic test passed"
                    else
                        log_error "$tool basic test failed"
                        all_good=false
                    fi
                    ;;
                "semgrep")
                    if "$tool_path" --version &>/dev/null; then
                        log_success "$tool basic test passed"
                    else
                        log_error "$tool basic test failed"
                        all_good=false
                    fi
                    ;;
            esac
        else
            log_error "$tool is not available in PATH"
            all_good=false
        fi
    done

    if $all_good; then
        log_success "All security scanning tools are installed and working"
        return 0
    else
        log_error "Some tools failed verification"
        return 1
    fi
}

# Main execution
main() {
    log_info "Starting local GitLab Security Audit System scanner installation..."
    log_info "Installing tools to $LOCAL_BIN_DIR"
    echo "============================================================="

    check_system_requirements
    install_gitleaks
    install_trufflehog
    install_semgrep
    verify_installation

    echo ""
    log_success "GitLab Security Audit System scanner setup completed!"
    log_info "All tools installed to: $LOCAL_BIN_DIR"
    log_info "Make sure $LOCAL_BIN_DIR is in your PATH for future sessions"

    if [[ ":$PATH:" != *":$LOCAL_BIN_DIR:"* ]]; then
        log_info "Add the following to your ~/.bashrc or ~/.zshrc:"
        echo "export PATH=\"$LOCAL_BIN_DIR:\$PATH\""
    fi
}

main "$@"