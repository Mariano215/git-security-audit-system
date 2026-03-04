#!/bin/bash
# setup_scanners.sh - Install security scanning tools for GitLab Security Audit System
#
# This script installs gitleaks, semgrep, and truffleHog security scanners
# with proper error handling, logging, and verification.

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

# Installation directory
readonly INSTALL_DIR="/usr/local/bin"

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

# Check if running with sufficient privileges
check_privileges() {
    if [ "$EUID" -ne 0 ] && ! sudo -n true 2>/dev/null; then
        log_error "This script requires sudo privileges to install tools to $INSTALL_DIR"
        log_info "Please run with sudo or ensure your user has sudo access"
        exit 1
    fi
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

    log_success "System requirements check passed"
}

# Install gitleaks
install_gitleaks() {
    log_info "Installing gitleaks v$GITLEAKS_VERSION..."

    if command -v gitleaks &> /dev/null; then
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
        log_error "Failed to extract gitleaks"
        return 1
    fi

    log_info "Installing gitleaks to $INSTALL_DIR..."
    if [ "$EUID" -eq 0 ]; then
        mv "$TEMP_DIR/gitleaks" "$INSTALL_DIR/"
    else
        sudo mv "$TEMP_DIR/gitleaks" "$INSTALL_DIR/"
    fi

    # Set permissions
    if [ "$EUID" -eq 0 ]; then
        chmod +x "$INSTALL_DIR/gitleaks"
    else
        sudo chmod +x "$INSTALL_DIR/gitleaks"
    fi

    # Verify installation
    if ! verify_tool_installation "gitleaks"; then
        return 1
    fi

    log_success "gitleaks v$GITLEAKS_VERSION installed successfully"
    return 0
}

# Install semgrep
install_semgrep() {
    log_info "Installing semgrep..."

    if command -v semgrep &> /dev/null; then
        local current_version
        current_version=$(semgrep --version 2>/dev/null | head -n1 | grep -oP '\d+\.\d+\.\d+' || echo "unknown")
        log_success "semgrep v$current_version is already installed"
        return 0
    fi

    log_info "Installing semgrep via pip..."
    if ! pip install --upgrade semgrep; then
        log_error "Failed to install semgrep via pip"
        log_info "Trying with --user flag..."
        if ! pip install --user --upgrade semgrep; then
            log_error "Failed to install semgrep with --user flag"
            return 1
        fi
    fi

    # Verify installation
    if ! verify_tool_installation "semgrep"; then
        return 1
    fi

    local installed_version
    installed_version=$(semgrep --version 2>/dev/null | head -n1 | grep -oP '\d+\.\d+\.\d+' || echo "unknown")
    log_success "semgrep v$installed_version installed successfully"
    return 0
}

# Install truffleHog
install_trufflehog() {
    log_info "Installing truffleHog v$TRUFFLEHOG_VERSION..."

    if command -v trufflehog &> /dev/null; then
        local current_version
        current_version=$(trufflehog --version 2>/dev/null | grep -oP 'v\K[\d.]+' || echo "unknown")
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
        log_error "Failed to extract truffleHog"
        return 1
    fi

    log_info "Installing truffleHog to $INSTALL_DIR..."
    if [ "$EUID" -eq 0 ]; then
        mv "$TEMP_DIR/trufflehog" "$INSTALL_DIR/"
    else
        sudo mv "$TEMP_DIR/trufflehog" "$INSTALL_DIR/"
    fi

    # Set permissions
    if [ "$EUID" -eq 0 ]; then
        chmod +x "$INSTALL_DIR/trufflehog"
    else
        sudo chmod +x "$INSTALL_DIR/trufflehog"
    fi

    # Verify installation
    if ! verify_tool_installation "trufflehog"; then
        return 1
    fi

    log_success "truffleHog v$TRUFFLEHOG_VERSION installed successfully"
    return 0
}

# Verify tool installation and functionality
verify_tool_installation() {
    local tool="$1"

    log_info "Verifying $tool installation..."

    if ! command -v "$tool" &> /dev/null; then
        log_error "$tool command not found in PATH"
        return 1
    fi

    # Test tool with version command
    case "$tool" in
        "gitleaks")
            if ! gitleaks version &> /dev/null; then
                log_error "$tool version command failed"
                return 1
            fi
            ;;
        "semgrep")
            if ! semgrep --version &> /dev/null; then
                log_error "$tool version command failed"
                return 1
            fi
            ;;
        "trufflehog")
            if ! trufflehog --version &> /dev/null; then
                log_error "$tool version command failed"
                return 1
            fi
            ;;
    esac

    log_success "$tool verification passed"
    return 0
}

# Create directories
create_directories() {
    log_info "Creating required directories..."

    local base_dir="$(dirname "$0")"
    local dirs=("config" "scripts" "reports" "tools")

    for dir in "${dirs[@]}"; do
        if [ ! -d "$base_dir/$dir" ]; then
            mkdir -p "$base_dir/$dir"
            log_info "Created directory: $base_dir/$dir"
        fi
    done

    log_success "Directory structure verified"
}

# Main installation function
main() {
    log_info "Starting GitLab Security Audit System scanner installation..."
    echo "=================================================================="

    # Pre-installation checks
    check_privileges
    check_system_requirements
    create_directories

    # Install tools
    local install_success=true

    if ! install_gitleaks; then
        install_success=false
        log_error "gitleaks installation failed"
    fi

    if ! install_semgrep; then
        install_success=false
        log_error "semgrep installation failed"
    fi

    if ! install_trufflehog; then
        install_success=false
        log_error "truffleHog installation failed"
    fi

    echo "=================================================================="

    if [ "$install_success" = true ]; then
        log_success "All security scanners installed successfully!"
        echo ""
        log_info "Installed tool versions:"
        gitleaks version 2>/dev/null | head -n1 | sed 's/^/  - gitleaks: /'
        semgrep --version 2>/dev/null | head -n1 | sed 's/^/  - semgrep: /'
        trufflehog --version 2>/dev/null | head -n1 | sed 's/^/  - trufflehog: /'
        echo ""
        log_info "Security audit system is ready to use!"
    else
        log_error "Some security scanners failed to install"
        log_info "Please check the error messages above and resolve any issues"
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi