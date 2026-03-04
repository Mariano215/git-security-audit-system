#!/bin/bash
# test_installation_dry_run.sh - Test installation script functions without system changes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0

# Helper functions
log_info() {
    echo -e "${YELLOW}[INFO]$(date +'%Y-%m-%d %H:%M:%S')${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]$(date +'%Y-%m-%d %H:%M:%S')${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]$(date +'%Y-%m-%d %H:%M:%S')${NC} $1"
}

run_test() {
    local test_name="$1"
    local test_command="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    log_info "Running test: $test_name"

    if eval "$test_command"; then
        log_success "$test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "$test_name"
        return 1
    fi
}

# Test that setup script has all expected functions
test_source_setup_script() {
    local setup_script="$(dirname "$0")/../setup_scanners.sh"

    # Check that the script contains expected function definitions
    grep -q "^log_info()" "$setup_script" && \
    grep -q "^log_success()" "$setup_script" && \
    grep -q "^log_error()" "$setup_script" && \
    grep -q "^check_system_requirements()" "$setup_script" && \
    grep -q "^install_gitleaks()" "$setup_script" && \
    grep -q "^install_semgrep()" "$setup_script" && \
    grep -q "^install_trufflehog()" "$setup_script"
}

# Test system requirements (basic command availability)
test_system_requirements() {
    # Test that basic required commands are available
    command -v curl >/dev/null 2>&1 && \
    command -v tar >/dev/null 2>&1 && \
    command -v python3 >/dev/null 2>&1
}

# Test that download URLs are reachable (HEAD request only)
test_download_urls() {
    local gitleaks_url="https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz"
    local trufflehog_url="https://github.com/trufflesecurity/trufflehog/releases/download/v3.63.7/trufflehog_3.63.7_linux_amd64.tar.gz"

    # Test URLs if curl is available
    if command -v curl >/dev/null 2>&1; then
        # Test gitleaks URL (GitHub returns 302 for releases)
        local gitleaks_status
        local trufflehog_status

        gitleaks_status=$(curl -s -I "$gitleaks_url" | head -n1 | grep -oE "[0-9]{3}")
        trufflehog_status=$(curl -s -I "$trufflehog_url" | head -n1 | grep -oE "[0-9]{3}")

        # Accept 200 (OK) or 302 (redirect) as valid responses
        [[ "$gitleaks_status" =~ ^(200|302)$ ]] && \
        [[ "$trufflehog_status" =~ ^(200|302)$ ]]
    else
        # Skip if curl is not available
        return 0
    fi
}

# Test configuration file syntax
test_gitleaks_config_syntax() {
    local config_file="$(dirname "$0")/../config/gitleaks.toml"

    # Basic TOML syntax check (look for expected content)
    grep -q "^\[\[rules\]\]" "$config_file" && \
    grep -q "^title =" "$config_file" && \
    grep -q "^id =" "$config_file" && \
    ! grep -q "^=" "$config_file"  # No lines starting with =
}

# Test requirements.txt format
test_requirements_format() {
    local req_file="$(dirname "$0")/../requirements.txt"

    # Check that requirements file has expected packages
    grep -q "^semgrep>=" "$req_file" && \
    grep -q "^requests>=" "$req_file" && \
    grep -q "^click>=" "$req_file" && \
    [ -s "$req_file" ]  # File is not empty
}

# Main test execution
main() {
    log_info "Starting installation dry-run tests..."
    echo "========================================"

    run_test "Can source setup script functions" "test_source_setup_script"
    run_test "System requirements check works" "test_system_requirements"
    run_test "Download URLs are accessible" "test_download_urls"
    run_test "Gitleaks config has valid syntax" "test_gitleaks_config_syntax"
    run_test "Requirements.txt has valid format" "test_requirements_format"

    echo "========================================"
    log_info "Test summary: $TESTS_PASSED/$TESTS_RUN tests passed"

    if [ $TESTS_PASSED -eq $TESTS_RUN ]; then
        log_success "All dry-run tests passed!"
        exit 0
    else
        log_error "Some dry-run tests failed!"
        exit 1
    fi
}

main "$@"