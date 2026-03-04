#!/bin/bash
# test_setup.sh - Test script for security scanner setup

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

# Test 1: Verify directory structure exists
test_directory_structure() {
    local base_dir="$(dirname "$0")/.."

    [ -d "$base_dir/config" ] && \
    [ -d "$base_dir/scripts" ] && \
    [ -d "$base_dir/reports" ] && \
    [ -d "$base_dir/tools" ] && \
    [ -d "$base_dir/tests" ]
}

# Test 2: Verify setup script exists and is executable
test_setup_script_exists() {
    local setup_script="$(dirname "$0")/../setup_scanners.sh"
    [ -f "$setup_script" ] && [ -x "$setup_script" ]
}

# Test 3: Verify setup script syntax
test_setup_script_syntax() {
    local setup_script="$(dirname "$0")/../setup_scanners.sh"
    bash -n "$setup_script"
}

# Test 4: Verify requirements.txt exists
test_requirements_exists() {
    local requirements_file="$(dirname "$0")/../requirements.txt"
    [ -f "$requirements_file" ]
}

# Test 5: Verify gitleaks config exists
test_gitleaks_config_exists() {
    local config_file="$(dirname "$0")/../config/gitleaks.toml"
    [ -f "$config_file" ]
}

# Main test execution
main() {
    log_info "Starting security audit setup tests..."
    echo "========================================"

    run_test "Directory structure exists" "test_directory_structure"
    run_test "Setup script exists and is executable" "test_setup_script_exists"
    run_test "Setup script has valid syntax" "test_setup_script_syntax"
    run_test "Requirements.txt exists" "test_requirements_exists"
    run_test "Gitleaks config exists" "test_gitleaks_config_exists"

    echo "========================================"
    log_info "Test summary: $TESTS_PASSED/$TESTS_RUN tests passed"

    if [ $TESTS_PASSED -eq $TESTS_RUN ]; then
        log_success "All tests passed!"
        exit 0
    else
        log_error "Some tests failed!"
        exit 1
    fi
}

main "$@"