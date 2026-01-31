#!/bin/bash

################################################################################
# WordPress VAPT Testing Script
#
# This script automates security testing for WordPress installations
# Run with --help for usage information
#
# Deployment: .agent/skills/wordpress-vapt-expert/scripts/vapt-test.sh
# Permissions: chmod +x vapt-test.sh
################################################################################

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script version
VERSION="1.0.0"

# Default values
TARGET_URL=""
TEST_TYPE="all"
OUTPUT_DIR="./vapt-results"
VERBOSE=false

################################################################################
# Helper Functions
################################################################################

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         WordPress VAPT Testing Script v${VERSION}              ║"
    echo "║         Automated Security Testing & Evidence Generation    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_help() {
    cat << EOF
Usage: $0 [OPTIONS]

OPTIONS:
    -u, --url URL           Target WordPress URL (required)
    -t, --test TYPE         Test type: all, headers, sqli, xss, enum, xmlrpc,
                           rest, csrf, auth, config (default: all)
    -o, --output DIR        Output directory for results (default: ./vapt-results)
    -v, --verbose          Enable verbose output
    -h, --help             Display this help message
    --version              Display script version

EXAMPLES:
    # Test all security features
    $0 -u https://example.com

    # Test only security headers
    $0 -u https://example.com -t headers

    # Test with custom output directory
    $0 -u https://example.com -o /tmp/security-test

    # Verbose mode
    $0 -u https://example.com -v

AVAILABLE TESTS:
    all         - Run all security tests
    headers     - Security headers (CSP, X-Frame-Options, etc.)
    sqli        - SQL Injection vulnerability testing
    xss         - Cross-Site Scripting testing
    enum        - User enumeration testing
    xmlrpc      - XML-RPC security testing
    rest        - REST API security testing
    csrf        - CSRF protection testing
    auth        - Authentication security testing
    config      - Configuration security testing

EOF
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_verbose() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${NC}[DEBUG] $1"
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."

    local missing_deps=()

    command -v curl >/dev/null 2>&1 || missing_deps+=("curl")
    command -v grep >/dev/null 2>&1 || missing_deps+=("grep")
    command -v awk >/dev/null 2>&1 || missing_deps+=("awk")

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        echo "Please install missing dependencies and try again."
        exit 1
    fi

    log_success "All dependencies satisfied"
}

create_output_dir() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        log_success "Created output directory: $OUTPUT_DIR"
    fi
}

################################################################################
# Test Functions
################################################################################

test_security_headers() {
    log_info "Testing Security Headers..."

    local output_file="$OUTPUT_DIR/security-headers.txt"
    local temp_file=$(mktemp)

    curl -sI "$TARGET_URL" > "$temp_file"

    # Check for important security headers
    local headers=(
        "X-Frame-Options"
        "X-Content-Type-Options"
        "X-XSS-Protection"
        "Strict-Transport-Security"
        "Content-Security-Policy"
        "Referrer-Policy"
        "Permissions-Policy"
    )

    echo "=== Security Headers Test Results ===" > "$output_file"
    echo "Target: $TARGET_URL" >> "$output_file"
    echo "Date: $(date)" >> "$output_file"
    echo "" >> "$output_file"

    local missing_headers=()
    local present_headers=()

    for header in "${headers[@]}"; do
        if grep -qi "^$header:" "$temp_file"; then
            local value=$(grep -i "^$header:" "$temp_file" | cut -d: -f2- | xargs)
            present_headers+=("$header")
            echo "[✓] $header: $value" >> "$output_file"
            log_success "$header present"
        else
            missing_headers+=("$header")
            echo "[✗] $header: MISSING" >> "$output_file"
            log_warning "$header missing"
        fi
    done

    echo "" >> "$output_file"
    echo "Summary:" >> "$output_file"
    echo "- Headers Present: ${#present_headers[@]}/${#headers[@]}" >> "$output_file"
    echo "- Headers Missing: ${#missing_headers[@]}/${#headers[@]}" >> "$output_file"

    if [ ${#missing_headers[@]} -eq 0 ]; then
        echo "- Status: PASSED ✓" >> "$output_file"
        log_success "All security headers present"
    else
        echo "- Status: FAILED ✗" >> "$output_file"
        echo "- Missing: ${missing_headers[*]}" >> "$output_file"
        log_warning "Some security headers missing"
    fi

    rm "$temp_file"
    log_info "Results saved to: $output_file"
}

test_sql_injection() {
    log_info "Testing SQL Injection Protection..."

    local output_file="$OUTPUT_DIR/sql-injection.txt"

    echo "=== SQL Injection Test Results ===" > "$output_file"
    echo "Target: $TARGET_URL" >> "$output_file"
    echo "Date: $(date)" >> "$output_file"
    echo "" >> "$output_file"

    # Common SQLi payloads
    local payloads=(
        "' OR '1'='1"
        "\" OR \"1\"=\"1"
        "' OR 1=1--"
        "admin' --"
        "1' UNION SELECT NULL--"
    )

    local vulnerable=false

    for payload in "${payloads[@]}"; do
        log_verbose "Testing payload: $payload"

        local encoded_payload=$(echo "$payload" | sed 's/ /%20/g' | sed "s/'/%27/g" | sed 's/"/%22/g')
        local test_url="${TARGET_URL}?id=${encoded_payload}"

        local response=$(curl -s -o /dev/null -w "%{http_code}" "$test_url")
        local content=$(curl -s "$test_url")

        echo "Payload: $payload" >> "$output_file"
        echo "HTTP Status: $response" >> "$output_file"

        # Check for SQL error messages
        if echo "$content" | grep -qi "sql\|mysql\|database error\|warning.*mysql"; then
            echo "Result: VULNERABLE - SQL error detected" >> "$output_file"
            log_error "Potential SQL injection vulnerability detected"
            vulnerable=true
        else
            echo "Result: Protected" >> "$output_file"
            log_verbose "Payload blocked or no SQL error"
        fi
        echo "" >> "$output_file"
    done

    if [ "$vulnerable" = false ]; then
        echo "Summary: PASSED ✓ - No SQL injection vulnerabilities detected" >> "$output_file"
        log_success "SQL Injection tests passed"
    else
        echo "Summary: FAILED ✗ - Potential SQL injection vulnerabilities found" >> "$output_file"
        log_warning "SQL Injection vulnerabilities detected"
    fi

    log_info "Results saved to: $output_file"
}

test_xss_protection() {
    log_info "Testing XSS Protection..."

    local output_file="$OUTPUT_DIR/xss-protection.txt"

    echo "=== XSS Protection Test Results ===" > "$output_file"
    echo "Target: $TARGET_URL" >> "$output_file"
    echo "Date: $(date)" >> "$output_file"
    echo "" >> "$output_file"

    # Common XSS payloads
    local payloads=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "<svg/onload=alert('XSS')>"
        "javascript:alert('XSS')"
    )

    local vulnerable=false

    for payload in "${payloads[@]}"; do
        log_verbose "Testing XSS payload: $payload"

        local encoded_payload=$(echo "$payload" | sed 's/ /%20/g' | sed 's/</%3C/g' | sed 's/>/%3E/g')
        local test_url="${TARGET_URL}?search=${encoded_payload}"

        local content=$(curl -s "$test_url")

        echo "Payload: $payload" >> "$output_file"

        # Check if payload is reflected unescaped
        if echo "$content" | grep -qF "$payload"; then
            echo "Result: VULNERABLE - Unescaped script detected" >> "$output_file"
            log_error "XSS vulnerability detected"
            vulnerable=true
        else
            echo "Result: Protected - Payload escaped or filtered" >> "$output_file"
            log_verbose "XSS payload properly handled"
        fi
        echo "" >> "$output_file"
    done

    if [ "$vulnerable" = false ]; then
        echo "Summary: PASSED ✓ - XSS protection working" >> "$output_file"
        log_success "XSS protection tests passed"
    else
        echo "Summary: FAILED ✗ - XSS vulnerabilities found" >> "$output_file"
        log_warning "XSS vulnerabilities detected"
    fi

    log_info "Results saved to: $output_file"
}

test_user_enumeration() {
    log_info "Testing User Enumeration Protection..."

    local output_file="$OUTPUT_DIR/user-enumeration.txt"

    echo "=== User Enumeration Test Results ===" > "$output_file"
    echo "Target: $TARGET_URL" >> "$output_file"
    echo "Date: $(date)" >> "$output_file"
    echo "" >> "$output_file"

    # Test author archives
    local author_test=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/?author=1")
    echo "Author Archive Test (/?author=1):" >> "$output_file"
    echo "HTTP Status: $author_test" >> "$output_file"

    if [ "$author_test" = "200" ]; then
        echo "Result: VULNERABLE - Author archives accessible" >> "$output_file"
        log_warning "User enumeration possible via author archives"
    else
        echo "Result: Protected" >> "$output_file"
        log_success "Author archives protected"
    fi
    echo "" >> "$output_file"

    # Test REST API user endpoint
    local rest_test=$(curl -s "${TARGET_URL}/wp-json/wp/v2/users")
    echo "REST API Users Endpoint (/wp-json/wp/v2/users):" >> "$output_file"

    if echo "$rest_test" | grep -q "slug"; then
        echo "Result: VULNERABLE - User information exposed via REST API" >> "$output_file"
        log_warning "User enumeration possible via REST API"
    else
        echo "Result: Protected or disabled" >> "$output_file"
        log_success "REST API users endpoint protected"
    fi
    echo "" >> "$output_file"

    echo "Summary: Review results above for enumeration vulnerabilities" >> "$output_file"
    log_info "Results saved to: $output_file"
}

test_xmlrpc_security() {
    log_info "Testing XML-RPC Security..."

    local output_file="$OUTPUT_DIR/xmlrpc-security.txt"

    echo "=== XML-RPC Security Test Results ===" > "$output_file"
    echo "Target: $TARGET_URL" >> "$output_file"
    echo "Date: $(date)" >> "$output_file"
    echo "" >> "$output_file"

    # Test if XML-RPC is accessible
    local xmlrpc_url="${TARGET_URL}/xmlrpc.php"
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$xmlrpc_url")

    echo "XML-RPC Endpoint Test ($xmlrpc_url):" >> "$output_file"
    echo "HTTP Status: $response" >> "$output_file"

    if [ "$response" = "405" ] || [ "$response" = "403" ]; then
        echo "Result: PASSED ✓ - XML-RPC disabled or blocked" >> "$output_file"
        log_success "XML-RPC properly secured"
    elif [ "$response" = "200" ]; then
        echo "Result: FAILED ✗ - XML-RPC is accessible" >> "$output_file"
        log_warning "XML-RPC is accessible and may be vulnerable"

        # Test system.listMethods
        local methods_test=$(curl -s -X POST -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' "$xmlrpc_url")

        echo "" >> "$output_file"
        echo "Available Methods Test:" >> "$output_file"
        if echo "$methods_test" | grep -q "methodResponse"; then
            echo "Result: XML-RPC fully functional - SECURITY RISK" >> "$output_file"
            log_error "XML-RPC is fully functional - high security risk"
        fi
    else
        echo "Result: UNKNOWN - Unexpected response" >> "$output_file"
    fi

    log_info "Results saved to: $output_file"
}

test_rest_api_security() {
    log_info "Testing REST API Security..."

    local output_file="$OUTPUT_DIR/rest-api-security.txt"

    echo "=== REST API Security Test Results ===" > "$output_file"
    echo "Target: $TARGET_URL" >> "$output_file"
    echo "Date: $(date)" >> "$output_file"
    echo "" >> "$output_file"

    # Test REST API root
    local api_root="${TARGET_URL}/wp-json/"
    local response=$(curl -s "$api_root")

    echo "REST API Root Test ($api_root):" >> "$output_file"

    if echo "$response" | grep -q "authentication_failure\|rest_forbidden"; then
        echo "Result: PASSED ✓ - REST API restricted" >> "$output_file"
        log_success "REST API properly secured"
    elif echo "$response" | grep -q "namespace"; then
        echo "Result: WARNING - REST API fully accessible" >> "$output_file"
        log_warning "REST API is accessible without authentication"
    else
        echo "Result: Protected or disabled" >> "$output_file"
        log_success "REST API appears protected"
    fi

    log_info "Results saved to: $output_file"
}

test_wordpress_config() {
    log_info "Testing WordPress Configuration Security..."

    local output_file="$OUTPUT_DIR/config-security.txt"

    echo "=== Configuration Security Test Results ===" > "$output_file"
    echo "Target: $TARGET_URL" >> "$output_file"
    echo "Date: $(date)" >> "$output_file"
    echo "" >> "$output_file"

    # Test wp-config.php accessibility
    local config_test=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/wp-config.php")
    echo "wp-config.php Access Test:" >> "$output_file"
    echo "HTTP Status: $config_test" >> "$output_file"

    if [ "$config_test" = "403" ] || [ "$config_test" = "404" ]; then
        echo "Result: PASSED ✓ - wp-config.php not accessible" >> "$output_file"
        log_success "wp-config.php properly protected"
    else
        echo "Result: FAILED ✗ - wp-config.php may be accessible" >> "$output_file"
        log_error "wp-config.php may be accessible - critical security risk!"
    fi
    echo "" >> "$output_file"

    # Test readme.html
    local readme_test=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/readme.html")
    echo "readme.html Test:" >> "$output_file"
    echo "HTTP Status: $readme_test" >> "$output_file"

    if [ "$readme_test" = "404" ] || [ "$readme_test" = "403" ]; then
        echo "Result: PASSED ✓ - readme.html removed or blocked" >> "$output_file"
        log_success "readme.html properly handled"
    else
        echo "Result: WARNING - readme.html accessible (version disclosure)" >> "$output_file"
        log_warning "readme.html accessible - may disclose WordPress version"
    fi
    echo "" >> "$output_file"

    # Test directory listing
    local uploads_test=$(curl -s "${TARGET_URL}/wp-content/uploads/")
    echo "Directory Listing Test (wp-content/uploads/):" >> "$output_file"

    if echo "$uploads_test" | grep -qi "index of"; then
        echo "Result: FAILED ✗ - Directory listing enabled" >> "$output_file"
        log_error "Directory listing enabled - security risk"
    else
        echo "Result: PASSED ✓ - Directory listing disabled" >> "$output_file"
        log_success "Directory listing disabled"
    fi

    log_info "Results saved to: $output_file"
}

generate_summary_report() {
    log_info "Generating summary report..."

    local summary_file="$OUTPUT_DIR/SUMMARY.txt"

    echo "╔══════════════════════════════════════════════════════════════╗" > "$summary_file"
    echo "║         WordPress VAPT Testing - Summary Report             ║" >> "$summary_file"
    echo "╚══════════════════════════════════════════════════════════════╝" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "Target URL: $TARGET_URL" >> "$summary_file"
    echo "Test Date: $(date)" >> "$summary_file"
    echo "Test Type: $TEST_TYPE" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "═══════════════════════════════════════════════════════════════" >> "$summary_file"
    echo "DETAILED RESULTS" >> "$summary_file"
    echo "═══════════════════════════════════════════════════════════════" >> "$summary_file"
    echo "" >> "$summary_file"

    # Add results from each test file
    for file in "$OUTPUT_DIR"/*.txt; do
        if [ "$file" != "$summary_file" ] && [ -f "$file" ]; then
            echo "" >> "$summary_file"
            cat "$file" >> "$summary_file"
            echo "" >> "$summary_file"
            echo "───────────────────────────────────────────────────────────────" >> "$summary_file"
        fi
    done

    echo "" >> "$summary_file"
    echo "═══════════════════════════════════════════════════════════════" >> "$summary_file"
    echo "RECOMMENDATIONS" >> "$summary_file"
    echo "═══════════════════════════════════════════════════════════════" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "1. Review all FAILED and WARNING items above" >> "$summary_file"
    echo "2. Implement missing security controls" >> "$summary_file"
    echo "3. Regularly update WordPress core, plugins, and themes" >> "$summary_file"
    echo "4. Enable security logging and monitoring" >> "$summary_file"
    echo "5. Conduct periodic security assessments" >> "$summary_file"
    echo "" >> "$summary_file"
    echo "All test results saved in: $OUTPUT_DIR" >> "$summary_file"

    log_success "Summary report generated: $summary_file"
}

################################################################################
# Main Execution
################################################################################

main() {
    print_banner

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--url)
                TARGET_URL="$2"
                shift 2
                ;;
            -t|--test)
                TEST_TYPE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                print_help
                exit 0
                ;;
            --version)
                echo "WordPress VAPT Testing Script v${VERSION}"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                print_help
                exit 1
                ;;
        esac
    done

    # Validate required parameters
    if [ -z "$TARGET_URL" ]; then
        log_error "Target URL is required"
        print_help
        exit 1
    fi

    # Check dependencies
    check_dependencies

    # Create output directory
    create_output_dir

    log_info "Starting security tests for: $TARGET_URL"
    log_info "Test type: $TEST_TYPE"
    echo ""

    # Run tests based on type
    case $TEST_TYPE in
        all)
            test_security_headers
            test_sql_injection
            test_xss_protection
            test_user_enumeration
            test_xmlrpc_security
            test_rest_api_security
            test_wordpress_config
            ;;
        headers)
            test_security_headers
            ;;
        sqli)
            test_sql_injection
            ;;
        xss)
            test_xss_protection
            ;;
        enum)
            test_user_enumeration
            ;;
        xmlrpc)
            test_xmlrpc_security
            ;;
        rest)
            test_rest_api_security
            ;;
        config)
            test_wordpress_config
            ;;
        *)
            log_error "Invalid test type: $TEST_TYPE"
            print_help
            exit 1
            ;;
    esac

    echo ""
    generate_summary_report

    echo ""
    log_success "Testing complete!"
    log_info "Review the summary report at: $OUTPUT_DIR/SUMMARY.txt"
}

# Run main function
main "$@"
