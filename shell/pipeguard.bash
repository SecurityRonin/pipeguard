#!/usr/bin/env bash
# PipeGuard Bash Integration
# Intercepts pipe-to-shell patterns before execution
#
# This file is sourced by your .bashrc/.bash_profile via the init.sh loader

# Prevent double-loading
[[ -n "$PIPEGUARD_LOADED" ]] && return 0
export PIPEGUARD_LOADED=1

# Configuration with sensible defaults
PIPEGUARD_ENABLED=${PIPEGUARD_ENABLED:-1}
PIPEGUARD_BIN=${PIPEGUARD_BIN:-"${HOME}/.local/bin/pipeguard"}
PIPEGUARD_RULES=${PIPEGUARD_RULES:-"${HOME}/.local/share/pipeguard/rules/core.yar"}
PIPEGUARD_CONFIG=${PIPEGUARD_CONFIG:-"${HOME}/.config/pipeguard/config.toml"}
PIPEGUARD_AUDIT_LOG=${PIPEGUARD_AUDIT_LOG:-}

# Verify pipeguard binary exists
if [[ ! -x "$PIPEGUARD_BIN" ]]; then
    # Try finding in PATH
    if command -v pipeguard &>/dev/null; then
        PIPEGUARD_BIN=$(command -v pipeguard)
    else
        echo -e "\033[0;33m[PipeGuard] Warning: Binary not found at $PIPEGUARD_BIN\033[0m" >&2
        echo -e "\033[0;33m[PipeGuard] Run the installer again or check your PATH\033[0m" >&2
        return 0
    fi
fi

# Verify rules file exists
if [[ ! -f "$PIPEGUARD_RULES" ]]; then
    echo -e "\033[0;33m[PipeGuard] Warning: Rules not found at $PIPEGUARD_RULES\033[0m" >&2
    echo -e "\033[0;33m[PipeGuard] Using built-in rules only\033[0m" >&2
    PIPEGUARD_RULES=""
fi

# Helper to run pipeguard scan with or without custom rules
_pipeguard_scan() {
    if [[ -n "$PIPEGUARD_RULES" ]]; then
        "$PIPEGUARD_BIN" scan --rules "$PIPEGUARD_RULES" "$@"
    else
        "$PIPEGUARD_BIN" scan "$@"
    fi
}

# =============================================================================
# Content-Based Smart Filter
# =============================================================================

# Determines if content should be scanned based on its characteristics
# Returns: 0 = Should scan, 1 = Should skip
_pipeguard_should_scan() {
    local content="$1"
    local header

    # Read first 512 bytes for analysis
    header=$(printf '%s' "$content" | head -c 512)

    # Check 1: Shebang detection (definite script)
    if [[ "$header" =~ ^'#!' ]]; then
        return 0  # SCAN
    fi

    # Check 2: Binary file signatures (skip scanning)
    if [[ "$header" =~ $'^\x89PNG' ]] || \
       [[ "$header" =~ $'^\xff\xd8\xff' ]] || \
       [[ "$header" =~ ^'PK' ]] || \
       [[ "$header" =~ $'^\x1f\x8b' ]] || \
       [[ "$header" =~ $'^\x7fELF' ]] || \
       [[ "$header" =~ $'^\xfe\xed\xfa' ]] || \
       [[ "$header" =~ ^'%PDF' ]]; then
        return 1  # SKIP - binary file
    fi

    # Check 3: Shell keywords (likely script)
    if [[ "$header" =~ (bash|/bin/sh|/bin/bash|/bin/zsh|eval|exec|source) ]] || \
       [[ "$header" =~ 'curl.*\||wget.*\||/dev/tcp|nc |netcat|base64 -d' ]] || \
       [[ "$header" =~ ^(if\ |for\ |while\ |function\ |export\ |chmod\ \+x) ]]; then
        return 0  # SCAN - shell content detected
    fi

    # Check 4: Installation script keywords
    if [[ "$header" =~ (install|setup|configure|download|script) ]]; then
        return 0  # SCAN - likely installation script
    fi

    # Default: When uncertain, scan for safety
    return 0  # SCAN
}

# =============================================================================
# Layer 2: Hardened Shell Wrappers
# =============================================================================

# Wrap curl to intercept pipe-to-shell
curl() {
    local args=("$@")
    local output

    # Check if being piped (stdout not a terminal)
    if [[ ! -t 1 ]]; then
        # Output is being piped, fetch and scan
        output=$(command curl "${args[@]}")
        local curl_exit=$?

        if (( curl_exit != 0 )); then
            return $curl_exit
        fi

        # Smart content filtering
        if (( PIPEGUARD_ENABLED )) && _pipeguard_should_scan "$output"; then
            local result
            result=$( printf '%s' "$output" | _pipeguard_scan 2>&1 )
            local pg_exit=$?

            if (( pg_exit != 0 )); then
                echo -e "\033[1;31m⚠ PipeGuard blocked execution:\033[0m" >&2
                echo "$result" >&2
                return 1
            fi
        fi

        printf '%s' "$output"
    else
        command curl "${args[@]}"
    fi
}

# Wrap wget similarly
wget() {
    local args=("$@")

    if [[ ! -t 1 ]]; then
        local output
        output=$(command wget -qO- "${args[@]}")
        local wget_exit=$?

        if (( wget_exit != 0 )); then
            return $wget_exit
        fi

        # Smart content filtering
        if (( PIPEGUARD_ENABLED )) && _pipeguard_should_scan "$output"; then
            local result
            result=$( printf '%s' "$output" | _pipeguard_scan 2>&1 )
            local pg_exit=$?

            if (( pg_exit != 0 )); then
                echo -e "\033[1;31m⚠ PipeGuard blocked execution:\033[0m" >&2
                echo "$result" >&2
                return 1
            fi
        fi

        printf '%s' "$output"
    else
        command wget "${args[@]}"
    fi
}

# =============================================================================
# Layer 3: Preexec Audit Hook (via DEBUG trap)
# =============================================================================

# Use bash-preexec if available, otherwise use DEBUG trap
if [[ -n "${bash_preexec_imported:-}" ]]; then
    # bash-preexec is loaded
    preexec_pipeguard() {
        local cmd="$1"
        _pipeguard_audit "$cmd"
    }
    preexec_functions+=(preexec_pipeguard)
else
    # Fallback to DEBUG trap
    _pipeguard_debug_trap() {
        # Only run once per command
        if [[ "$BASH_COMMAND" != "$_pipeguard_last_cmd" ]]; then
            _pipeguard_last_cmd="$BASH_COMMAND"
            _pipeguard_audit "$BASH_COMMAND"
        fi
    }

    # Only set if not already trapped
    if ! trap -p DEBUG | grep -q pipeguard; then
        trap '_pipeguard_debug_trap' DEBUG
    fi
fi

_pipeguard_audit() {
    local cmd="$1"

    # Log all commands for audit trail
    if [[ -n "$PIPEGUARD_AUDIT_LOG" ]]; then
        printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$cmd" >> "$PIPEGUARD_AUDIT_LOG"
    fi

    # Check for dangerous patterns
    if [[ "$cmd" =~ curl.*\|.*(ba)?sh ]] || \
       [[ "$cmd" =~ wget.*\|.*(ba)?sh ]]; then
        if [[ -n "$PIPEGUARD_AUDIT_LOG" ]]; then
            printf '%s\t%s\tWARN: pipe-to-shell pattern detected\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" >> "$PIPEGUARD_AUDIT_LOG"
        fi
    fi
}

# =============================================================================
# Helper Functions
# =============================================================================

# Disable PipeGuard temporarily
pipeguard-disable() {
    PIPEGUARD_ENABLED=0
    echo "PipeGuard disabled for this session"
}

# Enable PipeGuard
pipeguard-enable() {
    PIPEGUARD_ENABLED=1
    echo "PipeGuard enabled"
}

# Check PipeGuard status
pipeguard-status() {
    if (( PIPEGUARD_ENABLED )); then
        echo -e "PipeGuard: \033[1;32mEnabled\033[0m"
    else
        echo -e "PipeGuard: \033[1;31mDisabled\033[0m"
    fi
    echo "Binary: $PIPEGUARD_BIN"
    echo "Rules: ${PIPEGUARD_RULES:-<built-in>}"
    echo "Config: $PIPEGUARD_CONFIG"
}

# Manual scan
pipeguard-scan() {
    _pipeguard_scan "$@"
}

# Quiet startup (only show message if PIPEGUARD_VERBOSE is set)
if [[ -n "$PIPEGUARD_VERBOSE" ]]; then
    echo -e "\033[0;32m[PipeGuard]\033[0m Loaded. Run 'pipeguard-status' for info."
fi
