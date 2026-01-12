#!/usr/bin/env zsh
# PipeGuard Zsh Integration
# Intercepts pipe-to-shell patterns before execution
#
# This file is sourced by your .zshrc via the init.sh loader

# Prevent double-loading
[[ -n "$PIPEGUARD_LOADED" ]] && return 0
export PIPEGUARD_LOADED=1

# Configuration with sensible defaults
PIPEGUARD_ENABLED=${PIPEGUARD_ENABLED:-1}
PIPEGUARD_BIN=${PIPEGUARD_BIN:-"${HOME}/.local/bin/pipeguard"}
PIPEGUARD_RULES=${PIPEGUARD_RULES:-"${HOME}/.local/share/pipeguard/rules/core.yar"}
PIPEGUARD_CONFIG=${PIPEGUARD_CONFIG:-"${HOME}/.config/pipeguard/config.toml"}

# Verify pipeguard binary exists
if [[ ! -x "$PIPEGUARD_BIN" ]]; then
    # Try finding in PATH
    if command -v pipeguard &>/dev/null; then
        PIPEGUARD_BIN=$(command -v pipeguard)
    else
        echo "\033[0;33m[PipeGuard] Warning: Binary not found at $PIPEGUARD_BIN\033[0m" >&2
        echo "\033[0;33m[PipeGuard] Run the installer again or check your PATH\033[0m" >&2
        return 0
    fi
fi

# Verify rules file exists
if [[ ! -f "$PIPEGUARD_RULES" ]]; then
    echo "\033[0;33m[PipeGuard] Warning: Rules not found at $PIPEGUARD_RULES\033[0m" >&2
    echo "\033[0;33m[PipeGuard] Using built-in rules only\033[0m" >&2
    PIPEGUARD_RULES=""
fi

# =============================================================================
# Layer 1: ZLE Paste Interception
# =============================================================================

# Original paste widget backup
if [[ -z "$_pipeguard_original_paste" ]]; then
    zle -la bracketed-paste && _pipeguard_original_paste=bracketed-paste
fi

# Intercept paste events
function pipeguard-bracketed-paste() {
    local pasted
    zle .bracketed-paste pasted

    # Check for dangerous patterns
    if [[ "$pasted" =~ 'curl.*\|.*bash' ]] || \
       [[ "$pasted" =~ 'wget.*\|.*sh' ]] || \
       [[ "$pasted" =~ 'curl.*\|.*sh' ]]; then

        if (( PIPEGUARD_ENABLED )); then
            echo ""
            echo "\033[1;33m⚠ PipeGuard: Detected pipe-to-shell pattern in paste\033[0m"
            echo ""

            # Scan with pipeguard
            local result
            result=$( printf '%s' "$pasted" | "$PIPEGUARD_BIN" scan --rules "$PIPEGUARD_RULES" --format text 2>&1 )
            local exit_code=$?

            if (( exit_code != 0 )); then
                echo "\033[1;31m$result\033[0m"
                echo ""
                echo "Press 'y' to execute anyway, any other key to abort: "
                read -k1 confirm
                echo ""

                if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                    echo "\033[1;32m✓ Command aborted by PipeGuard\033[0m"
                    BUFFER=""
                    return 0
                fi
            fi
        fi
    fi

    # Insert the pasted content
    LBUFFER+="$pasted"
}

zle -N bracketed-paste pipeguard-bracketed-paste

# =============================================================================
# Content-Based Smart Filter
# =============================================================================

# Determines if content should be scanned based on its characteristics
# Returns: 0 = Should scan, 1 = Should skip
function _pipeguard_should_scan() {
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
       [[ "$header" =~ '^(if |for |while |function |export |chmod \+x)' ]]; then
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
function curl() {
    local args=("$@")
    local output

    # Check if being piped to a shell
    if [[ ! -t 1 ]]; then
        # Output is being piped, run through pipeguard
        output=$(command curl "${args[@]}")
        local curl_exit=$?

        if (( curl_exit != 0 )); then
            return $curl_exit
        fi

        # Smart content filtering
        if (( PIPEGUARD_ENABLED )) && _pipeguard_should_scan "$output"; then
            local result
            result=$( printf '%s' "$output" | "$PIPEGUARD_BIN" scan --rules "$PIPEGUARD_RULES" 2>&1 )
            local pg_exit=$?

            if (( pg_exit != 0 )); then
                echo "\033[1;31m⚠ PipeGuard blocked execution:\033[0m" >&2
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
function wget() {
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
            result=$( printf '%s' "$output" | "$PIPEGUARD_BIN" scan --rules "$PIPEGUARD_RULES" 2>&1 )
            local pg_exit=$?

            if (( pg_exit != 0 )); then
                echo "\033[1;31m⚠ PipeGuard blocked execution:\033[0m" >&2
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
# Layer 3: Preexec Audit Hook
# =============================================================================

autoload -Uz add-zsh-hook

function pipeguard-preexec() {
    local cmd="$1"

    # Log all commands for audit trail
    if [[ -n "$PIPEGUARD_AUDIT_LOG" ]]; then
        printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$cmd" >> "$PIPEGUARD_AUDIT_LOG"
    fi

    # Check for dangerous patterns even if active blocking is disabled
    if [[ "$cmd" =~ 'curl.*\|.*(ba)?sh' ]] || \
       [[ "$cmd" =~ 'wget.*\|.*(ba)?sh' ]]; then
        if [[ -n "$PIPEGUARD_AUDIT_LOG" ]]; then
            printf '%s\t%s\tWARN: pipe-to-shell pattern detected\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" >> "$PIPEGUARD_AUDIT_LOG"
        fi
    fi
}

add-zsh-hook preexec pipeguard-preexec

# =============================================================================
# Helper Functions
# =============================================================================

# Disable PipeGuard temporarily
function pipeguard-disable() {
    PIPEGUARD_ENABLED=0
    echo "PipeGuard disabled for this session"
}

# Enable PipeGuard
function pipeguard-enable() {
    PIPEGUARD_ENABLED=1
    echo "PipeGuard enabled"
}

# Check PipeGuard status
function pipeguard-status() {
    if (( PIPEGUARD_ENABLED )); then
        echo "PipeGuard: \033[1;32mEnabled\033[0m"
    else
        echo "PipeGuard: \033[1;31mDisabled\033[0m"
    fi
    echo "Binary: $PIPEGUARD_BIN"
    echo "Rules: $PIPEGUARD_RULES"
}

# Manual scan
function pipeguard-scan() {
    if [[ -n "$PIPEGUARD_RULES" ]]; then
        "$PIPEGUARD_BIN" scan --rules "$PIPEGUARD_RULES" "$@"
    else
        "$PIPEGUARD_BIN" scan "$@"
    fi
}

# Quiet startup (only show message if PIPEGUARD_VERBOSE is set)
if [[ -n "$PIPEGUARD_VERBOSE" ]]; then
    echo "\033[0;32m[PipeGuard]\033[0m Loaded. Run 'pipeguard-status' for info."
fi
