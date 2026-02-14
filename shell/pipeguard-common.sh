#!/bin/sh
# PipeGuard Common Shell Integration
# Shared logic sourced by both pipeguard.zsh and pipeguard.bash
#
# This file uses constructs compatible with both bash and zsh.
# It is NOT intended to be sourced by a pure POSIX sh — it relies on
# [[ ]], (( )), and local, which bash and zsh both support.

# Prevent double-loading
[[ -n "$PIPEGUARD_LOADED" ]] && return 0
export PIPEGUARD_LOADED=1

# =============================================================================
# Configuration Defaults
# =============================================================================

PIPEGUARD_ENABLED=${PIPEGUARD_ENABLED:-1}
PIPEGUARD_BIN=${PIPEGUARD_BIN:-"${HOME}/.local/bin/pipeguard"}
PIPEGUARD_RULES=${PIPEGUARD_RULES:-"${HOME}/.local/share/pipeguard/rules/core.yar"}
PIPEGUARD_CONFIG=${PIPEGUARD_CONFIG:-"${HOME}/.config/pipeguard/config.toml"}
PIPEGUARD_AUDIT_LOG=${PIPEGUARD_AUDIT_LOG:-"${HOME}/.local/share/pipeguard/audit.log"}

# =============================================================================
# Binary and Rules Verification
# =============================================================================

if [[ ! -x "$PIPEGUARD_BIN" ]]; then
    if command -v pipeguard &>/dev/null; then
        PIPEGUARD_BIN=$(command -v pipeguard)
    else
        printf '\033[0;33m[PipeGuard] Warning: Binary not found at %s\033[0m\n' "$PIPEGUARD_BIN" >&2
        printf '\033[0;33m[PipeGuard] Run the installer again or check your PATH\033[0m\n' >&2
        return 0
    fi
fi

if [[ ! -f "$PIPEGUARD_RULES" ]]; then
    printf '\033[0;33m[PipeGuard] Warning: Rules not found at %s\033[0m\n' "$PIPEGUARD_RULES" >&2
    printf '\033[0;33m[PipeGuard] Using built-in rules only\033[0m\n' >&2
    PIPEGUARD_RULES=""
fi

# =============================================================================
# Core Scan Helper
# =============================================================================

_pipeguard_scan() {
    if [[ -n "$PIPEGUARD_RULES" ]]; then
        "$PIPEGUARD_BIN" scan --rules "$PIPEGUARD_RULES" "$@"
    else
        "$PIPEGUARD_BIN" scan "$@"
    fi
}

# =============================================================================
# Pattern Constants
# =============================================================================
# Stored as variables so that [[ "$cmd" =~ $var ]] works in both bash and zsh.
# Bash requires unquoted variables for regex; zsh accepts both. Using variables
# satisfies both shells.

# Shell interpreters and eval-like execution targets
_PIPEGUARD_SHELL_TARGETS='(ba|da|k|c|tc|z)?sh|bash|zsh|eval|source|\.'

# Execution targets for download-then-execute pattern
# Catches: && bash file, ; sh file, && chmod +x file, && ./file
_PIPEGUARD_DL_EXEC_TARGETS='(ba|da|k|c|tc|z)?sh|bash|zsh|chmod[[:space:]]+\+x|\.\/'

# URL pattern
_PIPEGUARD_URL_PATTERN='https?://[^[:space:]"'"'"';&|]+'

# Composite patterns for matching (used in accept-line and audit)
_PIPEGUARD_PIPE_PATTERN='\|[[:space:]]*('"$_PIPEGUARD_SHELL_TARGETS"')'
_PIPEGUARD_EXEC_PATTERN='[;&]+[[:space:]]*('"$_PIPEGUARD_DL_EXEC_TARGETS"')'

# =============================================================================
# Pattern Detection
# =============================================================================

# Given a command string, echo "pipe-to-shell" or "download-then-execute" or ""
_pipeguard_detect_pattern() {
    local cmd="$1"

    if [[ "$cmd" =~ $_PIPEGUARD_URL_PATTERN ]]; then
        if [[ "$cmd" =~ $_PIPEGUARD_PIPE_PATTERN ]]; then
            printf '%s' "pipe-to-shell"
            return 0
        elif [[ "$cmd" =~ $_PIPEGUARD_EXEC_PATTERN ]]; then
            printf '%s' "download-then-execute"
            return 0
        fi
    fi
    return 1
}

# =============================================================================
# Content Filter
# =============================================================================
# Smart filter: skip scanning obvious non-scripts (binary files)

_pipeguard_should_scan() {
    local content="$1"
    local header
    header=$(printf '%s' "$content" | head -c 512)

    # Binary signatures -- skip
    if [[ "$header" == $'\x89PNG'* ]] || \
       [[ "$header" == $'\xff\xd8\xff'* ]] || \
       [[ "$header" == 'PK'* ]] || \
       [[ "$header" == $'\x1f\x8b'* ]] || \
       [[ "$header" == $'\x7fELF'* ]] || \
       [[ "$header" == $'\xfe\xed\xfa'* ]] || \
       [[ "$header" == '%PDF'* ]]; then
        return 1  # SKIP -- binary
    fi

    # Shebang or shell keywords -- scan
    if [[ "$header" == '#!'* ]] || \
       [[ "$header" == *bash* ]] || [[ "$header" == */bin/sh* ]] || \
       [[ "$header" == *eval* ]] || [[ "$header" == *export* ]] || \
       [[ "$header" == *chmod* ]] || \
       [[ "$header" == *'curl'*'|'* ]] || [[ "$header" == *'wget'*'|'* ]] || \
       [[ "$header" == */dev/tcp* ]] || [[ "$header" == *base64* ]]; then
        return 0  # SCAN
    fi

    # Default: scan for safety
    return 0
}

# =============================================================================
# Fetch and Scan
# =============================================================================
# Pre-fetches URL content and scans it. Sets variables for the caller:
#   _pg_fetch_content  - the fetched content
#   _pg_scan_result    - scan output text
#   _pg_scan_exit      - scan exit code (0=clean, nonzero=threats)
#
# Returns:
#   0 - fetch and scan completed (check _pg_scan_exit for threats)
#   1 - fetch failed

_pipeguard_fetch_and_scan() {
    local url="$1"

    printf '\033[0;90mScanning remote content from: %s\033[0m\n' "$url"

    _pg_fetch_content=$(command curl -sSL --max-time 30 "$url" 2>/dev/null)
    local fetch_exit=$?

    if (( fetch_exit != 0 )); then
        printf '\033[1;31m✗ Failed to fetch URL (exit %d)\033[0m\n' "$fetch_exit"
        return 1
    fi

    _pg_scan_result=$(printf '%s' "$_pg_fetch_content" | _pipeguard_scan --format text 2>&1)
    _pg_scan_exit=$?

    if (( _pg_scan_exit == 0 )); then
        printf '\033[1;32m✓ Content scanned — no threats detected\033[0m\n'
    else
        printf '\033[1;31m%s\033[0m\n' "$_pg_scan_result"
        printf '\n'
    fi

    return 0
}

# =============================================================================
# Audit Logging
# =============================================================================

_pipeguard_audit_log() {
    local cmd="$1"
    local level="${2:-}"  # optional: "BLOCK", "WARN: ..."

    if [[ -n "$PIPEGUARD_AUDIT_LOG" ]]; then
        if [[ -n "$level" ]]; then
            printf '%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$level" "$cmd" >> "$PIPEGUARD_AUDIT_LOG"
        else
            printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$cmd" >> "$PIPEGUARD_AUDIT_LOG"
        fi
    fi
}

_pipeguard_audit_command() {
    local cmd="$1"

    if [[ -n "$PIPEGUARD_AUDIT_LOG" ]]; then
        printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$cmd" >> "$PIPEGUARD_AUDIT_LOG"

        local pattern
        pattern=$(_pipeguard_detect_pattern "$cmd")
        if [[ -n "$pattern" ]]; then
            printf '%s\t%s\tWARN: %s pattern detected\n' \
                "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$pattern" >> "$PIPEGUARD_AUDIT_LOG"
        fi
    fi
}

# =============================================================================
# Automatic Update Checking
# =============================================================================

PIPEGUARD_UPDATE_CHECK_INTERVAL="${PIPEGUARD_UPDATE_CHECK_INTERVAL:-24}"
PIPEGUARD_TIMESTAMP_FILE="${HOME}/.pipeguard/.last_update_check"

_pipeguard_should_check_update() {
    local current_time interval_seconds last_check
    current_time=$(date +%s)
    interval_seconds=$((PIPEGUARD_UPDATE_CHECK_INTERVAL * 3600))

    if [[ ! -f "$PIPEGUARD_TIMESTAMP_FILE" ]]; then
        mkdir -p "$(dirname "$PIPEGUARD_TIMESTAMP_FILE")"
        printf '%s' "0" > "$PIPEGUARD_TIMESTAMP_FILE"
        return 0
    fi

    last_check=$(cat "$PIPEGUARD_TIMESTAMP_FILE" 2>/dev/null || printf '%s' "0")
    (( current_time - last_check >= interval_seconds ))
}

# _pipeguard_check_updates is defined in the shell-specific scripts because
# the background job syntax differs: zsh uses &! while bash uses & disown.
# The shell-specific scripts call _pipeguard_run_update_check in a background
# job, which contains the actual update logic.

_pipeguard_run_update_check() {
    if pipeguard update check --quiet 2>/dev/null; then
        :
    elif [[ $? -eq 1 ]]; then
        printf '\033[33m⚠️  PipeGuard update available.\033[0m Run: pipeguard update apply\n' >&2
    fi
    mkdir -p "$(dirname "$PIPEGUARD_TIMESTAMP_FILE")"
    printf '%s' "$(date +%s)" > "$PIPEGUARD_TIMESTAMP_FILE"
}

# =============================================================================
# Helper Functions
# =============================================================================

pipeguard-disable() {
    PIPEGUARD_ENABLED=0
    printf '%s\n' "PipeGuard disabled for this session"
}

pipeguard-enable() {
    PIPEGUARD_ENABLED=1
    printf '%s\n' "PipeGuard enabled"
}

pipeguard-status() {
    if (( PIPEGUARD_ENABLED )); then
        printf 'PipeGuard: \033[1;32mEnabled\033[0m\n'
    else
        printf 'PipeGuard: \033[1;31mDisabled\033[0m\n'
    fi
    printf 'Binary: %s\n' "$PIPEGUARD_BIN"
    printf 'Rules: %s\n' "${PIPEGUARD_RULES:-<built-in>}"
    printf 'Audit: %s\n' "${PIPEGUARD_AUDIT_LOG:-<disabled>}"
}

pipeguard-scan() {
    _pipeguard_scan "$@"
}
