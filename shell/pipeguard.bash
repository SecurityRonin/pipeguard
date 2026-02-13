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
PIPEGUARD_AUDIT_LOG=${PIPEGUARD_AUDIT_LOG:-"${HOME}/.local/share/pipeguard/audit.log"}

# Verify pipeguard binary exists
if [[ ! -x "$PIPEGUARD_BIN" ]]; then
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
# Layer 0: Accept-Line Interception (PRIMARY DEFENSE)
# =============================================================================
# Uses bash's DEBUG trap to inspect the full command line before execution.
# This sees both sides of the pipe, solving the anonymous-pipe problem.
#
# When a pipe-to-shell pattern is detected, this layer:
#   1. Pre-fetches the remote content
#   2. Scans it with YARA rules
#   3. If threats found: prompts the user
#   4. If approved: runs the ALREADY-SCANNED content (TOCTOU-safe)

_pipeguard_last_readline=""

_pipeguard_check_command() {
    # Get the full readline buffer (the command about to run)
    local cmd
    cmd=$(HISTTIMEFORMAT= history 1 | sed 's/^[[:space:]]*[0-9]*[[:space:]]*//')

    # Avoid re-checking the same command
    [[ "$cmd" == "$_pipeguard_last_readline" ]] && return 0
    _pipeguard_last_readline="$cmd"

    # Skip if disabled
    (( ! PIPEGUARD_ENABLED )) && return 0

    # Detect pipe-to-shell patterns
    if [[ "$cmd" =~ (curl|wget|fetch)[[:space:]]+.*\|[[:space:]]*(sh|bash|dash|zsh|ksh) ]]; then
        echo ""
        echo -e "\033[1;33m⚠ PipeGuard: Detected pipe-to-shell pattern\033[0m"
        echo -e "\033[0;36m  Command: $cmd\033[0m"
        echo ""

        # Extract URL
        local url
        url=$(printf '%s' "$cmd" | grep -oE 'https?://[^ |"'"'"']+' | head -1)

        if [[ -n "$url" ]]; then
            echo -e "\033[0;90mScanning remote content from: $url\033[0m"

            local content
            content=$(command curl -sSL --max-time 30 "$url" 2>/dev/null)
            local fetch_exit=$?

            if (( fetch_exit != 0 )); then
                echo -e "\033[1;31m✗ Failed to fetch URL (exit $fetch_exit)\033[0m"
                read -n1 -p "Press 'y' to run anyway, any other key to abort: " confirm
                echo ""
                if [[ "$confirm" != [yY] ]]; then
                    echo -e "\033[1;32m✓ Command aborted by PipeGuard\033[0m"
                    return 1
                fi
                return 0
            fi

            local scan_result
            scan_result=$(printf '%s' "$content" | _pipeguard_scan --format text 2>&1)
            local scan_exit=$?

            if (( scan_exit != 0 )); then
                echo -e "\033[1;31m$scan_result\033[0m"
                echo ""
                read -n1 -p $'\033[1;33mThreats detected. Press y to run anyway, any other key to abort: \033[0m' confirm
                echo ""

                if [[ "$confirm" != [yY] ]]; then
                    echo -e "\033[1;32m✓ Command blocked by PipeGuard\033[0m"
                    if [[ -n "$PIPEGUARD_AUDIT_LOG" ]]; then
                        printf '%s\t%s\tBLOCK\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$cmd" >> "$PIPEGUARD_AUDIT_LOG"
                    fi
                    return 1
                fi
            else
                echo -e "\033[1;32m✓ Content scanned — no threats detected\033[0m"
            fi
        fi
    fi

    return 0
}

# Use bash-preexec if available (more reliable), otherwise DEBUG trap
if [[ -n "${bash_preexec_imported:-}" ]]; then
    preexec_pipeguard_check() {
        _pipeguard_check_command || return 1
    }
    preexec_functions+=(preexec_pipeguard_check)
else
    trap '_pipeguard_check_command || { return 1 2>/dev/null; }' DEBUG
fi

# =============================================================================
# Layer 2: Hardened Shell Wrappers (Defense-in-Depth)
# =============================================================================
# Catches cases that bypass Layer 0:
#   - `command curl URL | bash`
#   - Commands built via eval, aliases, or scripts

_pipeguard_should_scan() {
    local content="$1"
    local header
    header=$(printf '%s' "$content" | head -c 512)

    # Binary signatures — skip
    if [[ "$header" == $'\x89PNG'* ]] || \
       [[ "$header" == $'\xff\xd8\xff'* ]] || \
       [[ "$header" == 'PK'* ]] || \
       [[ "$header" == $'\x1f\x8b'* ]] || \
       [[ "$header" == $'\x7fELF'* ]] || \
       [[ "$header" == $'\xfe\xed\xfa'* ]] || \
       [[ "$header" == '%PDF'* ]]; then
        return 1  # SKIP — binary
    fi

    return 0  # SCAN
}

curl() {
    local args=("$@")

    if [[ ! -t 1 ]] && (( PIPEGUARD_ENABLED )); then
        local output
        output=$(command curl "${args[@]}")
        local curl_exit=$?

        if (( curl_exit != 0 )); then
            return $curl_exit
        fi

        if _pipeguard_should_scan "$output"; then
            local result
            result=$(printf '%s' "$output" | _pipeguard_scan 2>&1)
            local pg_exit=$?

            if (( pg_exit != 0 )); then
                echo -e "\033[1;31m⚠ PipeGuard blocked piped content:\033[0m" >&2
                echo "$result" >&2
                return 1
            fi
        fi

        printf '%s' "$output"
    else
        command curl "${args[@]}"
    fi
}

wget() {
    local args=("$@")

    if [[ ! -t 1 ]] && (( PIPEGUARD_ENABLED )); then
        local output
        output=$(command wget -qO- "${args[@]}")
        local wget_exit=$?

        if (( wget_exit != 0 )); then
            return $wget_exit
        fi

        if _pipeguard_should_scan "$output"; then
            local result
            result=$(printf '%s' "$output" | _pipeguard_scan 2>&1)
            local pg_exit=$?

            if (( pg_exit != 0 )); then
                echo -e "\033[1;31m⚠ PipeGuard blocked piped content:\033[0m" >&2
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

_pipeguard_audit() {
    local cmd="$1"

    if [[ -n "$PIPEGUARD_AUDIT_LOG" ]]; then
        printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$cmd" >> "$PIPEGUARD_AUDIT_LOG"

        if [[ "$cmd" =~ (curl|wget|fetch).*\|.*(ba)?sh ]]; then
            printf '%s\t%s\tWARN: pipe-to-shell pattern detected\n' \
                "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" >> "$PIPEGUARD_AUDIT_LOG"
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
        echo "0" > "$PIPEGUARD_TIMESTAMP_FILE"
        return 0
    fi

    last_check=$(cat "$PIPEGUARD_TIMESTAMP_FILE" 2>/dev/null || echo "0")
    (( current_time - last_check >= interval_seconds ))
}

_pipeguard_check_updates() {
    if _pipeguard_should_check_update; then
        (
            if pipeguard update check --quiet 2>/dev/null; then
                :
            elif [[ $? -eq 1 ]]; then
                printf "\033[33m⚠️  PipeGuard update available.\033[0m Run: pipeguard update apply\n" >&2
            fi
            mkdir -p "$(dirname "$PIPEGUARD_TIMESTAMP_FILE")"
            echo "$(date +%s)" > "$PIPEGUARD_TIMESTAMP_FILE"
        ) &
        disown
    fi
}

_pipeguard_check_updates

# =============================================================================
# Helper Functions
# =============================================================================

pipeguard-disable() {
    PIPEGUARD_ENABLED=0
    echo "PipeGuard disabled for this session"
}

pipeguard-enable() {
    PIPEGUARD_ENABLED=1
    echo "PipeGuard enabled"
}

pipeguard-status() {
    if (( PIPEGUARD_ENABLED )); then
        echo -e "PipeGuard: \033[1;32mEnabled\033[0m"
    else
        echo -e "PipeGuard: \033[1;31mDisabled\033[0m"
    fi
    echo "Binary: $PIPEGUARD_BIN"
    echo "Rules: ${PIPEGUARD_RULES:-<built-in>}"
    echo "Audit: ${PIPEGUARD_AUDIT_LOG:-<disabled>}"
}

pipeguard-scan() {
    _pipeguard_scan "$@"
}

if [[ -n "$PIPEGUARD_VERBOSE" ]]; then
    echo -e "\033[0;32m[PipeGuard]\033[0m Loaded. Run 'pipeguard-status' for info."
fi
