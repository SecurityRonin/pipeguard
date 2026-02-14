#!/usr/bin/env bash
# PipeGuard Bash Integration
# Bash-specific hooks and wrappers; shared logic lives in pipeguard-common.sh
#
# This file is sourced by your .bashrc/.bash_profile via the init.sh loader

# Source shared logic (config, patterns, helpers, scan, update checking)
_pipeguard_common_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${_pipeguard_common_dir}/pipeguard-common.sh" || return 0
unset _pipeguard_common_dir

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

    local _pg_pattern
    _pg_pattern=$(_pipeguard_detect_pattern "$cmd")

    if [[ -n "$_pg_pattern" ]]; then
        echo ""
        printf '\033[1;33m⚠ PipeGuard: Detected %s pattern\033[0m\n' "$_pg_pattern"
        printf '\033[0;36m  Command: %s\033[0m\n' "$cmd"
        echo ""

        # Extract URL
        local url
        url=$(printf '%s' "$cmd" | grep -oE 'https?://[^ |"'"'"';&]+' | head -1)

        if [[ -n "$url" ]]; then
            local _pg_fetch_content _pg_scan_result _pg_scan_exit

            if ! _pipeguard_fetch_and_scan "$url"; then
                # Fetch failed
                read -n1 -p "Press 'y' to run anyway, any other key to abort: " confirm
                echo ""
                if [[ "$confirm" != [yY] ]]; then
                    printf '\033[1;32m✓ Command aborted by PipeGuard\033[0m\n'
                    return 1
                fi
                return 0
            fi

            if (( _pg_scan_exit != 0 )); then
                # Threats detected
                read -n1 -p $'\033[1;33mThreats detected. Press y to run anyway, any other key to abort: \033[0m' confirm
                echo ""

                if [[ "$confirm" != [yY] ]]; then
                    printf '\033[1;32m✓ Command blocked by PipeGuard\033[0m\n'
                    _pipeguard_audit_log "$cmd" "BLOCK"
                    return 1
                fi
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
                printf '\033[1;31m⚠ PipeGuard blocked piped content:\033[0m\n' >&2
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
                printf '\033[1;31m⚠ PipeGuard blocked piped content:\033[0m\n' >&2
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
    _pipeguard_audit_command "$1"
}

# =============================================================================
# Automatic Update Checking (bash-specific background job syntax)
# =============================================================================

_pipeguard_check_updates() {
    if _pipeguard_should_check_update; then
        _pipeguard_run_update_check &
        disown
    fi
}

_pipeguard_check_updates

# =============================================================================
# Verbose Loading Message
# =============================================================================

if [[ -n "$PIPEGUARD_VERBOSE" ]]; then
    printf '\033[0;32m[PipeGuard]\033[0m Loaded. Run '\''pipeguard-status'\'' for info.\n'
fi
