#!/usr/bin/env zsh
# PipeGuard Zsh Integration
# Zsh-specific hooks and widgets; shared logic lives in pipeguard-common.sh
#
# This file is sourced by your .zshrc via the init.sh loader

# Source shared logic (config, patterns, helpers, scan, update checking)
source "${0:A:h}/pipeguard-common.sh" || return 0

# =============================================================================
# Layer 0: Accept-Line Interception (PRIMARY DEFENSE)
# =============================================================================
# Intercepts the full command line when the user presses Enter.
# This is the most reliable layer because it sees both sides of the pipe,
# solving the fundamental problem that Unix pipes are anonymous -- the
# curl wrapper cannot know what process will consume its output.
#
# When a pipe-to-shell pattern is detected, this layer:
#   1. Pre-fetches the remote content
#   2. Scans it with YARA rules
#   3. If threats found: prompts the user
#   4. If approved: runs the ALREADY-SCANNED content (TOCTOU-safe)

function pipeguard-accept-line() {
    local cmd="$BUFFER"

    # Skip if disabled or empty command
    if (( ! PIPEGUARD_ENABLED )) || [[ -z "$cmd" ]]; then
        zle .accept-line
        return
    fi

    local _pg_pattern
    _pg_pattern=$(_pipeguard_detect_pattern "$cmd")

    if [[ -n "$_pg_pattern" ]]; then
        echo ""
        printf '\033[1;33m⚠ PipeGuard: Detected %s pattern\033[0m\n' "$_pg_pattern"
        printf '\033[0;36m  Command: %s\033[0m\n' "$cmd"
        echo ""

        # Extract URL from the command (first http/https URL found)
        local url
        url=$(printf '%s' "$cmd" | grep -oE 'https?://[^ |"'"'"';&]+' | head -1)

        if [[ -n "$url" ]]; then
            local _pg_fetch_content _pg_scan_result _pg_scan_exit

            if ! _pipeguard_fetch_and_scan "$url"; then
                # Fetch failed
                echo "Press 'y' to run original command anyway, any other key to abort: \c"
                read -k1 confirm
                echo ""
                if [[ "$confirm" != [yY] ]]; then
                    printf '\033[1;32m✓ Command aborted by PipeGuard\033[0m\n'
                    BUFFER=""
                    zle redisplay
                    return 0
                fi
                zle .accept-line
                return
            fi

            if (( _pg_scan_exit != 0 )); then
                # Threats detected
                printf '\033[1;33mThreats detected. Press '\''y'\'' to run anyway, any other key to abort: \033[0m\c'
                read -k1 confirm
                echo ""

                if [[ "$confirm" != [yY] ]]; then
                    printf '\033[1;32m✓ Command blocked by PipeGuard\033[0m\n'
                    _pipeguard_audit_log "$cmd" "BLOCK"
                    BUFFER=""
                    zle redisplay
                    return 0
                fi
            fi

            # TOCTOU-safe substitution: only possible for pipe-to-shell pattern.
            # Replace everything before the pipe with printf of scanned content.
            # For download-then-execute, the tool writes to a file, so we
            # accept the scan result and let the original command run.
            if [[ "$_pg_pattern" == "pipe-to-shell" ]]; then
                local shell_cmd
                shell_cmd=$(printf '%s' "$cmd" | sed -E 's/^.*\|[[:space:]]*//')
                BUFFER="printf '%s' ${(q)_pg_fetch_content} | $shell_cmd"
            fi
        fi
    fi

    zle .accept-line
}

zle -N accept-line pipeguard-accept-line

# =============================================================================
# Layer 1: ZLE Paste Interception
# =============================================================================
# Early warning when user pastes content containing pipe-to-shell patterns.
# Triggers before the user even presses Enter -- immediate visual feedback.

if [[ -z "$_pipeguard_original_paste" ]]; then
    zle -la bracketed-paste && _pipeguard_original_paste=bracketed-paste
fi

function pipeguard-bracketed-paste() {
    local pasted
    zle .bracketed-paste pasted

    if (( PIPEGUARD_ENABLED )); then
        local _pg_paste_warn
        _pg_paste_warn=$(_pipeguard_detect_pattern "$pasted")
        if [[ -n "$_pg_paste_warn" ]]; then
            echo ""
            if [[ "$_pg_paste_warn" == "pipe-to-shell" ]]; then
                printf '\033[1;33m⚠ PipeGuard: Pipe-to-shell pattern detected in paste\033[0m\n'
            else
                printf '\033[1;33m⚠ PipeGuard: Download-then-execute pattern detected in paste\033[0m\n'
            fi
            printf '\033[0;90m  Tip: Press Enter to trigger full scan, or Ctrl-C to abort\033[0m\n'
        fi
    fi

    # Always insert the paste -- Layer 0 handles blocking on Enter
    LBUFFER+="$pasted"
}

zle -N bracketed-paste pipeguard-bracketed-paste

# =============================================================================
# Layer 2: Hardened Shell Wrappers (Defense-in-Depth)
# =============================================================================
# Catches cases that bypass Layer 0:
#   - `command curl URL | bash` (explicit bypass of shell function)
#   - Commands built via eval, aliases, or scripts
#
# Limitation: fires on ALL piped curl/wget output (including curl | jq).
# Mitigated by smart content filtering -- benign content passes quickly.

function curl() {
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

function wget() {
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
# Logs all commands and flags pipe-to-shell patterns for forensic review.

autoload -Uz add-zsh-hook

function pipeguard-preexec() {
    _pipeguard_audit_command "$1"
}

add-zsh-hook preexec pipeguard-preexec

# =============================================================================
# Automatic Update Checking (zsh-specific background job syntax)
# =============================================================================

_pipeguard_check_updates() {
    if _pipeguard_should_check_update; then
        _pipeguard_run_update_check &!
    fi
}

_pipeguard_check_updates

# =============================================================================
# Verbose Loading Message
# =============================================================================

if [[ -n "$PIPEGUARD_VERBOSE" ]]; then
    printf '\033[0;32m[PipeGuard]\033[0m Loaded. Run '\''pipeguard-status'\'' for info.\n'
fi
