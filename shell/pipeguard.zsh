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
PIPEGUARD_AUDIT_LOG=${PIPEGUARD_AUDIT_LOG:-"${HOME}/.local/share/pipeguard/audit.log"}

# Verify pipeguard binary exists
if [[ ! -x "$PIPEGUARD_BIN" ]]; then
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

# Helper to run pipeguard scan with or without custom rules
_pipeguard_scan() {
    if [[ -n "$PIPEGUARD_RULES" ]]; then
        "$PIPEGUARD_BIN" scan --rules "$PIPEGUARD_RULES" "$@"
    else
        "$PIPEGUARD_BIN" scan "$@"
    fi
}

# Pattern matching dangerous pipe targets (shells and eval-like commands)
_PIPEGUARD_SHELL_TARGETS='(ba|da|k|c|tc|z)?sh|bash|zsh|eval|source|\.'

# =============================================================================
# Layer 0: Accept-Line Interception (PRIMARY DEFENSE)
# =============================================================================
# Intercepts the full command line when the user presses Enter.
# This is the most reliable layer because it sees both sides of the pipe,
# solving the fundamental problem that Unix pipes are anonymous — the
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

    # Detect pipe-to-shell: curl/wget/fetch piped to a shell interpreter
    if [[ "$cmd" =~ '(curl|wget|fetch)[[:space:]]+.*\|[[:space:]]*('"$_PIPEGUARD_SHELL_TARGETS"')' ]]; then
        echo ""
        echo "\033[1;33m⚠ PipeGuard: Detected pipe-to-shell pattern\033[0m"
        echo "\033[0;36m  Command: $cmd\033[0m"
        echo ""

        # Extract URL from the command (first http/https URL found)
        local url
        url=$(printf '%s' "$cmd" | grep -oE 'https?://[^ |"'"'"']+' | head -1)

        if [[ -n "$url" ]]; then
            echo "\033[0;90mScanning remote content from: $url\033[0m"

            # Pre-fetch the content
            local content
            content=$(command curl -sSL --max-time 30 "$url" 2>/dev/null)
            local fetch_exit=$?

            if (( fetch_exit != 0 )); then
                echo "\033[1;31m✗ Failed to fetch URL (exit $fetch_exit)\033[0m"
                echo "Press 'y' to run original command anyway, any other key to abort: \c"
                read -k1 confirm
                echo ""
                if [[ "$confirm" != [yY] ]]; then
                    echo "\033[1;32m✓ Command aborted by PipeGuard\033[0m"
                    BUFFER=""
                    zle redisplay
                    return 0
                fi
                zle .accept-line
                return
            fi

            # Scan the pre-fetched content
            local scan_result
            scan_result=$(printf '%s' "$content" | _pipeguard_scan --format text 2>&1)
            local scan_exit=$?

            if (( scan_exit != 0 )); then
                # Threats detected
                echo "\033[1;31m$scan_result\033[0m"
                echo ""
                echo "\033[1;33mThreats detected. Press 'y' to run anyway, any other key to abort: \033[0m\c"
                read -k1 confirm
                echo ""

                if [[ "$confirm" != [yY] ]]; then
                    echo "\033[1;32m✓ Command blocked by PipeGuard\033[0m"
                    # Audit log the block
                    if [[ -n "$PIPEGUARD_AUDIT_LOG" ]]; then
                        printf '%s\t%s\tBLOCK\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$cmd" >> "$PIPEGUARD_AUDIT_LOG"
                    fi
                    BUFFER=""
                    zle redisplay
                    return 0
                fi
            else
                echo "\033[1;32m✓ Content scanned — no threats detected\033[0m"
            fi

            # TOCTOU-safe: pipe the already-scanned content to the shell
            # instead of re-fetching from the URL
            local shell_cmd
            shell_cmd=$(printf '%s' "$cmd" | sed -E 's/(curl|wget|fetch)[[:space:]]+[^|]+\|//')
            BUFFER="printf '%s' ${(q)content} | $shell_cmd"
        fi
    fi

    zle .accept-line
}

zle -N accept-line pipeguard-accept-line

# =============================================================================
# Layer 1: ZLE Paste Interception
# =============================================================================
# Early warning when user pastes content containing pipe-to-shell patterns.
# Triggers before the user even presses Enter — immediate visual feedback.

if [[ -z "$_pipeguard_original_paste" ]]; then
    zle -la bracketed-paste && _pipeguard_original_paste=bracketed-paste
fi

function pipeguard-bracketed-paste() {
    local pasted
    zle .bracketed-paste pasted

    if [[ "$pasted" =~ '(curl|wget|fetch).*\|.*('"$_PIPEGUARD_SHELL_TARGETS"')' ]]; then
        if (( PIPEGUARD_ENABLED )); then
            echo ""
            echo "\033[1;33m⚠ PipeGuard: Pipe-to-shell pattern detected in paste\033[0m"
            echo "\033[0;90m  Tip: Press Enter to trigger full scan, or Ctrl-C to abort\033[0m"
        fi
    fi

    # Always insert the paste — Layer 0 handles blocking on Enter
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
# Mitigated by smart content filtering — benign content passes quickly.

# Content-based smart filter: skip scanning obvious non-scripts
_pipeguard_should_scan() {
    local content="$1"
    local header
    header=$(printf '%s' "$content" | head -c 512)

    # Binary signatures — skip
    if [[ "$header" =~ $'^\x89PNG' ]] || \
       [[ "$header" =~ $'^\xff\xd8\xff' ]] || \
       [[ "$header" =~ ^'PK' ]] || \
       [[ "$header" =~ $'^\x1f\x8b' ]] || \
       [[ "$header" =~ $'^\x7fELF' ]] || \
       [[ "$header" =~ $'^\xfe\xed\xfa' ]] || \
       [[ "$header" =~ ^'%PDF' ]]; then
        return 1  # SKIP — binary
    fi

    # Shebang or shell keywords — scan
    if [[ "$header" =~ ^'#!' ]] || \
       [[ "$header" =~ (bash|/bin/sh|eval|export|chmod) ]] || \
       [[ "$header" =~ (curl.*\||wget.*\||/dev/tcp|base64) ]]; then
        return 0  # SCAN
    fi

    # Default: scan for safety
    return 0
}

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
                echo "\033[1;31m⚠ PipeGuard blocked piped content:\033[0m" >&2
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
                echo "\033[1;31m⚠ PipeGuard blocked piped content:\033[0m" >&2
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
# Enabled by default via PIPEGUARD_AUDIT_LOG.

autoload -Uz add-zsh-hook

function pipeguard-preexec() {
    local cmd="$1"

    if [[ -n "$PIPEGUARD_AUDIT_LOG" ]]; then
        printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$cmd" >> "$PIPEGUARD_AUDIT_LOG"

        if [[ "$cmd" =~ '(curl|wget|fetch).*\|.*('"$_PIPEGUARD_SHELL_TARGETS"')' ]]; then
            printf '%s\t%s\tWARN: pipe-to-shell pattern detected\n' \
                "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" >> "$PIPEGUARD_AUDIT_LOG"
        fi
    fi
}

add-zsh-hook preexec pipeguard-preexec

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
        mkdir -p "${PIPEGUARD_TIMESTAMP_FILE:h}"
        echo "0" > "$PIPEGUARD_TIMESTAMP_FILE"
        return 0
    fi

    last_check=$(cat "$PIPEGUARD_TIMESTAMP_FILE" 2>/dev/null || echo "0")
    (( current_time - last_check >= interval_seconds ))
}

_pipeguard_check_updates() {
    if _pipeguard_should_check_update; then
        {
            if pipeguard update check --quiet 2>/dev/null; then
                :
            elif [[ $? -eq 1 ]]; then
                print -P "%F{yellow}⚠️  PipeGuard update available.%f Run: pipeguard update apply" >&2
            fi
            mkdir -p "${PIPEGUARD_TIMESTAMP_FILE:h}"
            echo "$(date +%s)" > "$PIPEGUARD_TIMESTAMP_FILE"
        } &!
    fi
}

_pipeguard_check_updates

# =============================================================================
# Helper Functions
# =============================================================================

function pipeguard-disable() {
    PIPEGUARD_ENABLED=0
    echo "PipeGuard disabled for this session"
}

function pipeguard-enable() {
    PIPEGUARD_ENABLED=1
    echo "PipeGuard enabled"
}

function pipeguard-status() {
    if (( PIPEGUARD_ENABLED )); then
        echo "PipeGuard: \033[1;32mEnabled\033[0m"
    else
        echo "PipeGuard: \033[1;31mDisabled\033[0m"
    fi
    echo "Binary: $PIPEGUARD_BIN"
    echo "Rules: ${PIPEGUARD_RULES:-<built-in>}"
    echo "Audit: ${PIPEGUARD_AUDIT_LOG:-<disabled>}"
}

function pipeguard-scan() {
    _pipeguard_scan "$@"
}

if [[ -n "$PIPEGUARD_VERBOSE" ]]; then
    echo "\033[0;32m[PipeGuard]\033[0m Loaded. Run 'pipeguard-status' for info."
fi
