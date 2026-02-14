# PipeGuard Fish Shell Integration
# Fish-native implementation of PipeGuard shell protection.
#
# Install: copy this file to ~/.config/fish/conf.d/pipeguard.fish
#   or source it from your ~/.config/fish/config.fish:
#     source ~/.local/share/pipeguard/shell/pipeguard.fish

# Prevent double-loading
if set -q PIPEGUARD_LOADED
    exit 0
end
set -gx PIPEGUARD_LOADED 1

# =============================================================================
# Configuration Defaults
# =============================================================================

if not set -q PIPEGUARD_ENABLED
    set -g PIPEGUARD_ENABLED 1
end

if not set -q PIPEGUARD_BIN
    set -gx PIPEGUARD_BIN "$HOME/.local/bin/pipeguard"
end

if not set -q PIPEGUARD_RULES
    set -gx PIPEGUARD_RULES "$HOME/.local/share/pipeguard/rules/core.yar"
end

if not set -q PIPEGUARD_CONFIG
    set -gx PIPEGUARD_CONFIG "$HOME/.config/pipeguard/config.toml"
end

if not set -q PIPEGUARD_AUDIT_LOG
    set -gx PIPEGUARD_AUDIT_LOG "$HOME/.local/share/pipeguard/audit.log"
end

if not set -q PIPEGUARD_UPDATE_CHECK_INTERVAL
    set -g PIPEGUARD_UPDATE_CHECK_INTERVAL 24
end

set -g PIPEGUARD_TIMESTAMP_FILE "$HOME/.pipeguard/.last_update_check"

# =============================================================================
# YARA Library Path (required on macOS)
# =============================================================================

if test -d /opt/homebrew/opt/yara/lib
    set -gx DYLD_LIBRARY_PATH "/opt/homebrew/opt/yara/lib:$DYLD_LIBRARY_PATH"
else if test -d /usr/local/opt/yara/lib
    set -gx DYLD_LIBRARY_PATH "/usr/local/opt/yara/lib:$DYLD_LIBRARY_PATH"
end

# Ensure pipeguard is in PATH
fish_add_path -g "$HOME/.local/bin"

# =============================================================================
# Binary and Rules Verification
# =============================================================================

if not test -x "$PIPEGUARD_BIN"
    if command -sq pipeguard
        set -gx PIPEGUARD_BIN (command -s pipeguard)
    else
        printf '\033[0;33m[PipeGuard] Warning: Binary not found at %s\033[0m\n' "$PIPEGUARD_BIN" >&2
        printf '\033[0;33m[PipeGuard] Run the installer again or check your PATH\033[0m\n' >&2
        exit 0
    end
end

if not test -f "$PIPEGUARD_RULES"
    printf '\033[0;33m[PipeGuard] Warning: Rules not found at %s\033[0m\n' "$PIPEGUARD_RULES" >&2
    printf '\033[0;33m[PipeGuard] Using built-in rules only\033[0m\n' >&2
    set -gx PIPEGUARD_RULES ""
end

# =============================================================================
# Core Scan Helper
# =============================================================================

function _pipeguard_scan --description "Run pipeguard scan with configured rules"
    if test -n "$PIPEGUARD_RULES"
        command "$PIPEGUARD_BIN" scan --rules "$PIPEGUARD_RULES" $argv
    else
        command "$PIPEGUARD_BIN" scan $argv
    end
end

# =============================================================================
# Pattern Detection
# =============================================================================

function _pipeguard_detect_pattern --description "Detect pipe-to-shell or download-then-execute patterns"
    set -l cmd "$argv"

    # Must contain a URL
    if not string match -rq 'https?://[^\s"\';&|]+' -- "$cmd"
        return 1
    end

    # Pipe-to-shell: url | sh, url | bash, etc.
    if string match -rq '\|\s*(ba|da|k|c|tc|z)?sh\b' -- "$cmd"
        or string match -rq '\|\s*bash\b' -- "$cmd"
        or string match -rq '\|\s*zsh\b' -- "$cmd"
        or string match -rq '\|\s*eval\b' -- "$cmd"
        or string match -rq '\|\s*source\b' -- "$cmd"
        printf '%s' "pipe-to-shell"
        return 0
    end

    # Download-then-execute: url && sh file, url; chmod +x, url && ./file
    if string match -rq '[;&]+\s*(ba|da|k|c|tc|z)?sh\b' -- "$cmd"
        or string match -rq '[;&]+\s*bash\b' -- "$cmd"
        or string match -rq '[;&]+\s*zsh\b' -- "$cmd"
        or string match -rq '[;&]+\s*chmod\s+\+x' -- "$cmd"
        or string match -rq '[;&]+\s*\./' -- "$cmd"
        printf '%s' "download-then-execute"
        return 0
    end

    return 1
end

# =============================================================================
# Content Filter
# =============================================================================

function _pipeguard_should_scan --description "Determine if content should be scanned"
    set -l content "$argv[1]"
    set -l header (printf '%s' "$content" | head -c 512)

    # Binary signatures -- skip
    if string match -q '\x89PNG*' -- "$header"
        or string match -q '\xff\xd8\xff*' -- "$header"
        or string match -q 'PK*' -- "$header"
        or string match -q '\x1f\x8b*' -- "$header"
        or string match -q '\x7fELF*' -- "$header"
        or string match -q '\xfe\xed\xfa*' -- "$header"
        or string match -q '%PDF*' -- "$header"
        return 1
    end

    # Default: scan for safety
    return 0
end

# =============================================================================
# Fetch and Scan
# =============================================================================

function _pipeguard_fetch_and_scan --description "Fetch URL content and scan it"
    set -l url "$argv[1]"

    printf '\033[0;90mScanning remote content from: %s\033[0m\n' "$url"

    set -g _pg_fetch_content (command curl -sSL --max-time 30 "$url" 2>/dev/null)
    set -l fetch_exit $status

    if test $fetch_exit -ne 0
        printf '\033[1;31m✗ Failed to fetch URL (exit %d)\033[0m\n' $fetch_exit
        return 1
    end

    set -g _pg_scan_result (printf '%s' "$_pg_fetch_content" | _pipeguard_scan --format text 2>&1)
    set -g _pg_scan_exit $status

    if test $_pg_scan_exit -eq 0
        printf '\033[1;32m✓ Content scanned — no threats detected\033[0m\n'
    else
        printf '\033[1;31m%s\033[0m\n' "$_pg_scan_result"
        printf '\n'
    end

    return 0
end

# =============================================================================
# Audit Logging
# =============================================================================

function _pipeguard_audit_log --description "Write an entry to the audit log"
    set -l cmd "$argv[1]"
    set -l level "$argv[2]"

    if test -n "$PIPEGUARD_AUDIT_LOG"
        set -l ts (date -u +%Y-%m-%dT%H:%M:%SZ)
        if test -n "$level"
            printf '%s\t%s\t%s\t%s\n' "$ts" $fish_pid "$level" "$cmd" >>"$PIPEGUARD_AUDIT_LOG"
        else
            printf '%s\t%s\t%s\n' "$ts" $fish_pid "$cmd" >>"$PIPEGUARD_AUDIT_LOG"
        end
    end
end

function _pipeguard_audit_command --description "Audit a command and flag dangerous patterns"
    set -l cmd "$argv[1]"

    if test -n "$PIPEGUARD_AUDIT_LOG"
        set -l ts (date -u +%Y-%m-%dT%H:%M:%SZ)
        printf '%s\t%s\t%s\n' "$ts" $fish_pid "$cmd" >>"$PIPEGUARD_AUDIT_LOG"

        set -l pattern (_pipeguard_detect_pattern "$cmd")
        if test -n "$pattern"
            printf '%s\t%s\tWARN: %s pattern detected\n' \
                (date -u +%Y-%m-%dT%H:%M:%SZ) $fish_pid "$pattern" >>"$PIPEGUARD_AUDIT_LOG"
        end
    end
end

# =============================================================================
# Layer 0: Fish Event-Based Command Interception (PRIMARY DEFENSE)
# =============================================================================
# Fish doesn't have DEBUG traps or accept-line widgets. Instead we use
# the fish_preexec event, which fires before every command line execution.

function _pipeguard_preexec --on-event fish_preexec --description "PipeGuard preexec hook"
    set -l cmd "$argv[1]"

    # Audit the command
    _pipeguard_audit_command "$cmd"

    # Skip if disabled
    if test "$PIPEGUARD_ENABLED" -ne 1
        return 0
    end

    set -l pattern (_pipeguard_detect_pattern "$cmd")

    if test -n "$pattern"
        echo ""
        printf '\033[1;33m⚠ PipeGuard: Detected %s pattern\033[0m\n' "$pattern"
        printf '\033[0;36m  Command: %s\033[0m\n' "$cmd"
        echo ""

        # Extract the first URL from the command
        set -l url (printf '%s' "$cmd" | string match -r 'https?://[^ |"\';&]+' | head -1)

        if test -n "$url"
            if not _pipeguard_fetch_and_scan "$url"
                read -l -n 1 -P "Press 'y' to run anyway, any other key to abort: " confirm
                if not string match -qi 'y' -- "$confirm"
                    printf '\033[1;32m✓ Command aborted by PipeGuard\033[0m\n'
                    commandline -r ""
                    return 1
                end
                return 0
            end

            if test "$_pg_scan_exit" -ne 0
                read -l -n 1 -P (printf '\033[1;33mThreats detected. Press y to run anyway, any other key to abort: \033[0m') confirm
                if not string match -qi 'y' -- "$confirm"
                    printf '\033[1;32m✓ Command blocked by PipeGuard\033[0m\n'
                    _pipeguard_audit_log "$cmd" "BLOCK"
                    commandline -r ""
                    return 1
                end
            end
        end
    end

    return 0
end

# =============================================================================
# Layer 2: Hardened Shell Wrappers (Defense-in-Depth)
# =============================================================================
# Catches cases that bypass Layer 0:
#   - `command curl URL | bash`
#   - Commands built via eval

function curl --description "PipeGuard-wrapped curl" --wraps curl
    if not isatty stdout; and test "$PIPEGUARD_ENABLED" -eq 1
        set -l output (command curl $argv)
        set -l curl_exit $status

        if test $curl_exit -ne 0
            return $curl_exit
        end

        if _pipeguard_should_scan "$output"
            set -l result (printf '%s' "$output" | _pipeguard_scan 2>&1)
            set -l pg_exit $status

            if test $pg_exit -ne 0
                printf '\033[1;31m⚠ PipeGuard blocked piped content:\033[0m\n' >&2
                echo "$result" >&2
                return 1
            end
        end

        printf '%s' "$output"
    else
        command curl $argv
    end
end

function wget --description "PipeGuard-wrapped wget" --wraps wget
    if not isatty stdout; and test "$PIPEGUARD_ENABLED" -eq 1
        set -l output (command wget -qO- $argv)
        set -l wget_exit $status

        if test $wget_exit -ne 0
            return $wget_exit
        end

        if _pipeguard_should_scan "$output"
            set -l result (printf '%s' "$output" | _pipeguard_scan 2>&1)
            set -l pg_exit $status

            if test $pg_exit -ne 0
                printf '\033[1;31m⚠ PipeGuard blocked piped content:\033[0m\n' >&2
                echo "$result" >&2
                return 1
            end
        end

        printf '%s' "$output"
    else
        command wget $argv
    end
end

# =============================================================================
# Helper Functions
# =============================================================================

function pipeguard-disable --description "Disable PipeGuard for this session"
    set -g PIPEGUARD_ENABLED 0
    printf '%s\n' "PipeGuard disabled for this session"
end

function pipeguard-enable --description "Enable PipeGuard"
    set -g PIPEGUARD_ENABLED 1
    printf '%s\n' "PipeGuard enabled"
end

function pipeguard-status --description "Show PipeGuard status"
    if test "$PIPEGUARD_ENABLED" -eq 1
        printf 'PipeGuard: \033[1;32mEnabled\033[0m\n'
    else
        printf 'PipeGuard: \033[1;31mDisabled\033[0m\n'
    end
    printf 'Binary: %s\n' "$PIPEGUARD_BIN"
    if test -n "$PIPEGUARD_RULES"
        printf 'Rules: %s\n' "$PIPEGUARD_RULES"
    else
        printf 'Rules: <built-in>\n'
    end
    if test -n "$PIPEGUARD_AUDIT_LOG"
        printf 'Audit: %s\n' "$PIPEGUARD_AUDIT_LOG"
    else
        printf 'Audit: <disabled>\n'
    end
end

function pipeguard-scan --description "Run a PipeGuard scan"
    _pipeguard_scan $argv
end

# =============================================================================
# Automatic Update Checking
# =============================================================================

function _pipeguard_should_check_update --description "Check if an update check is due"
    set -l current_time (date +%s)
    set -l interval_seconds (math "$PIPEGUARD_UPDATE_CHECK_INTERVAL * 3600")

    if not test -f "$PIPEGUARD_TIMESTAMP_FILE"
        mkdir -p (dirname "$PIPEGUARD_TIMESTAMP_FILE")
        printf '%s' "0" >"$PIPEGUARD_TIMESTAMP_FILE"
        return 0
    end

    set -l last_check (cat "$PIPEGUARD_TIMESTAMP_FILE" 2>/dev/null; or printf '%s' "0")
    test (math "$current_time - $last_check") -ge $interval_seconds
end

function _pipeguard_run_update_check --description "Run the update check"
    if command "$PIPEGUARD_BIN" update check --quiet 2>/dev/null
        : # up to date
    else if test $status -eq 1
        printf '\033[33m⚠️  PipeGuard update available.\033[0m Run: pipeguard update apply\n' >&2
    end
    mkdir -p (dirname "$PIPEGUARD_TIMESTAMP_FILE")
    printf '%s' (date +%s) >"$PIPEGUARD_TIMESTAMP_FILE"
end

if _pipeguard_should_check_update
    _pipeguard_run_update_check &
    disown
end

# =============================================================================
# Verbose Loading Message
# =============================================================================

if set -q PIPEGUARD_VERBOSE
    printf '\033[0;32m[PipeGuard]\033[0m Loaded (Fish). Run \'pipeguard-status\' for info.\n'
end
