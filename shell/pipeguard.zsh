#!/bin/zsh
# PipeGuard zsh integration
# Source this file from ~/.zshrc

# Check if pipeguard is installed
if ! (( $+commands[pipeguard] )); then
    return
fi

# Check interval configuration (hours)
PIPEGUARD_UPDATE_CHECK_INTERVAL="${PIPEGUARD_UPDATE_CHECK_INTERVAL:-24}"

# Timestamp file location
PIPEGUARD_TIMESTAMP_FILE="${HOME}/.pipeguard/.last_update_check"

# Function to check if enough time has passed
_pipeguard_should_check() {
    local current_time
    local last_check
    local interval_seconds

    current_time=$(date +%s)
    interval_seconds=$((PIPEGUARD_UPDATE_CHECK_INTERVAL * 3600))

    # Create timestamp file if it doesn't exist
    if [[ ! -f "$PIPEGUARD_TIMESTAMP_FILE" ]]; then
        mkdir -p "${PIPEGUARD_TIMESTAMP_FILE:h}"
        echo "0" > "$PIPEGUARD_TIMESTAMP_FILE"
        return 0
    fi

    last_check=$(cat "$PIPEGUARD_TIMESTAMP_FILE" 2>/dev/null || echo "0")

    # Check if interval has passed
    if (( current_time - last_check >= interval_seconds )); then
        return 0
    else
        return 1
    fi
}

# Function to update timestamp
_pipeguard_update_timestamp() {
    local current_time
    current_time=$(date +%s)
    mkdir -p "${PIPEGUARD_TIMESTAMP_FILE:h}"
    echo "$current_time" > "$PIPEGUARD_TIMESTAMP_FILE"
}

# Check for updates on shell start (non-blocking)
_pipeguard_check_updates() {
    if _pipeguard_should_check; then
        # Run check in background to avoid blocking shell startup
        {
            if pipeguard update check --quiet 2>/dev/null; then
                # No update available (exit code 0)
                :
            elif [[ $? -eq 1 ]]; then
                # Update available (exit code 1)
                print -P "%F{yellow}⚠️  PipeGuard update available.%f Run: pipeguard update apply" >&2
            fi

            # Update timestamp after check
            _pipeguard_update_timestamp
        } &!
    fi
}

# Run check (won't block if in background)
_pipeguard_check_updates
