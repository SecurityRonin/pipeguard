# PipeGuard Shell Integration Loader
# This file is sourced by your shell RC file

# Ensure pipeguard is in PATH
export PATH="${HOME}/.local/bin:${PATH}"

# Set YARA library path (required on macOS)
if [[ -d "/opt/homebrew/opt/yara/lib" ]]; then
    export DYLD_LIBRARY_PATH="/opt/homebrew/opt/yara/lib:${DYLD_LIBRARY_PATH:-}"
elif [[ -d "/usr/local/opt/yara/lib" ]]; then
    export DYLD_LIBRARY_PATH="/usr/local/opt/yara/lib:${DYLD_LIBRARY_PATH:-}"
fi

# Load shell-specific integration
PIPEGUARD_SHARE="${HOME}/.local/share/pipeguard"

if [[ -n "${ZSH_VERSION:-}" ]]; then
    # Zsh integration
    if [[ -f "${PIPEGUARD_SHARE}/shell/pipeguard.zsh" ]]; then
        source "${PIPEGUARD_SHARE}/shell/pipeguard.zsh"
    fi
elif [[ -n "${BASH_VERSION:-}" ]]; then
    # Bash integration
    if [[ -f "${PIPEGUARD_SHARE}/shell/pipeguard.bash" ]]; then
        source "${PIPEGUARD_SHARE}/shell/pipeguard.bash"
    fi
fi
