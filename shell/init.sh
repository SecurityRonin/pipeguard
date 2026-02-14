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

# Load shell integration (shell-specific scripts source pipeguard-common.sh)
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
elif [[ -n "${FISH_VERSION:-}" ]]; then
    # Fish shell integration
    # NOTE: Fish cannot source POSIX scripts. This branch only works if Fish
    # evaluates init.sh via `bass` or similar POSIX-compat wrapper.
    # Preferred setup for Fish users:
    #   cp ~/.local/share/pipeguard/shell/pipeguard.fish ~/.config/fish/conf.d/
    # or add to ~/.config/fish/config.fish:
    #   source ~/.local/share/pipeguard/shell/pipeguard.fish
    if [[ -f "${PIPEGUARD_SHARE}/shell/pipeguard.fish" ]]; then
        source "${PIPEGUARD_SHARE}/shell/pipeguard.fish"
    fi
fi
