#!/bin/bash
#
# PipeGuard Uninstaller
# Removes PipeGuard and cleans up shell configuration
#
# Usage: sudo /usr/local/share/pipeguard/uninstall.sh
#

set -e

echo ""
echo "PipeGuard Uninstaller"
echo "====================="
echo ""

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "This uninstaller must be run as root."
    echo "Usage: sudo $0"
    exit 1
fi

# Confirm
read -p "Are you sure you want to uninstall PipeGuard? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled."
    exit 0
fi

INSTALL_PREFIX="/usr/local"
MARKER="PipeGuard shell integration"

# Get real user
if [[ -n "$SUDO_USER" ]]; then
    REAL_USER="$SUDO_USER"
else
    REAL_USER=$(stat -f '%Su' /dev/console 2>/dev/null || echo "")
fi

if [[ -n "$REAL_USER" && "$REAL_USER" != "root" ]]; then
    REAL_HOME=$(eval echo "~$REAL_USER")
else
    REAL_HOME=""
fi

# Remove shell integration from RC files
remove_from_rc() {
    local rc_file="$1"

    if [[ -f "$rc_file" ]] && grep -qF "$MARKER" "$rc_file" 2>/dev/null; then
        echo "Removing shell integration from $rc_file..."
        # Create backup
        cp "$rc_file" "${rc_file}.pipeguard-uninstall-backup"
        # Remove PipeGuard lines (the marker and the source line)
        grep -vF "$MARKER" "$rc_file" | grep -v "pipeguard/shell/init.sh" > "${rc_file}.tmp"
        mv "${rc_file}.tmp" "$rc_file"
        chown "$REAL_USER" "$rc_file" 2>/dev/null || true
    fi
}

# Remove from shell RC files
if [[ -n "$REAL_HOME" ]]; then
    remove_from_rc "$REAL_HOME/.zshrc"
    remove_from_rc "$REAL_HOME/.bashrc"
    remove_from_rc "$REAL_HOME/.bash_profile"
fi

# Remove installed files
echo "Removing PipeGuard files..."

rm -f "$INSTALL_PREFIX/bin/pipeguard"
rm -rf "$INSTALL_PREFIX/share/pipeguard"

# Ask about user config
if [[ -n "$REAL_HOME" && -d "$REAL_HOME/.config/pipeguard" ]]; then
    read -p "Remove user configuration ($REAL_HOME/.config/pipeguard)? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$REAL_HOME/.config/pipeguard"
        echo "Configuration removed."
    else
        echo "Configuration preserved."
    fi
fi

# Forget the package receipt
pkgutil --forget com.securityronin.pipeguard 2>/dev/null || true

echo ""
echo "PipeGuard has been uninstalled."
echo ""
echo "Note: Restart your terminal for shell changes to take effect."
echo ""

exit 0
