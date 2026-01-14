# PipeGuard macOS Packaging
# Creates signed and notarized .pkg and .dmg installers
#
# Prerequisites:
#   - Apple Developer ID (Developer ID Installer + Developer ID Application certificates)
#   - Xcode Command Line Tools (xcode-select --install)
#   - create-dmg (brew install create-dmg)
#   - Notarytool credentials stored in keychain
#
# Setup credentials once:
#   make setup-credentials APPLE_ID=you@example.com TEAM_ID=XXXXXXXXXX
#
# Build installers:
#   make pkg          # Build signed .pkg
#   make dmg          # Build signed .dmg
#   make notarize     # Notarize and staple
#   make all          # Everything
#
# References:
#   - https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution
#   - https://scriptingosx.com/2021/07/notarize-a-command-line-tool-with-notarytool/
#   - https://github.com/create-dmg/create-dmg

# =============================================================================
# Configuration
# =============================================================================

# Version (read from Cargo.toml)
VERSION := $(shell grep '^version' ../Cargo.toml | head -1 | cut -d'"' -f2)

# Product info
PRODUCT_NAME := PipeGuard
BUNDLE_ID := com.securityronin.pipeguard
INSTALL_LOCATION := /usr/local

# Signing identities (find with: security find-identity -v)
# These should match your Apple Developer ID certificates
DEVELOPER_ID_APPLICATION ?= Developer ID Application: Your Company Name (XXXXXXXXXX)
DEVELOPER_ID_INSTALLER ?= Developer ID Installer: Your Company Name (XXXXXXXXXX)

# Notarization profile (created with: make setup-credentials)
NOTARY_PROFILE ?= pipeguard-notary

# Directories
ROOT_DIR := $(shell cd .. && pwd)
BUILD_DIR := $(ROOT_DIR)/target/release
PACKAGE_DIR := ./build
PAYLOAD_DIR := $(PACKAGE_DIR)/payload
SCRIPTS_DIR := ./scripts
RESOURCES_DIR := ./resources

# Output files
PKG_UNSIGNED := $(PACKAGE_DIR)/$(PRODUCT_NAME)-$(VERSION)-unsigned.pkg
PKG_SIGNED := $(PACKAGE_DIR)/$(PRODUCT_NAME)-$(VERSION).pkg
DMG_FILE := $(PACKAGE_DIR)/$(PRODUCT_NAME)-$(VERSION).dmg

# Binary
BINARY := $(BUILD_DIR)/pipeguard

# =============================================================================
# Main Targets
# =============================================================================

.PHONY: all clean pkg dmg notarize setup-credentials verify help

all: pkg dmg notarize
	@echo "==> All packages built and notarized!"
	@echo "    PKG: $(PKG_SIGNED)"
	@echo "    DMG: $(DMG_FILE)"

help:
	@echo "PipeGuard Packaging System"
	@echo ""
	@echo "Setup (one-time):"
	@echo "  make setup-credentials APPLE_ID=you@example.com TEAM_ID=XXXXXXXXXX"
	@echo ""
	@echo "Build targets:"
	@echo "  make pkg        - Build signed .pkg installer"
	@echo "  make dmg        - Build signed .dmg disk image"
	@echo "  make notarize   - Notarize and staple both pkg and dmg"
	@echo "  make all        - Build and notarize everything"
	@echo "  make verify     - Verify signatures and notarization"
	@echo "  make clean      - Remove build artifacts"
	@echo ""
	@echo "Configuration:"
	@echo "  VERSION=$(VERSION)"
	@echo "  DEVELOPER_ID_APPLICATION=$(DEVELOPER_ID_APPLICATION)"
	@echo "  DEVELOPER_ID_INSTALLER=$(DEVELOPER_ID_INSTALLER)"

clean:
	rm -rf $(PACKAGE_DIR)

# =============================================================================
# Build Binary
# =============================================================================

$(BINARY):
	@echo "==> Building release binary..."
	cd $(ROOT_DIR) && cargo build --release

# =============================================================================
# PKG Installer
# =============================================================================

pkg: $(PKG_SIGNED)

$(PKG_SIGNED): $(BINARY)
	@echo "==> Creating .pkg installer..."
	@mkdir -p $(PACKAGE_DIR) $(PAYLOAD_DIR)

	# Create payload directory structure
	@mkdir -p $(PAYLOAD_DIR)$(INSTALL_LOCATION)/bin
	@mkdir -p $(PAYLOAD_DIR)$(INSTALL_LOCATION)/share/pipeguard/rules
	@mkdir -p $(PAYLOAD_DIR)$(INSTALL_LOCATION)/share/pipeguard/shell

	# Copy files to payload
	@cp $(BINARY) $(PAYLOAD_DIR)$(INSTALL_LOCATION)/bin/
	@cp -r $(ROOT_DIR)/rules/* $(PAYLOAD_DIR)$(INSTALL_LOCATION)/share/pipeguard/rules/ 2>/dev/null || true
	@cp $(ROOT_DIR)/shell/*.zsh $(PAYLOAD_DIR)$(INSTALL_LOCATION)/share/pipeguard/shell/ 2>/dev/null || true
	@cp $(ROOT_DIR)/shell/*.bash $(PAYLOAD_DIR)$(INSTALL_LOCATION)/share/pipeguard/shell/ 2>/dev/null || true

	# Sign the binary with hardened runtime
	@echo "==> Signing binary..."
	codesign --force --sign "$(DEVELOPER_ID_APPLICATION)" \
		--options runtime \
		--timestamp \
		$(PAYLOAD_DIR)$(INSTALL_LOCATION)/bin/pipeguard

	# Verify binary signature
	codesign --verify --verbose $(PAYLOAD_DIR)$(INSTALL_LOCATION)/bin/pipeguard

	# Build component package
	@echo "==> Building component package..."
	pkgbuild \
		--root $(PAYLOAD_DIR) \
		--identifier $(BUNDLE_ID) \
		--version $(VERSION) \
		--install-location / \
		--scripts $(SCRIPTS_DIR) \
		$(PKG_UNSIGNED)

	# Sign the package
	@echo "==> Signing package..."
	productsign \
		--sign "$(DEVELOPER_ID_INSTALLER)" \
		--timestamp \
		$(PKG_UNSIGNED) \
		$(PKG_SIGNED)

	# Verify package signature
	pkgutil --check-signature $(PKG_SIGNED)

	# Clean up unsigned package
	@rm -f $(PKG_UNSIGNED)

	@echo "==> PKG created: $(PKG_SIGNED)"

# =============================================================================
# DMG Disk Image
# =============================================================================

dmg: $(DMG_FILE)

$(DMG_FILE): $(PKG_SIGNED)
	@echo "==> Creating .dmg disk image..."
	@mkdir -p $(PACKAGE_DIR)/dmg-contents

	# Copy pkg to dmg contents
	@cp $(PKG_SIGNED) $(PACKAGE_DIR)/dmg-contents/
	@cp $(RESOURCES_DIR)/README-DMG.txt $(PACKAGE_DIR)/dmg-contents/README.txt 2>/dev/null || \
		echo "Double-click the .pkg file to install PipeGuard" > $(PACKAGE_DIR)/dmg-contents/README.txt

	# Create DMG using create-dmg (install with: brew install create-dmg)
	@if command -v create-dmg >/dev/null 2>&1; then \
		create-dmg \
			--volname "$(PRODUCT_NAME) $(VERSION)" \
			--volicon "$(RESOURCES_DIR)/pipeguard.icns" \
			--background "$(RESOURCES_DIR)/dmg-background.png" \
			--window-pos 200 120 \
			--window-size 600 400 \
			--icon-size 100 \
			--icon "$(PRODUCT_NAME)-$(VERSION).pkg" 150 190 \
			--icon "README.txt" 450 190 \
			--hide-extension "$(PRODUCT_NAME)-$(VERSION).pkg" \
			--codesign "$(DEVELOPER_ID_APPLICATION)" \
			$(DMG_FILE) \
			$(PACKAGE_DIR)/dmg-contents/ 2>/dev/null || \
		create-dmg \
			--volname "$(PRODUCT_NAME) $(VERSION)" \
			--codesign "$(DEVELOPER_ID_APPLICATION)" \
			$(DMG_FILE) \
			$(PACKAGE_DIR)/dmg-contents/; \
	else \
		echo "==> create-dmg not found, using hdiutil..."; \
		hdiutil create -volname "$(PRODUCT_NAME) $(VERSION)" \
			-srcfolder $(PACKAGE_DIR)/dmg-contents \
			-ov -format UDZO \
			$(DMG_FILE); \
		codesign --force --sign "$(DEVELOPER_ID_APPLICATION)" \
			--timestamp \
			$(DMG_FILE); \
	fi

	# Verify DMG signature
	codesign --verify --verbose $(DMG_FILE)

	# Clean up
	@rm -rf $(PACKAGE_DIR)/dmg-contents

	@echo "==> DMG created: $(DMG_FILE)"

# =============================================================================
# Notarization
# =============================================================================

notarize: notarize-pkg notarize-dmg

notarize-pkg: $(PKG_SIGNED)
	@echo "==> Submitting PKG for notarization..."
	xcrun notarytool submit $(PKG_SIGNED) \
		--keychain-profile "$(NOTARY_PROFILE)" \
		--wait

	@echo "==> Stapling notarization ticket to PKG..."
	xcrun stapler staple $(PKG_SIGNED)

	@echo "==> PKG notarized and stapled!"

notarize-dmg: $(DMG_FILE)
	@echo "==> Submitting DMG for notarization..."
	xcrun notarytool submit $(DMG_FILE) \
		--keychain-profile "$(NOTARY_PROFILE)" \
		--wait

	@echo "==> Stapling notarization ticket to DMG..."
	xcrun stapler staple $(DMG_FILE)

	@echo "==> DMG notarized and stapled!"

# =============================================================================
# Verification
# =============================================================================

verify:
	@echo "==> Verifying PKG..."
	@pkgutil --check-signature $(PKG_SIGNED) || echo "PKG signature check failed"
	@xcrun stapler validate $(PKG_SIGNED) || echo "PKG staple validation failed"

	@echo ""
	@echo "==> Verifying DMG..."
	@codesign --verify --verbose $(DMG_FILE) || echo "DMG signature check failed"
	@xcrun stapler validate $(DMG_FILE) || echo "DMG staple validation failed"

	@echo ""
	@echo "==> Gatekeeper assessment..."
	@spctl --assess --type install $(PKG_SIGNED) && echo "PKG: Gatekeeper APPROVED" || echo "PKG: Gatekeeper REJECTED"
	@spctl --assess --type open --context context:primary-signature $(DMG_FILE) && echo "DMG: Gatekeeper APPROVED" || echo "DMG: Gatekeeper REJECTED"

# =============================================================================
# Setup
# =============================================================================

setup-credentials:
ifndef APPLE_ID
	$(error APPLE_ID is required. Usage: make setup-credentials APPLE_ID=you@example.com TEAM_ID=XXXXXXXXXX)
endif
ifndef TEAM_ID
	$(error TEAM_ID is required. Usage: make setup-credentials APPLE_ID=you@example.com TEAM_ID=XXXXXXXXXX)
endif
	@echo "==> Setting up notarization credentials..."
	@echo "You will be prompted for an app-specific password."
	@echo "Create one at: https://appleid.apple.com/account/manage -> App-Specific Passwords"
	@echo ""
	xcrun notarytool store-credentials "$(NOTARY_PROFILE)" \
		--apple-id "$(APPLE_ID)" \
		--team-id "$(TEAM_ID)"
	@echo ""
	@echo "==> Credentials stored in keychain as '$(NOTARY_PROFILE)'"

list-identities:
	@echo "==> Available signing identities:"
	@echo ""
	@echo "Application signing (for binaries and DMGs):"
	@security find-identity -v -p codesigning | grep "Developer ID Application" || echo "  (none found)"
	@echo ""
	@echo "Installer signing (for PKGs):"
	@security find-identity -v | grep "Developer ID Installer" || echo "  (none found)"
