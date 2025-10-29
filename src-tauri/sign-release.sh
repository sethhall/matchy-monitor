#!/bin/bash
# Sign and notarize macOS release builds
# 
# Prerequisites:
# 1. Valid Apple Developer ID certificate installed in Keychain
# 2. App-specific password stored in Keychain (for notarization)
#
# Setup:
#   # Find your signing identity:
#   security find-identity -v -p codesigning
#
#   # Store notarization credentials:
#   xcrun notarytool store-credentials "notarytool-profile" \
#     --apple-id "your-email@example.com" \
#     --team-id "YOUR_TEAM_ID" \
#     --password "app-specific-password"

set -e

# Configuration - edit these or pass as environment variables
SIGNING_IDENTITY="${APPLE_SIGNING_IDENTITY:-}"
NOTARYTOOL_PROFILE="${NOTARYTOOL_PROFILE:-notarytool-profile}"
BUNDLE_PATH="${1:-../target/release/bundle/macos/Matchy.app}"
DMG_PATH="${2:-../target/release/bundle/dmg/Matchy_0.1.0_aarch64.dmg}"

echo "🔐 Matchy Release Signing & Notarization"
echo "=========================================="
echo ""

# Check for signing identity
if [ -z "$SIGNING_IDENTITY" ]; then
    echo "❌ Error: APPLE_SIGNING_IDENTITY not set"
    echo ""
    echo "Find your signing identity with:"
    echo "  security find-identity -v -p codesigning"
    echo ""
    echo "Then set it with:"
    echo "  export APPLE_SIGNING_IDENTITY='Developer ID Application: Your Name (TEAM_ID)'"
    exit 1
fi

echo "Signing identity: $SIGNING_IDENTITY"
echo ""

# Step 1: Sign the .app bundle
if [ -d "$BUNDLE_PATH" ]; then
    echo "📝 Signing .app bundle..."
    codesign --force --sign "$SIGNING_IDENTITY" \
        --options runtime \
        --deep \
        --timestamp \
        "$BUNDLE_PATH"
    
    echo "✅ App bundle signed"
    
    # Verify signature
    echo "🔍 Verifying signature..."
    codesign --verify --verbose "$BUNDLE_PATH"
    echo ""
else
    echo "⚠️  Warning: App bundle not found at $BUNDLE_PATH"
    echo "Run 'cargo tauri build' first"
    exit 1
fi

# Step 2: Sign the DMG (if it exists)
if [ -f "$DMG_PATH" ]; then
    echo "📝 Signing DMG..."
    codesign --force --sign "$SIGNING_IDENTITY" \
        --timestamp \
        "$DMG_PATH"
    
    echo "✅ DMG signed"
    echo ""
    
    # Step 3: Notarize the DMG
    echo "📤 Submitting DMG for notarization..."
    echo "(This may take several minutes)"
    xcrun notarytool submit "$DMG_PATH" \
        --keychain-profile "$NOTARYTOOL_PROFILE" \
        --wait
    
    # Step 4: Staple the notarization ticket
    echo "📎 Stapling notarization ticket..."
    xcrun stapler staple "$DMG_PATH"
    
    echo ""
    echo "✅ DMG notarized and stapled!"
    echo ""
    echo "DMG ready for distribution: $DMG_PATH"
else
    echo "⚠️  Warning: DMG not found at $DMG_PATH"
    echo "Only the .app bundle was signed"
fi

echo ""
echo "🎉 Signing complete!"
