#!/bin/bash
# Sign the development binary

set -e

BINARY_PATH="${1:-../target/debug/matchy-app}"

echo "Signing binary: $BINARY_PATH"

# Sign with ad-hoc signature (- means use ad-hoc identity)
codesign --force --sign - \
    --deep \
    "$BINARY_PATH"

echo "✅ Binary signed successfully!"
echo ""
echo "To run the app, use: cargo tauri dev"
echo "Or manually: $BINARY_PATH"
