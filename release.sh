#!/bin/bash
set -e

VERSION="${1:-$(grep '^version' src-tauri/Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')}"
TAG="v${VERSION}"

echo "Building Matchy v${VERSION}..."
cargo tauri build

DMG_PATH=$(find target/release/bundle/dmg -name "*.dmg" | head -1)

if [ ! -f "$DMG_PATH" ]; then
    echo "Error: DMG not found at $DMG_PATH"
    exit 1
fi

echo "Found DMG: $DMG_PATH"

# Check if tag exists
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "Tag $TAG already exists"
else
    echo "Creating tag $TAG..."
    git tag -a "$TAG" -m "Release $TAG"
    git push origin "$TAG"
fi

# Create or update release
echo "Uploading to GitHub release $TAG..."
gh release create "$TAG" "$DMG_PATH" --title "Matchy $TAG" --notes "Release $TAG" 2>/dev/null || \
gh release upload "$TAG" "$DMG_PATH" --clobber

echo "✅ Released: $(basename $DMG_PATH)"
echo "View at: $(gh release view $TAG --json url -q .url)"
