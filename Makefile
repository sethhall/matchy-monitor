.PHONY: help dev dev-es build-debug build-release run-debug run-debug-sudo clean

# Default target
help:
	@echo "Matchy App - Development Targets"
	@echo ""
	@echo "  make dev          - Run frontend dev server only (no ES support)"
	@echo "  make dev-es       - Build, sign, and run app with EndpointSecurity (requires sudo)"
	@echo "  make build-debug  - Build debug app bundle with code signing"
	@echo "  make build-release- Build release app bundle"
	@echo "  make run-debug    - Run signed debug app bundle"
	@echo "  make run-sudo     - Run signed debug app bundle with sudo (for ES)"
	@echo "  make clean        - Clean build artifacts"
	@echo ""

# Frontend dev only (no Tauri backend)
dev:
	trunk serve

# Full dev workflow with EndpointSecurity support
dev-es: build-debug
	@echo ""
	@echo "🚀 Launching app with sudo for EndpointSecurity support..."
	@echo "   You'll be prompted for your password."
	@echo ""
	sudo open -a "$$(pwd)/target/debug/bundle/macos/Matchy.app"

# Build debug bundle with proper signing
build-debug:
	@echo "🔨 Building debug bundle with code signing..."
	cargo tauri build --debug --bundles app
	@echo "✅ Build complete: target/debug/bundle/macos/Matchy.app"

# Build release bundle
build-release:
	@echo "🔨 Building release bundle..."
	cargo tauri build
	@echo "✅ Build complete: target/release/bundle/macos/Matchy.app"

# Run debug app (normal mode, ES will fail without sudo)
run-debug:
	@if [ ! -d "target/debug/bundle/macos/Matchy.app" ]; then \
		echo "❌ Debug app not found. Run 'make build-debug' first."; \
		exit 1; \
	fi
	@echo "🚀 Launching debug app..."
	open -a target/debug/bundle/macos/Matchy.app

# Run debug app with sudo (for EndpointSecurity)
run-sudo:
	@if [ ! -d "target/debug/bundle/macos/Matchy.app" ]; then \
		echo "❌ Debug app not found. Run 'make build-debug' first."; \
		exit 1; \
	fi
	@echo "🚀 Launching debug app with sudo..."
	sudo open -a "$$(pwd)/target/debug/bundle/macos/Matchy.app"

# Clean build artifacts
clean:
	cargo clean
	rm -rf dist/
	@echo "✨ Clean complete"
