# Matchy UI - Desktop Frontend for Matchy

A modern desktop application built with **Tauri** and **Leptos** for the [Matchy](https://github.com/sethhall/matchy) threat intelligence library.

## Features

### 🗄️ Database Management
- **Native file picker** for selecting `.mxy` database files
- **Real-time statistics** display:
  - File size and path
  - Match mode (case-sensitive/insensitive)
  - Query stats (total, matched, cache hit rate)
- Memory-mapped database loading for instant access
- Support for IP addresses, domains, patterns, and metadata

### 🔍 Single Query Interface
- Look up individual IPs, domains, or strings
- Automatic detection of query type
- Pretty-printed JSON metadata display
- Shows matching patterns and associated data

### 📋 Bulk Log Scanning
- Paste log files or text for batch processing
- SIMD-accelerated extraction of:
  - **Domains** (with TLD validation)
  - **IPv4 & IPv6 addresses**
  - **Email addresses**
- Line number tracking for matches
- Pattern type identification
- JSON metadata for each match

## Tech Stack

- **Backend**: Rust + Tauri 2.0
  - Direct integration with matchy library
  - Fast, native performance
  - Secure IPC between frontend/backend

- **Frontend**: Leptos 0.7 (CSR mode)
  - Reactive signals for state management
  - WebAssembly compiled UI
  - Clean, minimal interface

## Building

### Prerequisites
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add wasm target
rustup target add wasm32-unknown-unknown

# Install trunk (Leptos build tool)
cargo install trunk

# Install Tauri CLI
cargo install tauri-cli --version "^2.0.0"
```

### Development
```bash
cargo tauri dev
```

### Production Build
```bash
cargo tauri build
```

## Usage

1. **Open Database**: Enter the path to a `.mxy` file
2. **Query**: Enter an IP address, domain, or string to look up
3. **Scan**: Paste log lines to extract and match all patterns

## Example Workflow

```bash
# Create a sample threats database (using matchy CLI)
cat > threats.csv << EOF
entry,threat_level,category
1.2.3.4,high,malware
10.0.0.0/8,low,internal
*.evil.com,critical,phishing
malware.example.com,high,c2
EOF

matchy build threats.csv -o threats.mxy --format csv

# Then open threats.mxy in the UI
```

## License

BSD-2-Clause (same as matchy)
