# Changelog

## [Unreleased] - 2025-10-25

### Current State

Matchy Monitor is a **Tauri 2.0 + Leptos 0.7** desktop application providing real-time threat intelligence monitoring with the [matchy](https://crates.io/crates/matchy) library.

**Core Features:**
- Multi-database management with automatic file reload on changes
- Real-time system log monitoring with native notifications
- Live network packet capture via Zeek integration
- Flexible monitor system (SystemLogs, LogFile tailing, ZeekPacketCapture)
- System tray with background monitoring
- SIMD-accelerated IoC extraction (IPs, domains, emails, hashes, crypto addresses)

**Architecture:**
- Frontend: Leptos CSR (WebAssembly) with reactive signals
- Backend: Rust native with Tauri IPC bridge
- Monitor system: Dedicated threads per monitor using matchy's Worker API
- Database state: Arc<Mutex<HashMap>> for thread-safe concurrent access

**Platform Support:**
- macOS: Full support with osascript privilege escalation for Zeek
- Linux: Planned (pkexec/sudo for Zeek)
- Windows: Planned (UAC elevation for Zeek)

### Major Features

#### Database Management
- Load multiple `.mxy` databases simultaneously
- Native file picker dialog with `.mxy` filtering
- Real-time statistics (file size, match mode, query stats, cache hit rate)
- Automatic database reload when files change on disk
- File watcher using `notify` crate with debouncing

#### Monitor System
- **SystemLogs**: macOS `log stream` monitoring (legacy)
- **LogFile**: Tail any log file with rotation detection
- **ZeekPacketCapture**: Live network packet analysis
  - Requires system-installed Zeek (`brew install zeek`)
  - Automatic privilege escalation on macOS
  - Tails Zeek's conn.log for IP/domain extraction
  - Cleanup on exit with temporary log directories
- Start/stop monitoring from UI
- Per-monitor statistics tracking

#### IoC Extraction & Matching
- SIMD-accelerated pattern extraction via matchy's `Extractor`
- Batch processing with `Worker` API for efficiency
- Extracts: IPv4, IPv6, domains, emails, MD5/SHA1/SHA256, crypto addresses
- Queries all loaded databases for matches
- Real-time hit display with metadata

#### Notifications
- Native system notifications via `tauri-plugin-notification`
- Triggered on threat matches during monitoring
- Shows matched pattern and source

#### System Tray
- Background monitoring when window hidden
- Tray menu: Show/Hide window, Quit
- Window close button hides instead of exits

### Dependencies
- `matchy = "1.1.0"` - Core threat intelligence library
- `tauri = "2"` - Desktop app framework
- `leptos = "0.7"` - Frontend reactive framework
- `tauri-plugin-dialog = "2"` - Native file dialogs
- `tauri-plugin-notification = "2"` - System notifications
- `tauri-plugin-shell = "2"` - Shell command execution
- `notify = "6"` - Filesystem watching
- `tokio = "1"` - Async runtime
- `uuid = "1"` - Unique identifiers
- `chrono = "0.4"` - Timestamp handling
