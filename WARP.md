# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

Matchy UI is a desktop threat intelligence application built with **Tauri 2.0** and **Leptos 0.7** (CSR mode). It provides a frontend for the [matchy](https://github.com/sethhall/matchy) threat intelligence library, enabling real-time log monitoring, threat database management, and intelligence lookups.

## Development Commands

### Building and Running

```bash
# Development mode with hot reload
cargo tauri dev

# Production build
cargo tauri build

# Build frontend only (WebAssembly)
trunk build

# Serve frontend standalone (for testing without Tauri)
trunk serve
```

### Prerequisites Setup

```bash
# Add WebAssembly target (required for Leptos)
rustup target add wasm32-unknown-unknown

# Install build tools
cargo install trunk
cargo install tauri-cli --version "^2.0.0"
```

### Testing

Currently no automated tests exist in this codebase.

## Architecture

### Frontend-Backend Split

This is a **workspace project** with two distinct compilation targets:

1. **Frontend** (`src/`): Leptos application compiled to WebAssembly
   - Uses Leptos CSR (Client-Side Rendering) mode
   - Built with `trunk` (configured in `Trunk.toml`)
   - Communicates with backend via Tauri's IPC bridge

2. **Backend** (`src-tauri/`): Rust Tauri application
   - Native Rust with direct access to the `matchy` library
   - Provides Tauri commands for database operations
   - Spawns background thread for system log monitoring

### State Management

The backend uses **Tauri managed state** with `Arc<Mutex<_>>` for shared state across threads:

- `databases`: HashMap of loaded `.mxy` database files
- `monitoring_enabled`: Boolean flag for log monitoring
- `monitor_stats`: Running statistics (lines processed, items extracted)

### Event Flow

```
Frontend (Leptos/WASM) 
    ↕️ [Tauri IPC via wasm_bindgen]
Backend (Rust/Native)
    → Commands: load_database, query_databases, set_monitoring
    ← Events: "hit" (match found), "databases-updated"
```

### Monitor System Architecture

The app uses a flexible monitor system supporting multiple input sources:

#### Monitor Types
1. **SystemLogs**: macOS `log stream` command (legacy)
2. **LogFile**: Tail any log file with rotation detection
3. **ApiEndpoint**: Poll HTTP endpoints for data (not yet implemented)
4. **FilesystemScan**: Scan filesystem for IOCs (not yet implemented)
5. **ZeekPacketCapture**: Live network packet capture with Zeek

#### Monitor Lifecycle
Each monitor:
1. Spawns a dedicated background thread
2. Uses `Worker` API from matchy for efficient batch processing
3. Extracts IoCs via `Extractor` (IPs, domains, emails, hashes, crypto addresses)
4. Queries all loaded databases for matches
5. Emits `hit` events to frontend
6. Sends native notifications via `tauri-plugin-notification`

#### Zeek Integration (NEW)
The **ZeekPacketCapture** monitor enables real-time network traffic analysis:
- Requires system-installed Zeek (via `brew install zeek`)
- Uses **osascript** to request elevated privileges on macOS
- Spawns Zeek with `-i <interface>` to capture live packets
- Tails Zeek's `conn.log` to extract IPs/domains from network connections
- Temporary logs stored in `/tmp/matchy-zeek-<uuid>/` and cleaned up on exit
- See `ZEEK_INTEGRATION.md` for detailed documentation

**Platform-specific notes**: 
- macOS: Uses `osascript` for privilege escalation (fully implemented)
- Linux: Will use `pkexec` or `sudo` (planned)
- Windows: Will use UAC elevation (planned)

### Key Dependencies

- `matchy`: Local path dependency to sibling `matchy` crate (`path = "../../matchy"`)
- `leptos 0.7`: Frontend framework with `csr` feature flag
- `tauri 2.0`: Desktop app framework with tray icon support
- `trunk`: WebAssembly build tool (serves on port 1420)

## Important Implementation Details

### IPC Bridge Pattern

Frontend commands use `wasm_bindgen` to call Tauri:

```rust
#[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"])]
async fn invoke(cmd: &str, args: JsValue) -> JsValue;
```

Always serialize arguments with `serde_wasm_bindgen::to_value()` before passing to `invoke()`.

### Database Lifecycle

Each loaded database gets:
- A unique UUID as identifier
- An `Arc<Mutex<Database>>` wrapper for thread-safe access
- Metadata cached at load time (size, stats, mode)

Databases remain loaded until explicitly removed via `unload_database()` or app restart.

### Hit Tracking

Hits are limited to 100 most recent in the frontend (`hits.truncate(100)`) to prevent memory growth during extended monitoring sessions.

### Tauri Window Management

The app uses a **system tray** with window hiding instead of close:
- Clicking window close button hides the window
- Window can be restored from tray menu
- "Quit" tray menu item exits the process

This allows background monitoring to continue when window is hidden.

## File Organization

```
matchy-app/
├── src/                    # Frontend (Leptos/WASM)
│   ├── main.rs            # Entry point, mounts Leptos app
│   └── app.rs             # Main UI component with state and event handlers
├── src-tauri/             # Backend (Tauri/Native)
│   └── src/
│       ├── lib.rs         # Tauri commands, state management, log monitoring
│       └── main.rs        # Binary entry point
├── Cargo.toml             # Frontend workspace root
├── Trunk.toml             # Frontend build configuration
└── index.html             # HTML shell for WASM app
```

## Common Patterns

### Adding a New Tauri Command

1. Define command in `src-tauri/src/lib.rs`:
   ```rust
   #[tauri::command]
   fn my_command(arg: String, state: tauri::State<'_, AppState>) -> Result<MyType, String>
   ```

2. Register in `invoke_handler![]` macro at bottom of `lib.rs`

3. Call from frontend:
   ```rust
   let args = serde_wasm_bindgen::to_value(&serde_json::json!({"arg": value})).unwrap();
   let res = invoke("my_command", args).await;
   ```

### Adding a New Event

Backend emits with `app.emit("event-name", payload)`.

Frontend listens with:
```rust
Effect::new(move |_| {
    spawn_local(async move {
        let closure = Closure::wrap(Box::new(move |event: JsValue| { ... }));
        listen("event-name", closure.as_ref()).await;
        closure.forget();
    });
});
```

## Matchy Library Integration

The `matchy` library is a **local path dependency** located at `../../matchy`. Changes to the matchy library require:

1. Rebuild both the library and this app: `cargo tauri build`
2. The app directly uses matchy's types: `Database`, `QueryResult`, `PatternExtractor`
3. Database mode (case-sensitive/insensitive) is determined at `.mxy` file creation time and is read-only in this app
