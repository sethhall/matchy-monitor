# Changelog

## [Unreleased]

### Added
- **File Picker Dialog**: Native system file browser for selecting `.mxy` database files
  - "Browse..." button opens macOS file picker
  - Filters to show only `.mxy` files
  - Selected path auto-populates in input field

- **Database Statistics Display**: Shows real-time database info after opening
  - **File Path**: Full path to opened database
  - **File Size**: Human-readable size (KB/MB/GB)
  - **Match Mode**: Case-sensitive or case-insensitive matching
  - **Query Statistics**: 
    - Total queries executed
    - Number of matches found
    - Match rate percentage
  - **Cache Performance** (shown after queries):
    - Cache hit rate percentage
  
- **Backend Commands**:
  - `get_db_info()`: Returns current database statistics
  - Updated `open_database()`: Returns `DatabaseInfo` struct with stats
  
- **Auto-updating Stats**: Database stats update automatically after each query

### Technical Details

#### Backend Changes (`src-tauri/`)
- Added `tauri-plugin-dialog` dependency for native file dialogs
- New types: `DatabaseInfo`, `DatabaseStatsInfo`
- Track database path in `AppState`
- Helper function `format_size()` for human-readable file sizes
- Integration with matchy's `DatabaseStats` API

#### Frontend Changes (`src/`)
- File picker using `window.__TAURI__.dialog.open()`
- Reactive stats display using Leptos signals
- Grid layout for clean stats presentation
- Conditional rendering for cache stats (only after queries)

### UI Layout

```
┌─────────────────────────────────────────┐
│ Open Database                           │
│ ┌─────────────────────────────────┐     │
│ │ /path/to/file.mxy    │ Browse...│     │
│ └─────────────────────────────────┘     │
│ [Open] [Close]                          │
│                                         │
│ ┌─────────────────────────────────────┐ │
│ │ Database Info (when open):          │ │
│ │ File: /Users/seth/threats.mxy       │ │
│ │ Size: 2.5 MB                        │ │
│ │ Mode: CaseInsensitive               │ │
│ │ Queries: 127 total, 98 matched (77%)│ │
│ │ Cache Hit Rate: 85%                 │ │
│ └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### Dependencies Added
- `tauri-plugin-dialog = "2"` (backend)
