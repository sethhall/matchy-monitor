use chrono::Utc;
use matchy::extractor::Extractor;
use matchy::processing::Worker;
use matchy::{Database, QueryResult as MatchyQueryResult};
use notify::poll::PollWatcher;
use notify::{Config, EventKind, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{create_dir_all, metadata, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use tauri::{Emitter, Manager};
use uuid::Uuid;

#[derive(Clone)]
struct DatabaseEntry {
    id: String,
    path: String,
    db: Arc<Mutex<Database>>,
    size_bytes: u64,
}

// New monitor architecture
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum MonitorType {
    SystemLogs,
    LogFile,
    ApiEndpoint,
    FilesystemScan,
    ZeekPacketCapture,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum MonitorConfig {
    SystemLogs,
    LogFile {
        path: String,
    },
    ApiEndpoint {
        url: String,
        interval_secs: u64,
    },
    FilesystemScan {
        path: String,
        recursive: bool,
    },
    ZeekPacketCapture {
        interface: String, // Network interface to monitor (e.g., "en0")
        #[serde(default)]
        zeek_log_dir: Option<String>, // Temp directory where Zeek logs are written
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum MonitorState {
    Running,
    Paused,
    Scheduled,
    Completed,
    Error { message: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Monitor {
    id: String,
    name: String,
    monitor_type: MonitorType,
    config: MonitorConfig,
    enabled: bool,
    stats: MonitorStatsData,
    state: MonitorState,
    last_activity: Option<String>,
    #[serde(default)]
    zeek_pid: Option<i32>, // PID of Zeek process if this is a ZeekPacketCapture monitor
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct MonitorStatsData {
    lines_processed: u64,
    items_extracted: u64,
    hits_found: u64,
}

struct AppState {
    databases: Arc<Mutex<HashMap<String, DatabaseEntry>>>,
    monitors: Arc<Mutex<HashMap<String, Monitor>>>,
    // Thread handles for active monitors
    monitor_threads: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    // Track Zeek PIDs for cleanup on shutdown
    zeek_pids: Arc<Mutex<Vec<i32>>>,
    // Global file watcher handle
    file_watcher: Arc<FileWatcherHandle>,
}

// Global file watcher system types
#[derive(Debug)]
enum WatcherCommand {
    AddFile {
        path: PathBuf,
        source_name: String,
        monitor_id: String,
    },
    AddDirectoryPattern {
        directory: PathBuf,
        pattern: String, // e.g., "*.log"
        monitor_id: String,
    },
    RemoveMonitor {
        monitor_id: String,
    },
    ReloadDatabases,
    Shutdown,
}

struct FileWatchState {
    path: PathBuf,
    source_name: String,
    monitor_id: String,
    position: u64,
    inode: u64,
    file_handle: Option<File>,
    incomplete_line: Vec<u8>,
}

#[derive(Clone)]
struct FileWatcherHandle {
    command_tx: Sender<WatcherCommand>,
}

impl FileWatcherHandle {
    pub fn add_file(
        &self,
        path: PathBuf,
        source_name: String,
        monitor_id: String,
    ) -> Result<(), String> {
        self.command_tx
            .send(WatcherCommand::AddFile {
                path,
                source_name,
                monitor_id,
            })
            .map_err(|e| format!("Failed to send command: {}", e))
    }

    pub fn add_directory_pattern(
        &self,
        directory: PathBuf,
        pattern: String,
        monitor_id: String,
    ) -> Result<(), String> {
        self.command_tx
            .send(WatcherCommand::AddDirectoryPattern {
                directory,
                pattern,
                monitor_id,
            })
            .map_err(|e| format!("Failed to send command: {}", e))
    }

    pub fn remove_monitor(&self, monitor_id: String) -> Result<(), String> {
        self.command_tx
            .send(WatcherCommand::RemoveMonitor { monitor_id })
            .map_err(|e| format!("Failed to send command: {}", e))
    }

    pub fn reload_databases(&self) -> Result<(), String> {
        self.command_tx
            .send(WatcherCommand::ReloadDatabases)
            .map_err(|e| format!("Failed to send reload command: {}", e))
    }
}

// Start the global file watcher thread
fn start_global_file_watcher(
    app: tauri::AppHandle,
    databases: Arc<Mutex<HashMap<String, DatabaseEntry>>>,
    monitors: Arc<Mutex<HashMap<String, Monitor>>>,
) -> FileWatcherHandle {
    let (command_tx, command_rx) = channel();

    std::thread::spawn(move || {
        run_global_file_watcher(app, databases, monitors, command_rx);
    });

    FileWatcherHandle { command_tx }
}

fn run_global_file_watcher(
    app: tauri::AppHandle,
    databases: Arc<Mutex<HashMap<String, DatabaseEntry>>>,
    monitors: Arc<Mutex<HashMap<String, Monitor>>>,
    command_rx: Receiver<WatcherCommand>,
) {
    eprintln!("[DEBUG] Starting global file watcher");

    // Initialize worker immediately if databases exist
    let databases_snapshot = databases.lock().unwrap().clone();
    let mut worker_opt: Option<(Worker, Extractor)> = if !databases_snapshot.is_empty() {
        match build_worker_and_extractor(&databases_snapshot) {
            Ok(worker_extractor) => {
                eprintln!(
                    "[DEBUG] Initialized worker with {} databases",
                    databases_snapshot.len()
                );
                Some(worker_extractor)
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to initialize worker: {}", e);
                None
            }
        }
    } else {
        eprintln!("[DEBUG] No databases loaded, worker will be created when databases are added");
        None
    };

    // Set up PollWatcher for reliable file change detection (especially for appends)
    let (notify_tx, notify_rx) = channel();
    let config = Config::default().with_poll_interval(std::time::Duration::from_millis(500));
    let mut watcher = match PollWatcher::new(notify_tx, config) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("[ERROR] Failed to create PollWatcher: {}", e);
            return;
        }
    };

    // Track watched files: path -> FileWatchState
    let mut watched_files: HashMap<PathBuf, FileWatchState> = HashMap::new();
    // Track which monitor owns which files
    let mut monitor_files: HashMap<String, Vec<PathBuf>> = HashMap::new();
    // Track which directories are watched (for cleanup)
    let mut watched_directories: HashMap<String, Vec<PathBuf>> = HashMap::new();

    // Batching state
    let mut buffer: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut pending_lines: usize = 0;
    const MAX_BATCH_LINES: usize = 200;
    const MAX_BATCH_BYTES: usize = 128 * 1024;
    const MAX_BATCH_AGE: std::time::Duration = std::time::Duration::from_millis(100);
    let mut last_flush = std::time::Instant::now();
    let mut current_source: Option<String> = None;
    let mut current_monitor_id: Option<String> = None;

    let mut window_visible = app
        .get_webview_window("main")
        .and_then(|w| w.is_visible().ok())
        .unwrap_or(false);
    let mut last_visibility_check = std::time::Instant::now();
    const VISIBILITY_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

    let mut last_stats_update = std::time::Instant::now();
    const STATS_UPDATE_INTERVAL_VISIBLE: std::time::Duration = std::time::Duration::from_secs(1);
    const STATS_UPDATE_INTERVAL_HIDDEN: std::time::Duration = std::time::Duration::from_secs(30);

    let mut read_buffer = vec![0u8; 64 * 1024];

    // Fallback polling to ensure we don't miss events
    let mut last_full_scan = std::time::Instant::now();
    const FULL_SCAN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

    loop {
        // Calculate timeout for batch flushing
        let timeout = if pending_lines > 0 {
            MAX_BATCH_AGE
                .checked_sub(last_flush.elapsed())
                .unwrap_or(std::time::Duration::from_millis(10))
        } else {
            std::time::Duration::from_millis(100)
        };

        // Check for commands (non-blocking with timeout)
        match command_rx.recv_timeout(timeout) {
            Ok(WatcherCommand::AddFile {
                path,
                source_name,
                monitor_id,
            }) => {
                eprintln!("[DEBUG] Adding file to watch: {}", path.display());

                // Open file and seek to end
                if let Ok(mut file) = File::open(&path) {
                    let position = file.seek(SeekFrom::End(0)).unwrap_or(0);
                    let inode = metadata(&path).ok().map(|m| m.ino()).unwrap_or(0);

                    watched_files.insert(
                        path.clone(),
                        FileWatchState {
                            path: path.clone(),
                            source_name,
                            monitor_id: monitor_id.clone(),
                            position,
                            inode,
                            file_handle: Some(file),
                            incomplete_line: Vec::new(),
                        },
                    );

                    monitor_files
                        .entry(monitor_id)
                        .or_insert_with(Vec::new)
                        .push(path.clone());

                    // Watch the file
                    if let Err(e) = watcher.watch(&path, RecursiveMode::NonRecursive) {
                        eprintln!("[ERROR] Failed to watch {}: {}", path.display(), e);
                    }
                } else {
                    eprintln!("[WARN] Failed to open file: {}", path.display());
                }
            }

            Ok(WatcherCommand::AddDirectoryPattern {
                directory,
                pattern,
                monitor_id,
            }) => {
                eprintln!(
                    "[DEBUG] Adding directory pattern: {} / {}",
                    directory.display(),
                    pattern
                );

                // Find all matching files
                let mut matched_count = 0;
                if let Ok(entries) = std::fs::read_dir(&directory) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                                // Simple glob matching (just *.ext for now)
                                if pattern == "*"
                                    || pattern.trim_start_matches("*.").split('.').last()
                                        == path.extension().and_then(|e| e.to_str())
                                {
                                    let source_name =
                                        format!("Zeek:{}", filename.trim_end_matches(".log"));

                                    if let Ok(mut file) = File::open(&path) {
                                        // For existing files when monitor starts, seek to end
                                        let position = file.seek(SeekFrom::End(0)).unwrap_or(0);
                                        let inode =
                                            metadata(&path).ok().map(|m| m.ino()).unwrap_or(0);

                                        eprintln!("[DEBUG] Watching existing file: {} (inode: {}, position: {})", path.display(), inode, position);
                                        watched_files.insert(
                                            path.clone(),
                                            FileWatchState {
                                                path: path.clone(),
                                                source_name,
                                                monitor_id: monitor_id.clone(),
                                                position,
                                                inode,
                                                file_handle: Some(file),
                                                incomplete_line: Vec::new(),
                                            },
                                        );

                                        monitor_files
                                            .entry(monitor_id.clone())
                                            .or_insert_with(Vec::new)
                                            .push(path.clone());

                                        if let Err(e) =
                                            watcher.watch(&path, RecursiveMode::NonRecursive)
                                        {
                                            eprintln!(
                                                "[ERROR] Failed to watch {}: {}",
                                                path.display(),
                                                e
                                            );
                                        } else {
                                            matched_count += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                eprintln!(
                    "[DEBUG] Successfully watching {} files matching pattern {}",
                    matched_count, pattern
                );

                // Watch the directory for new files and track it
                if let Err(e) = watcher.watch(&directory, RecursiveMode::NonRecursive) {
                    eprintln!(
                        "[ERROR] Failed to watch directory {}: {}",
                        directory.display(),
                        e
                    );
                } else {
                    watched_directories
                        .entry(monitor_id.clone())
                        .or_insert_with(Vec::new)
                        .push(directory.clone());
                }
            }

            Ok(WatcherCommand::RemoveMonitor { monitor_id }) => {
                eprintln!("[DEBUG] Removing all files for monitor: {}", monitor_id);

                // Unwatch all files
                if let Some(paths) = monitor_files.remove(&monitor_id) {
                    for path in paths {
                        watched_files.remove(&path);
                        let _ = watcher.unwatch(&path);
                    }
                }

                // Unwatch all directories
                if let Some(dirs) = watched_directories.remove(&monitor_id) {
                    for dir in dirs {
                        eprintln!("[DEBUG] Unwatching directory: {}", dir.display());
                        let _ = watcher.unwatch(&dir);
                    }
                }
            }

            Ok(WatcherCommand::ReloadDatabases) => {
                eprintln!("[DEBUG] Reloading databases...");
                let databases_snapshot = databases.lock().unwrap().clone();

                if databases_snapshot.is_empty() {
                    eprintln!("[WARN] No databases to load, worker disabled");
                    worker_opt = None;
                } else {
                    match build_worker_and_extractor(&databases_snapshot) {
                        Ok(new_worker_extractor) => {
                            worker_opt = Some(new_worker_extractor);
                            eprintln!(
                                "[DEBUG] Successfully reloaded {} databases",
                                databases_snapshot.len()
                            );
                        }
                        Err(e) => {
                            eprintln!("[ERROR] Failed to reload databases: {}", e);
                        }
                    }
                }
            }

            Ok(WatcherCommand::Shutdown) => {
                eprintln!("[DEBUG] Global file watcher shutting down");
                break;
            }

            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Timeout - check for file events and flush batch if needed
            }

            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("[DEBUG] Command channel disconnected");
                break;
            }
        }

        // Process notify events (non-blocking)
        while let Ok(Ok(event)) = notify_rx.try_recv() {
            eprintln!("[DEBUG] File event: {:?} for {:?}", event.kind, event.paths);
            match event.kind {
                // Handle new file creation in monitored directories
                EventKind::Create(_) => {
                    for event_path in &event.paths {
                        // Check if this is a new .log file in a monitored directory
                        if event_path.is_file()
                            && event_path.extension().and_then(|e| e.to_str()) == Some("log")
                        {
                            // Check if file is already being watched
                            if !watched_files.contains_key(event_path) {
                                // Find which monitor owns this directory
                                if let Some(parent) = event_path.parent() {
                                    for (mon_id, paths) in &monitor_files {
                                        // Check if any watched file's parent matches this directory
                                        if paths.iter().any(|p| p.parent() == Some(parent)) {
                                            // Add this new file to watch
                                            let filename = event_path
                                                .file_name()
                                                .and_then(|n| n.to_str())
                                                .unwrap_or("unknown");
                                            let source_name = format!(
                                                "Zeek:{}",
                                                filename.trim_end_matches(".log")
                                            );

                                            if let Ok(mut file) = File::open(event_path) {
                                                // NEW files: seek to START to capture all data Zeek already wrote
                                                let position =
                                                    file.seek(SeekFrom::Start(0)).unwrap_or(0);
                                                let inode = metadata(event_path)
                                                    .ok()
                                                    .map(|m| m.ino())
                                                    .unwrap_or(0);

                                                eprintln!("[DEBUG] New log file created: {} (inode: {}, starting from position: {})", event_path.display(), inode, position);
                                                watched_files.insert(
                                                    event_path.clone(),
                                                    FileWatchState {
                                                        path: event_path.clone(),
                                                        source_name,
                                                        monitor_id: mon_id.clone(),
                                                        position,
                                                        inode,
                                                        file_handle: Some(file),
                                                        incomplete_line: Vec::new(),
                                                    },
                                                );

                                                monitor_files
                                                    .entry(mon_id.clone())
                                                    .or_insert_with(Vec::new)
                                                    .push(event_path.clone());

                                                if let Err(e) = watcher
                                                    .watch(event_path, RecursiveMode::NonRecursive)
                                                {
                                                    eprintln!(
                                                        "[ERROR] Failed to watch new file {}: {}",
                                                        event_path.display(),
                                                        e
                                                    );
                                                }
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                EventKind::Modify(_) => {
                    for event_path in &event.paths {
                        if let Some(file_state) = watched_files.get_mut(event_path) {
                            eprintln!(
                                "[DEBUG] Processing Modify event for: {}",
                                event_path.display()
                            );
                            // Flush previous batch if we're switching files
                            if pending_lines > 0
                                && (current_monitor_id.as_ref() != Some(&file_state.monitor_id)
                                    || current_source.as_ref() != Some(&file_state.source_name))
                            {
                                if let (Some(src), Some(mon_id)) =
                                    (&current_source, &current_monitor_id)
                                {
                                    if let Some((worker, extractor)) = &mut worker_opt {
                                        process_batch_worker(
                                            worker,
                                            extractor,
                                            &buffer,
                                            &app,
                                            src,
                                            window_visible,
                                            &monitors,
                                            mon_id,
                                            None,
                                        );
                                    }
                                    buffer.clear();
                                    pending_lines = 0;
                                    last_flush = std::time::Instant::now();
                                }
                            }

                            current_source = Some(file_state.source_name.clone());
                            current_monitor_id = Some(file_state.monitor_id.clone());

                            // Check for rotation
                            if let Ok(m) = metadata(&file_state.path) {
                                let new_inode = m.ino();
                                if new_inode != file_state.inode {
                                    eprintln!(
                                        "[DEBUG] File rotated: {}",
                                        file_state.path.display()
                                    );
                                    file_state.inode = new_inode;
                                    if let Ok(f) = File::open(&file_state.path) {
                                        file_state.file_handle = Some(f);
                                        file_state.position = 0;
                                    }
                                }
                            }

                            // Read new data
                            if let Some(ref mut file) = file_state.file_handle {
                                let _ = file.seek(SeekFrom::Start(file_state.position));

                                loop {
                                    match file.read(&mut read_buffer) {
                                        Ok(0) => {
                                            eprintln!(
                                                "[DEBUG] No data available in {}",
                                                file_state.path.display()
                                            );
                                            break;
                                        }
                                        Ok(n) => {
                                            eprintln!(
                                                "[DEBUG] Read {} bytes from {} (position now: {})",
                                                n,
                                                file_state.path.display(),
                                                file_state.position + n as u64
                                            );
                                            file_state.position += n as u64;

                                            let chunk = &read_buffer[..n];
                                            let line_count_before = pending_lines;

                                            // Find the last newline to identify incomplete line
                                            let last_newline_pos =
                                                chunk.iter().rposition(|&b| b == b'\n');

                                            let (complete_data, incomplete_data) =
                                                match last_newline_pos {
                                                    Some(pos) => {
                                                        // Split at the last newline
                                                        (&chunk[..=pos], &chunk[pos + 1..])
                                                    }
                                                    None => {
                                                        // No newline found - entire chunk is incomplete
                                                        (&chunk[..0], chunk)
                                                    }
                                                };

                                            // Process complete lines (prepend any previous incomplete line from THIS file)
                                            if !complete_data.is_empty()
                                                || !file_state.incomplete_line.is_empty()
                                            {
                                                let mut data_to_process =
                                                    file_state.incomplete_line.clone();
                                                data_to_process.extend_from_slice(complete_data);
                                                file_state.incomplete_line.clear();

                                                // Count and buffer complete lines
                                                for line in data_to_process.split(|&b| b == b'\n') {
                                                    if line.is_empty() {
                                                        continue;
                                                    }

                                                    // Update line count
                                                    {
                                                        let mut monitors_lock =
                                                            monitors.lock().unwrap();
                                                        if let Some(monitor) = monitors_lock
                                                            .get_mut(&file_state.monitor_id)
                                                        {
                                                            let old_count =
                                                                monitor.stats.lines_processed;
                                                            monitor.stats.lines_processed += 1;
                                                            if old_count % 100 == 0 {
                                                                eprintln!("[DEBUG] Monitor {} processed {} lines (source: {})", 
                                                                    file_state.monitor_id, monitor.stats.lines_processed, file_state.source_name);
                                                            }
                                                        }
                                                    }

                                                    buffer.extend_from_slice(line);
                                                    buffer.push(b'\n');
                                                    pending_lines += 1;

                                                    let should_flush = pending_lines
                                                        >= MAX_BATCH_LINES
                                                        || buffer.len() >= MAX_BATCH_BYTES
                                                        || last_flush.elapsed() >= MAX_BATCH_AGE;

                                                    if should_flush {
                                                        eprintln!("[DEBUG] Flushing batch: {} lines, {} bytes", pending_lines, buffer.len());
                                                        // Ensure worker exists before processing
                                                        if worker_opt.is_none() {
                                                            let dbs =
                                                                databases.lock().unwrap().clone();
                                                            if !dbs.is_empty() {
                                                                if let Ok(w) =
                                                                    build_worker_and_extractor(&dbs)
                                                                {
                                                                    worker_opt = Some(w);
                                                                    eprintln!("[DEBUG] Initialized worker with {} databases", dbs.len());
                                                                }
                                                            }
                                                        }
                                                        if let Some((worker, extractor)) =
                                                            &mut worker_opt
                                                        {
                                                            process_batch_worker(
                                                                worker,
                                                                extractor,
                                                                &buffer,
                                                                &app,
                                                                &file_state.source_name,
                                                                window_visible,
                                                                &monitors,
                                                                &file_state.monitor_id,
                                                                None,
                                                            );
                                                        }
                                                        buffer.clear();
                                                        pending_lines = 0;
                                                        last_flush = std::time::Instant::now();
                                                    }
                                                }
                                            }

                                            // Save incomplete data to THIS file's buffer for next read
                                            if !incomplete_data.is_empty() {
                                                file_state
                                                    .incomplete_line
                                                    .extend_from_slice(incomplete_data);
                                                eprintln!("[DEBUG] Buffering {} bytes of incomplete line from {}", incomplete_data.len(), file_state.path.display());
                                            }

                                            let lines_in_chunk =
                                                pending_lines.saturating_sub(line_count_before);
                                            if lines_in_chunk > 0 {
                                                eprintln!("[DEBUG] Found {} complete lines in this read from {}", lines_in_chunk, file_state.path.display());
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "[DEBUG] Read error from {}: {:?}",
                                                file_state.path.display(),
                                                e
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Fallback: periodic full scan of watched directories and files
        if last_full_scan.elapsed() >= FULL_SCAN_INTERVAL {
            // Discover any new files in watched directories (in case Create events were missed)
            let dir_map_snapshot: Vec<(String, Vec<PathBuf>)> = watched_directories
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            for (mon_id, dirs) in dir_map_snapshot {
                for directory in dirs {
                    if let Ok(entries) = std::fs::read_dir(&directory) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.is_file() {
                                if path.extension().and_then(|e| e.to_str()) == Some("log") {
                                    if !watched_files.contains_key(&path) {
                                        let filename = path
                                            .file_name()
                                            .and_then(|n| n.to_str())
                                            .unwrap_or("unknown");
                                        let source_name =
                                            format!("Zeek:{}", filename.trim_end_matches(".log"));
                                        if let Ok(mut file) = File::open(&path) {
                                            let _ = file.seek(SeekFrom::Start(0));
                                            let inode =
                                                metadata(&path).ok().map(|m| m.ino()).unwrap_or(0);
                                            eprintln!("[DEBUG] [SCAN] Found new file to watch: {} (inode: {})", path.display(), inode);
                                            watched_files.insert(
                                                path.clone(),
                                                FileWatchState {
                                                    path: path.clone(),
                                                    source_name,
                                                    monitor_id: mon_id.clone(),
                                                    position: 0,
                                                    inode,
                                                    file_handle: Some(file),
                                                    incomplete_line: Vec::new(),
                                                },
                                            );
                                            monitor_files
                                                .entry(mon_id.clone())
                                                .or_insert_with(Vec::new)
                                                .push(path.clone());
                                            let _ =
                                                watcher.watch(&path, RecursiveMode::NonRecursive);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Scan all watched files for appended data
            let paths_snapshot: Vec<PathBuf> = watched_files.keys().cloned().collect();
            for path in paths_snapshot {
                if let Some(file_state) = watched_files.get_mut(&path) {
                    // Flush previous batch if we're switching files
                    if pending_lines > 0
                        && (current_monitor_id.as_ref() != Some(&file_state.monitor_id)
                            || current_source.as_ref() != Some(&file_state.source_name))
                    {
                        if let (Some(src), Some(mon_id)) = (&current_source, &current_monitor_id) {
                            if let Some((worker, extractor)) = &mut worker_opt {
                                process_batch_worker(
                                    worker,
                                    extractor,
                                    &buffer,
                                    &app,
                                    src,
                                    window_visible,
                                    &monitors,
                                    mon_id,
                                    None,
                                );
                            }
                            buffer.clear();
                            pending_lines = 0;
                            last_flush = std::time::Instant::now();
                        }
                    }
                    current_source = Some(file_state.source_name.clone());
                    current_monitor_id = Some(file_state.monitor_id.clone());

                    // Check for rotation/truncation
                    if let Ok(m) = metadata(&file_state.path) {
                        let new_inode = m.ino();
                        if new_inode != file_state.inode || m.len() < file_state.position {
                            eprintln!(
                                "[DEBUG] [SCAN] File rotated or truncated: {}",
                                file_state.path.display()
                            );
                            file_state.inode = new_inode;
                            if let Ok(f) = File::open(&file_state.path) {
                                file_state.file_handle = Some(f);
                                file_state.position = 0;
                                file_state.incomplete_line.clear();
                            }
                        }
                    }

                    // Read any new data
                    if let Some(ref mut file) = file_state.file_handle {
                        let _ = file.seek(SeekFrom::Start(file_state.position));
                        loop {
                            match file.read(&mut read_buffer) {
                                Ok(0) => break,
                                Ok(n) => {
                                    file_state.position += n as u64;
                                    let chunk = &read_buffer[..n];
                                    let line_count_before = pending_lines;

                                    let last_newline_pos = chunk.iter().rposition(|&b| b == b'\n');
                                    let (complete_data, incomplete_data) = match last_newline_pos {
                                        Some(pos) => (&chunk[..=pos], &chunk[pos + 1..]),
                                        None => (&chunk[..0], chunk),
                                    };

                                    if !complete_data.is_empty()
                                        || !file_state.incomplete_line.is_empty()
                                    {
                                        let mut data_to_process =
                                            file_state.incomplete_line.clone();
                                        data_to_process.extend_from_slice(complete_data);
                                        file_state.incomplete_line.clear();

                                        for line in data_to_process.split(|&b| b == b'\n') {
                                            if line.is_empty() {
                                                continue;
                                            }
                                            {
                                                let mut monitors_lock = monitors.lock().unwrap();
                                                if let Some(monitor) =
                                                    monitors_lock.get_mut(&file_state.monitor_id)
                                                {
                                                    monitor.stats.lines_processed += 1;
                                                }
                                            }
                                            buffer.extend_from_slice(line);
                                            buffer.push(b'\n');
                                            pending_lines += 1;

                                            let should_flush = pending_lines >= MAX_BATCH_LINES
                                                || buffer.len() >= MAX_BATCH_BYTES
                                                || last_flush.elapsed() >= MAX_BATCH_AGE;

                                            if should_flush {
                                                // Ensure worker exists
                                                if worker_opt.is_none() {
                                                    let dbs = databases.lock().unwrap().clone();
                                                    if !dbs.is_empty() {
                                                        if let Ok(w) =
                                                            build_worker_and_extractor(&dbs)
                                                        {
                                                            worker_opt = Some(w);
                                                        }
                                                    }
                                                }
                                                if let Some((worker, extractor)) = &mut worker_opt {
                                                    process_batch_worker(
                                                        worker,
                                                        extractor,
                                                        &buffer,
                                                        &app,
                                                        &file_state.source_name,
                                                        window_visible,
                                                        &monitors,
                                                        &file_state.monitor_id,
                                                        None,
                                                    );
                                                }
                                                buffer.clear();
                                                pending_lines = 0;
                                                last_flush = std::time::Instant::now();
                                            }
                                        }
                                    }

                                    if !incomplete_data.is_empty() {
                                        file_state
                                            .incomplete_line
                                            .extend_from_slice(incomplete_data);
                                    }

                                    let _ = line_count_before; // quiet unused warning if any
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            }
            last_full_scan = std::time::Instant::now();
        }

        // Flush pending batch if timeout exceeded
        if pending_lines > 0 && last_flush.elapsed() >= MAX_BATCH_AGE {
            if let (Some(src), Some(mon_id)) = (&current_source, &current_monitor_id) {
                if let Some((worker, extractor)) = &mut worker_opt {
                    process_batch_worker(
                        worker,
                        extractor,
                        &buffer,
                        &app,
                        src,
                        window_visible,
                        &monitors,
                        mon_id,
                        None,
                    );
                }
                buffer.clear();
                pending_lines = 0;
                last_flush = std::time::Instant::now();
            }
        }

        // Update window visibility cache
        if last_visibility_check.elapsed() >= VISIBILITY_CHECK_INTERVAL {
            window_visible = app
                .get_webview_window("main")
                .and_then(|w| w.is_visible().ok())
                .unwrap_or(false);
            last_visibility_check = std::time::Instant::now();
        }

        // Emit periodic updates
        let interval = if window_visible {
            STATS_UPDATE_INTERVAL_VISIBLE
        } else {
            STATS_UPDATE_INTERVAL_HIDDEN
        };

        if last_stats_update.elapsed() >= interval {
            let _ = app.emit("databases-updated", ());
            let _ = app.emit("monitors-updated", ());
            last_stats_update = std::time::Instant::now();
        }
    }

    eprintln!("[DEBUG] Global file watcher exited");
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DatabaseInfo {
    id: String,
    path: String,
    size_bytes: u64,
    size_human: String,
    mode: String,
    stats: DatabaseStatsInfo,
    indicator_counts: IndicatorCounts,
    description: Option<String>,
    build_epoch: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DatabaseStatsInfo {
    total_queries: u64,
    queries_with_match: u64,
    cache_hit_rate: f64,
    match_rate: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct IndicatorCounts {
    total: usize,
    ip: usize,
    literal: usize,
    glob: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Hit {
    id: String,
    timestamp: String,
    matched_text: String,
    match_type: String,
    source: String, // "manual" or "log"
    database_id: String,
    matched_indicators: Vec<String>, // Pattern IDs or "IP: <cidr>" for IP matches
    data: Vec<serde_json::Value>,
    log_line: Option<String>, // Full log line for context
}

#[tauri::command]
async fn pick_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let file_path = app
        .dialog()
        .file()
        .add_filter("Matchy Database", &["mxy"])
        .blocking_pick_file();

    Ok(file_path.map(|p| p.to_string()))
}

#[tauri::command]
async fn pick_any_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let file_path = app.dialog().file().blocking_pick_file();

    Ok(file_path.map(|p| p.to_string()))
}

#[tauri::command]
fn load_database(
    path: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<DatabaseInfo, String> {
    match Database::from(&path).open() {
        Ok(db) => {
            let size_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

            let size_human = format_size(size_bytes);
            let stats = db.stats();
            let mode = format!("{:?}", db.mode());

            // Get indicator counts
            let ip_count = db.ip_count();
            let literal_count = db.literal_count();
            let glob_count = db.glob_count();
            let total_count = ip_count + literal_count + glob_count;

            // Extract description and build_epoch from metadata
            let (description, build_epoch) = db
                .metadata()
                .and_then(|meta| {
                    if let matchy::data_section::DataValue::Map(map) = meta {
                        let description =
                            if let Some(matchy::data_section::DataValue::Map(desc_map)) =
                                map.get("description")
                            {
                                // Try English first
                                if let Some(matchy::data_section::DataValue::String(desc)) =
                                    desc_map.get("en")
                                {
                                    Some(desc.clone())
                                } else {
                                    // Fallback to first available language
                                    desc_map.iter().find_map(|(_, desc_value)| {
                                        if let matchy::data_section::DataValue::String(desc) =
                                            desc_value
                                        {
                                            Some(desc.clone())
                                        } else {
                                            None
                                        }
                                    })
                                }
                            } else {
                                None
                            };

                        let build_epoch = match map.get("build_epoch") {
                            Some(matchy::data_section::DataValue::Uint64(epoch)) => Some(*epoch),
                            Some(matchy::data_section::DataValue::Uint32(epoch)) => {
                                Some(*epoch as u64)
                            }
                            Some(matchy::data_section::DataValue::Uint16(epoch)) => {
                                Some(*epoch as u64)
                            }
                            _ => None,
                        };

                        return Some((description, build_epoch));
                    }
                    None
                })
                .unwrap_or((None, None));

            // Generate unique ID
            let id = format!("{}", uuid::Uuid::new_v4());

            let entry = DatabaseEntry {
                id: id.clone(),
                path: path.clone(),
                db: Arc::new(Mutex::new(db)),
                size_bytes,
            };

            let info = DatabaseInfo {
                id: id.clone(),
                path,
                size_bytes,
                size_human,
                mode,
                stats: DatabaseStatsInfo {
                    total_queries: stats.total_queries,
                    queries_with_match: stats.queries_with_match,
                    cache_hit_rate: stats.cache_hit_rate(),
                    match_rate: stats.match_rate(),
                },
                indicator_counts: IndicatorCounts {
                    total: total_count,
                    ip: ip_count,
                    literal: literal_count,
                    glob: glob_count,
                },
                description,
                build_epoch,
            };

            state.inner().databases.lock().unwrap().insert(id, entry);

            // Save database paths to disk
            let databases = state.inner().databases.lock().unwrap().clone();
            let _ = save_database_paths_to_disk(&databases, &app);

            // Notify global watcher to reload databases
            let _ = state.file_watcher.reload_databases();

            Ok(info)
        }
        Err(e) => Err(format!("Failed to open database: {}", e)),
    }
}

#[tauri::command]
fn unload_database(
    id: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    state.inner().databases.lock().unwrap().remove(&id);

    // Save updated database paths to disk
    let databases = state.inner().databases.lock().unwrap().clone();
    let _ = save_database_paths_to_disk(&databases, &app);

    // Notify global watcher to reload databases
    let _ = state.file_watcher.reload_databases();

    Ok(())
}

#[tauri::command]
fn list_databases(state: tauri::State<'_, AppState>) -> Result<Vec<DatabaseInfo>, String> {
    let databases = state.inner().databases.lock().unwrap();
    let mut result = Vec::new();

    for entry in databases.values() {
        let db = entry.db.lock().unwrap();
        let stats = db.stats();
        let mode = format!("{:?}", db.mode());

        // Get indicator counts
        let ip_count = db.ip_count();
        let literal_count = db.literal_count();
        let glob_count = db.glob_count();
        let total_count = ip_count + literal_count + glob_count;

        // Extract description and build_epoch from metadata
        let (description, build_epoch) = db
            .metadata()
            .and_then(|meta| {
                if let matchy::data_section::DataValue::Map(map) = meta {
                    let description = if let Some(matchy::data_section::DataValue::Map(desc_map)) =
                        map.get("description")
                    {
                        // Try English first
                        if let Some(matchy::data_section::DataValue::String(desc)) =
                            desc_map.get("en")
                        {
                            Some(desc.clone())
                        } else {
                            // Fallback to first available language
                            desc_map.iter().find_map(|(_, desc_value)| {
                                if let matchy::data_section::DataValue::String(desc) = desc_value {
                                    Some(desc.clone())
                                } else {
                                    None
                                }
                            })
                        }
                    } else {
                        None
                    };

                    let build_epoch = match map.get("build_epoch") {
                        Some(matchy::data_section::DataValue::Uint64(epoch)) => Some(*epoch),
                        Some(matchy::data_section::DataValue::Uint32(epoch)) => Some(*epoch as u64),
                        Some(matchy::data_section::DataValue::Uint16(epoch)) => Some(*epoch as u64),
                        _ => None,
                    };

                    return Some((description, build_epoch));
                }
                None
            })
            .unwrap_or((None, None));

        result.push(DatabaseInfo {
            id: entry.id.clone(),
            path: entry.path.clone(),
            size_bytes: entry.size_bytes,
            size_human: format_size(entry.size_bytes),
            mode,
            stats: DatabaseStatsInfo {
                total_queries: stats.total_queries,
                queries_with_match: stats.queries_with_match,
                cache_hit_rate: stats.cache_hit_rate(),
                match_rate: stats.match_rate(),
            },
            indicator_counts: IndicatorCounts {
                total: total_count,
                ip: ip_count,
                literal: literal_count,
                glob: glob_count,
            },
            description,
            build_epoch,
        });
    }

    Ok(result)
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

#[tauri::command]
fn query_databases(
    query: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<Vec<Hit>, String> {
    let databases = state.inner().databases.lock().unwrap();
    let mut hits = Vec::new();

    for entry in databases.values() {
        let db = entry.db.lock().unwrap();
        if let Ok(Some(result)) = db.lookup(&query) {
            let (data_values, matched_indicators): (Vec<serde_json::Value>, Vec<String>) =
                match result {
                    MatchyQueryResult::Ip { data, prefix_len } => {
                        let indicator = format!("{}/{}", query, prefix_len);
                        (
                            vec![serde_json::to_value(&data).unwrap_or(serde_json::Value::Null)],
                            vec![indicator],
                        )
                    }
                    MatchyQueryResult::Pattern { data, pattern_ids } => {
                        let indicators: Vec<String> = pattern_ids
                            .iter()
                            .map(|id| db.get_pattern_string(*id).unwrap_or_else(|| query.clone()))
                            .collect();
                        let values = data
                            .iter()
                            .filter_map(|opt_dv| {
                                opt_dv.as_ref().and_then(|dv| serde_json::to_value(dv).ok())
                            })
                            .collect();
                        (values, indicators)
                    }
                    MatchyQueryResult::NotFound => continue,
                };

            // Show hit if we have indicators (even without data)
            if !matched_indicators.is_empty() {
                let hit = Hit {
                    id: Uuid::new_v4().to_string(),
                    timestamp: Utc::now().to_rfc3339(),
                    matched_text: query.clone(),
                    match_type: "Manual".to_string(),
                    source: "manual".to_string(),
                    database_id: entry.id.clone(),
                    matched_indicators,
                    data: data_values,
                    log_line: None,
                };

                // Emit hit event to frontend
                let _ = app.emit("hit", hit.clone());
                hits.push(hit);
            }
        }
    }

    // Notify frontend to refresh database stats
    let _ = app.emit("databases-updated", ());

    Ok(hits)
}

// Monitor management commands
// Helper functions for monitor persistence
fn get_monitors_config_path(app: &tauri::AppHandle) -> PathBuf {
    let app_data = app
        .path()
        .app_data_dir()
        .expect("Failed to get app data directory");
    app_data.join("monitors.json")
}

fn get_databases_config_path(app: &tauri::AppHandle) -> PathBuf {
    let app_data = app
        .path()
        .app_data_dir()
        .expect("Failed to get app data directory");
    app_data.join("databases.json")
}

fn save_monitors_to_disk(
    monitors: &HashMap<String, Monitor>,
    app: &tauri::AppHandle,
) -> Result<(), String> {
    let config_path = get_monitors_config_path(app);

    // Ensure parent directory exists
    if let Some(parent) = config_path.parent() {
        create_dir_all(parent).map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    let json = serde_json::to_string_pretty(monitors)
        .map_err(|e| format!("Failed to serialize monitors: {}", e))?;

    std::fs::write(&config_path, json)
        .map_err(|e| format!("Failed to write monitors config: {}", e))?;

    Ok(())
}

fn load_monitors_from_disk(app: &tauri::AppHandle) -> HashMap<String, Monitor> {
    let config_path = get_monitors_config_path(app);

    if !config_path.exists() {
        return HashMap::new();
    }

    match std::fs::read_to_string(&config_path) {
        Ok(json) => match serde_json::from_str(&json) {
            Ok(monitors) => monitors,
            Err(e) => {
                eprintln!("Failed to parse monitors config: {}", e);
                HashMap::new()
            }
        },
        Err(e) => {
            eprintln!("Failed to read monitors config: {}", e);
            HashMap::new()
        }
    }
}

fn save_database_paths_to_disk(
    databases: &HashMap<String, DatabaseEntry>,
    app: &tauri::AppHandle,
) -> Result<(), String> {
    let config_path = get_databases_config_path(app);

    // Ensure parent directory exists
    if let Some(parent) = config_path.parent() {
        create_dir_all(parent).map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    // Extract just the paths to save
    let paths: Vec<String> = databases.values().map(|entry| entry.path.clone()).collect();

    let json = serde_json::to_string_pretty(&paths)
        .map_err(|e| format!("Failed to serialize database paths: {}", e))?;

    std::fs::write(&config_path, json)
        .map_err(|e| format!("Failed to write databases config: {}", e))?;

    Ok(())
}

fn load_databases_from_disk(app: &tauri::AppHandle) -> HashMap<String, DatabaseEntry> {
    let config_path = get_databases_config_path(app);

    if !config_path.exists() {
        return HashMap::new();
    }

    let paths: Vec<String> = match std::fs::read_to_string(&config_path) {
        Ok(json) => match serde_json::from_str(&json) {
            Ok(paths) => paths,
            Err(e) => {
                eprintln!("Failed to parse databases config: {}", e);
                return HashMap::new();
            }
        },
        Err(e) => {
            eprintln!("Failed to read databases config: {}", e);
            return HashMap::new();
        }
    };

    let mut databases = HashMap::new();

    // Try to load each saved database
    for path in paths {
        match Database::from(&path).open() {
            Ok(db) => {
                let size_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

                let id = format!("{}", uuid::Uuid::new_v4());

                let entry = DatabaseEntry {
                    id: id.clone(),
                    path: path.clone(),
                    db: Arc::new(Mutex::new(db)),
                    size_bytes,
                };

                databases.insert(id, entry);
                eprintln!("[INFO] Restored database: {}", path);
            }
            Err(e) => {
                eprintln!("[WARN] Failed to restore database {}: {}", path, e);
            }
        }
    }

    databases
}

#[tauri::command]
fn list_monitors(state: tauri::State<'_, AppState>) -> Result<Vec<Monitor>, String> {
    let monitors = state.inner().monitors.lock().unwrap();
    Ok(monitors.values().cloned().collect())
}

#[tauri::command]
fn add_monitor(
    name: String,
    config: MonitorConfig,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<Monitor, String> {
    let id = Uuid::new_v4().to_string();

    let monitor_type = match &config {
        MonitorConfig::SystemLogs => MonitorType::SystemLogs,
        MonitorConfig::LogFile { .. } => MonitorType::LogFile,
        MonitorConfig::ApiEndpoint { .. } => MonitorType::ApiEndpoint,
        MonitorConfig::FilesystemScan { .. } => MonitorType::FilesystemScan,
        MonitorConfig::ZeekPacketCapture { .. } => MonitorType::ZeekPacketCapture,
    };

    let monitor = Monitor {
        id: id.clone(),
        name,
        monitor_type,
        config,
        enabled: false,
        stats: MonitorStatsData::default(),
        state: MonitorState::Paused,
        last_activity: None,
        zeek_pid: None,
    };

    state
        .inner()
        .monitors
        .lock()
        .unwrap()
        .insert(id, monitor.clone());

    // Save to disk
    let monitors = state.inner().monitors.lock().unwrap().clone();
    let _ = save_monitors_to_disk(&monitors, &app);

    // Emit monitors-updated event
    let _ = app.emit("monitors-updated", ());

    Ok(monitor)
}

#[tauri::command]
fn remove_monitor(
    id: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    // Don't allow removing if it's currently running
    {
        let monitors = state.inner().monitors.lock().unwrap();
        if let Some(monitor) = monitors.get(&id) {
            if monitor.enabled {
                return Err("Cannot remove a running monitor. Disable it first.".to_string());
            }
        }
    }

    state.inner().monitors.lock().unwrap().remove(&id);

    // Save to disk
    let monitors = state.inner().monitors.lock().unwrap().clone();
    let _ = save_monitors_to_disk(&monitors, &app);

    // Emit monitors-updated event
    let _ = app.emit("monitors-updated", ());

    Ok(())
}

#[tauri::command]
fn toggle_monitor(
    id: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<Monitor, String> {
    // Get the monitor and toggle its state
    let (should_start, monitor_clone) = {
        let mut monitors = state.inner().monitors.lock().unwrap();

        if let Some(monitor) = monitors.get_mut(&id) {
            monitor.enabled = !monitor.enabled;

            if monitor.enabled {
                monitor.state = MonitorState::Running;
                monitor.stats = MonitorStatsData::default(); // Reset stats
                (true, Some(monitor.clone()))
            } else {
                monitor.state = MonitorState::Paused;
                (false, None)
            }
        } else {
            return Err("Monitor not found".to_string());
        }
    }; // Lock is released here

    // If disabling, clean up the thread handle and Zeek process if applicable
    if !should_start {
        state.inner().monitor_threads.lock().unwrap().remove(&id);

        // If this is a Zeek monitor, kill the process and clean up config
        let zeek_pid = {
            let mut monitors = state.inner().monitors.lock().unwrap();
            if let Some(monitor) = monitors.get_mut(&id) {
                let pid = monitor.zeek_pid.take();
                // Clear log directory from config
                if let MonitorConfig::ZeekPacketCapture { zeek_log_dir, .. } = &mut monitor.config {
                    *zeek_log_dir = None;
                }
                pid
            } else {
                None
            }
        };

        // Kill Zeek process if we have a PID
        if let Some(pid) = zeek_pid {
            eprintln!("[INFO] Stopping Zeek process with PID: {}", pid);
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).output();

            // Remove from global zeek_pids tracking
            if let Some(state_ref) = app.try_state::<AppState>() {
                state_ref.zeek_pids.lock().unwrap().retain(|&p| p != pid);
            }
        }
    }

    // Start monitor if needed (outside of any locks)
    if should_start {
        if let Some(monitor) = monitor_clone {
            start_single_monitor(
                monitor,
                app.clone(),
                state.inner().databases.clone(),
                state.inner().monitors.clone(),
                state.inner().monitor_threads.clone(),
            );
        }
    }

    // Emit monitors-updated event
    let _ = app.emit("monitors-updated", ());

    // Save monitors state to disk
    let monitors = state.inner().monitors.lock().unwrap().clone();
    let _ = save_monitors_to_disk(&monitors, &app);

    // Get the final state to return
    let result = state
        .inner()
        .monitors
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .ok_or_else(|| "Monitor not found after toggle".to_string())?;

    Ok(result)
}

#[tauri::command]
fn get_monitor(id: String, state: tauri::State<'_, AppState>) -> Result<Monitor, String> {
    let monitors = state.inner().monitors.lock().unwrap();
    monitors
        .get(&id)
        .cloned()
        .ok_or_else(|| "Monitor not found".to_string())
}

#[tauri::command]
fn list_network_interfaces() -> Result<Vec<String>, String> {
    // Use ifconfig to list interfaces on macOS
    match Command::new("ifconfig").arg("-l").output() {
        Ok(output) if output.status.success() => {
            let interfaces_str = String::from_utf8_lossy(&output.stdout);
            let interfaces: Vec<String> = interfaces_str
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            Ok(interfaces)
        }
        Ok(_) => Err("Failed to list network interfaces".to_string()),
        Err(e) => Err(format!("Failed to execute ifconfig: {}", e)),
    }
}

#[tauri::command]
fn update_monitor(
    id: String,
    name: Option<String>,
    config: Option<MonitorConfig>,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<Monitor, String> {
    // Don't allow updating if it's currently running
    {
        let monitors = state.inner().monitors.lock().unwrap();
        if let Some(monitor) = monitors.get(&id) {
            if monitor.enabled {
                return Err("Cannot update a running monitor. Disable it first.".to_string());
            }
        } else {
            return Err("Monitor not found".to_string());
        }
    }

    // Update the monitor
    let updated_monitor = {
        let mut monitors = state.inner().monitors.lock().unwrap();
        if let Some(monitor) = monitors.get_mut(&id) {
            if let Some(new_name) = name {
                monitor.name = new_name;
            }
            if let Some(new_config) = config {
                // Update monitor type based on new config
                monitor.monitor_type = match &new_config {
                    MonitorConfig::SystemLogs => MonitorType::SystemLogs,
                    MonitorConfig::LogFile { .. } => MonitorType::LogFile,
                    MonitorConfig::ApiEndpoint { .. } => MonitorType::ApiEndpoint,
                    MonitorConfig::FilesystemScan { .. } => MonitorType::FilesystemScan,
                    MonitorConfig::ZeekPacketCapture { .. } => MonitorType::ZeekPacketCapture,
                };
                monitor.config = new_config;
            }
            monitor.clone()
        } else {
            return Err("Monitor not found".to_string());
        }
    };

    // Save to disk
    let monitors = state.inner().monitors.lock().unwrap().clone();
    let _ = save_monitors_to_disk(&monitors, &app);

    // Emit monitors-updated event
    let _ = app.emit("monitors-updated", ());

    Ok(updated_monitor)
}

// Process a batch of data with the Worker API and emit hits
fn process_batch_worker(
    worker: &mut Worker,
    _extractor: &Extractor,
    batch: &[u8],
    app: &tauri::AppHandle,
    source_name: &str,
    window_visible: bool,
    monitors: &Arc<Mutex<HashMap<String, Monitor>>>,
    monitor_id: &str,
    log_line: Option<&str>,
) {
    // Get baseline stats before processing
    let stats_before = worker.stats().clone();

    // Process the batch through worker
    let matches = match worker.process_bytes(batch) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Worker process error: {}", e);
            return;
        }
    };

    // Get stats after processing to see delta
    let stats_after = worker.stats();
    let candidates_delta = stats_after
        .candidates_tested
        .saturating_sub(stats_before.candidates_tested);

    // Removed: extracted-value emissions (panel removed)

    // Update monitor stats with batch results
    {
        let mut monitors_lock = monitors.lock().unwrap();
        if let Some(monitor) = monitors_lock.get_mut(monitor_id) {
            monitor.stats.items_extracted += candidates_delta as u64;
            monitor.stats.hits_found += matches.len() as u64;
            if !matches.is_empty() {
                monitor.last_activity = Some(Utc::now().format("%H:%M:%S").to_string());
            }
        }
    }

    // Process each match
    for m in matches {
        let matched_text = m.matched_text;
        let match_type = m.match_type;
        let db_id = m.database_id;

        let (data_values, matched_indicators): (Vec<serde_json::Value>, Vec<String>) =
            match m.result {
                MatchyQueryResult::Ip { data, prefix_len } => {
                    let indicator = format!("{}/{}", matched_text, prefix_len);
                    (
                        vec![serde_json::to_value(&data).unwrap_or(serde_json::Value::Null)],
                        vec![indicator],
                    )
                }
                MatchyQueryResult::Pattern { data, pattern_ids } => {
                    // Pattern IDs themselves serve as indicators - no need to resolve strings
                    let indicators: Vec<String> = pattern_ids
                        .iter()
                        .map(|id| format!("pattern_{}", id))
                        .collect();
                    let values = data
                        .iter()
                        .filter_map(|opt_dv| {
                            opt_dv.as_ref().and_then(|dv| serde_json::to_value(dv).ok())
                        })
                        .collect();
                    (values, indicators)
                }
                MatchyQueryResult::NotFound => continue,
            };

        let hit = Hit {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            matched_text: matched_text.clone(),
            match_type: match_type.clone(),
            source: source_name.to_string(),
            database_id: db_id.clone(),
            matched_indicators,
            data: data_values,
            log_line: log_line.map(|s| s.to_string()),
        };

        // Send notification (always)
        if let Err(e) = send_hit_notification(app, &hit) {
            eprintln!("Failed to send notification: {}", e);
        }

        // Emit to frontend (always emit hits)
        let _ = app.emit("hit", &hit);
    }
}

// Build a Worker and Extractor from current databases
fn build_worker_and_extractor(
    databases: &HashMap<String, DatabaseEntry>,
) -> Result<(Worker, Extractor), String> {
    let extractor = Extractor::new().map_err(|e| format!("Extractor error: {}", e))?;
    let extractor_clone = Extractor::new().map_err(|e| format!("Extractor error: {}", e))?;
    let mut builder = Worker::builder().extractor(extractor);

    // Add all databases to the worker (opens fresh mmap'd handles)
    for (id, entry) in databases.iter() {
        let db = Database::from(&entry.path)
            .open()
            .map_err(|e| format!("Failed to open {}: {}", entry.path, e))?;
        builder = builder.add_database(id.clone(), db);
    }

    Ok((builder.build(), extractor_clone))
}

// Start a single monitor (called when toggled on)
fn start_single_monitor(
    monitor: Monitor,
    app: tauri::AppHandle,
    databases: Arc<Mutex<HashMap<String, DatabaseEntry>>>,
    monitors: Arc<Mutex<HashMap<String, Monitor>>>,
    monitor_threads: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
) {
    let monitor_id = monitor.id.clone();

    // Check if a thread already exists for this monitor
    {
        let threads = monitor_threads.lock().unwrap();
        if threads.contains_key(&monitor_id) {
            eprintln!(
                "[DEBUG] Monitor {} already has a running thread",
                monitor_id
            );
            return;
        }
    }

    // Clone monitor_id before moving into closures
    let monitor_id_clone = monitor_id.clone();

    let handle = match monitor.monitor_type {
        MonitorType::SystemLogs => {
            std::thread::spawn(move || {
                // Build worker with current database snapshot
                let databases_snapshot = databases.lock().unwrap().clone();
                let (mut worker, extractor) = match build_worker_and_extractor(&databases_snapshot)
                {
                    Ok(w) => w,
                    Err(err) => {
                        eprintln!("Failed to build worker: {}", err);
                        return;
                    }
                };

                run_system_logs_monitor_worker(
                    app,
                    monitors,
                    monitor_id_clone,
                    &mut worker,
                    &extractor,
                );
            })
        }
        MonitorType::LogFile => {
            if let MonitorConfig::LogFile { path } = monitor.config {
                std::thread::spawn(move || {
                    // Build worker with current database snapshot
                    let databases_snapshot = databases.lock().unwrap().clone();
                    let (mut worker, extractor) =
                        match build_worker_and_extractor(&databases_snapshot) {
                            Ok(w) => w,
                            Err(err) => {
                                eprintln!("Failed to build worker: {}", err);
                                return;
                            }
                        };

                    run_log_file_monitor_worker(
                        app,
                        monitors,
                        monitor_id_clone,
                        path,
                        &mut worker,
                        &extractor,
                    );
                })
            } else {
                return; // Invalid config
            }
        }
        MonitorType::ZeekPacketCapture => {
            if let MonitorConfig::ZeekPacketCapture {
                interface,
                zeek_log_dir: _,
            } = monitor.config
            {
                std::thread::spawn(move || {
                    // Build worker with current database snapshot
                    let databases_snapshot = databases.lock().unwrap().clone();
                    let (mut worker, extractor) =
                        match build_worker_and_extractor(&databases_snapshot) {
                            Ok(w) => w,
                            Err(err) => {
                                eprintln!("Failed to build worker: {}", err);
                                return;
                            }
                        };

                    run_zeek_monitor_worker(
                        app,
                        monitors,
                        monitor_id_clone,
                        interface,
                        &mut worker,
                        &extractor,
                    );
                })
            } else {
                return; // Invalid config
            }
        }
        _ => {
            eprintln!(
                "[DEBUG] Monitor type {:?} not yet implemented",
                monitor.monitor_type
            );
            return;
        }
    };

    // Store thread handle
    monitor_threads
        .lock()
        .unwrap()
        .insert(monitor_id.clone(), handle);
}
fn run_log_file_monitor_worker(
    app: tauri::AppHandle,
    monitors: Arc<Mutex<HashMap<String, Monitor>>>,
    monitor_id: String,
    file_path: String,
    _worker: &mut Worker,
    _extractor: &Extractor,
) {
    eprintln!(
        "[DEBUG] Starting log file monitor for {} ({})",
        monitor_id, file_path
    );

    let app_state: tauri::State<AppState> = app.state();
    let source_name = std::path::Path::new(&file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&file_path)
        .to_string();

    // Register with global watcher
    if let Err(e) =
        app_state
            .file_watcher
            .add_file(PathBuf::from(&file_path), source_name, monitor_id.clone())
    {
        eprintln!("[ERROR] Failed to add file: {}", e);
        return;
    }

    // Wait for disable signal
    loop {
        let is_enabled = monitors
            .lock()
            .unwrap()
            .get(&monitor_id)
            .map(|m| m.enabled)
            .unwrap_or(false);

        if !is_enabled {
            let _ = app_state.file_watcher.remove_monitor(monitor_id.clone());
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    eprintln!("[DEBUG] Log file monitor {} exiting", monitor_id);
}

// Fallback per-file event-driven tailer used when the global watcher is unavailable
fn tail_file_with_notify_fallback(
    file_path: PathBuf,
    app: tauri::AppHandle,
    monitors: Arc<Mutex<HashMap<String, Monitor>>>,
    monitor_id: String,
    source_name: String,
    worker: &mut Worker,
    extractor: &Extractor,
) {
    // Open file and seek to end
    let mut file = match File::open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file {}: {}", file_path.display(), e);
            if let Ok(mut monitors_lock) = monitors.lock() {
                if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                    monitor.state = MonitorState::Error {
                        message: format!("Failed to open file: {}", e),
                    };
                }
            }
            return;
        }
    };

    let mut current_position = match file.seek(SeekFrom::End(0)) {
        Ok(pos) => pos,
        Err(e) => {
            eprintln!("Failed to seek to end: {}", e);
            return;
        }
    };

    let mut current_inode = match metadata(&file_path) {
        Ok(m) => m.ino(),
        Err(_) => 0,
    };

    // Set up file watcher
    let (tx, rx) = channel();
    let mut watcher = match notify::recommended_watcher(tx) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Failed to create watcher: {}", e);
            if let Ok(mut monitors_lock) = monitors.lock() {
                if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                    monitor.state = MonitorState::Error {
                        message: format!("Failed to create file watcher: {}", e),
                    };
                }
            }
            return;
        }
    };

    if let Err(e) = watcher.watch(&file_path, RecursiveMode::NonRecursive) {
        eprintln!("Failed to watch file: {}", e);
        if let Ok(mut monitors_lock) = monitors.lock() {
            if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                monitor.state = MonitorState::Error {
                    message: format!("Failed to watch file: {}", e),
                };
            }
        }
        return;
    }

    let mut last_stats_update = std::time::Instant::now();
    const STATS_UPDATE_INTERVAL_VISIBLE: std::time::Duration = std::time::Duration::from_secs(1);
    const STATS_UPDATE_INTERVAL_HIDDEN: std::time::Duration = std::time::Duration::from_secs(30);

    let mut window_visible = app
        .get_webview_window("main")
        .and_then(|w| w.is_visible().ok())
        .unwrap_or(false);
    let mut last_visibility_check = std::time::Instant::now();
    const VISIBILITY_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

    // Micro-batching state
    let mut buffer: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut pending_lines: usize = 0;
    const MAX_BATCH_LINES: usize = 200;
    const MAX_BATCH_BYTES: usize = 128 * 1024;
    const MAX_BATCH_AGE: std::time::Duration = std::time::Duration::from_millis(100);
    let mut last_flush = std::time::Instant::now();

    let mut read_buffer = vec![0u8; 64 * 1024];

    loop {
        // Check if monitor is still enabled
        let is_enabled = {
            let monitors_lock = monitors.lock().unwrap();
            monitors_lock
                .get(&monitor_id)
                .map(|m| m.enabled)
                .unwrap_or(false)
        };

        if !is_enabled {
            eprintln!("[DEBUG] File monitor {} disabled, exiting", monitor_id);
            break;
        }

        // Wait for file system event or timeout for batch flushing
        let timeout = if pending_lines > 0 {
            MAX_BATCH_AGE
                .checked_sub(last_flush.elapsed())
                .unwrap_or(std::time::Duration::from_millis(10))
        } else {
            std::time::Duration::from_secs(1)
        };

        match rx.recv_timeout(timeout) {
            Ok(Ok(event)) => {
                match event.kind {
                    EventKind::Modify(_) | EventKind::Create(_) => {
                        // Check for file rotation
                        if let Ok(m) = metadata(&file_path) {
                            let new_inode = m.ino();
                            if new_inode != current_inode {
                                eprintln!(
                                    "[DEBUG] File rotated, reopening: {}",
                                    file_path.display()
                                );
                                current_inode = new_inode;
                                match File::open(&file_path) {
                                    Ok(f) => {
                                        file = f;
                                        current_position = 0;
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to reopen after rotation: {}", e);
                                        std::thread::sleep(std::time::Duration::from_secs(1));
                                        continue;
                                    }
                                }
                            }
                        }

                        // Seek to last read position
                        if let Err(e) = file.seek(SeekFrom::Start(current_position)) {
                            eprintln!("Failed to seek: {}", e);
                            continue;
                        }

                        // Read all new data
                        loop {
                            match file.read(&mut read_buffer) {
                                Ok(0) => break, // EOF
                                Ok(n) => {
                                    current_position += n as u64;

                                    // Process lines
                                    let chunk = &read_buffer[..n];
                                    for line in chunk.split(|&b| b == b'\n') {
                                        if line.is_empty() {
                                            continue;
                                        }

                                        // Update line count
                                        {
                                            let mut monitors_lock = monitors.lock().unwrap();
                                            if let Some(monitor) =
                                                monitors_lock.get_mut(&monitor_id)
                                            {
                                                monitor.stats.lines_processed += 1;
                                            }
                                        }

                                        // Accumulate into batch
                                        buffer.extend_from_slice(line);
                                        buffer.push(b'\n');
                                        pending_lines += 1;

                                        // Check if we should flush
                                        let should_flush = pending_lines >= MAX_BATCH_LINES
                                            || buffer.len() >= MAX_BATCH_BYTES
                                            || last_flush.elapsed() >= MAX_BATCH_AGE;

                                        if should_flush {
                                            process_batch_worker(
                                                worker,
                                                extractor,
                                                &buffer,
                                                &app,
                                                &source_name,
                                                window_visible,
                                                &monitors,
                                                &monitor_id,
                                                None,
                                            );
                                            buffer.clear();
                                            pending_lines = 0;
                                            last_flush = std::time::Instant::now();
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Error reading file: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    EventKind::Remove(_) => {
                        eprintln!("[DEBUG] File removed: {}", file_path.display());
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                    _ => {}
                }
            }
            Ok(Err(e)) => {
                eprintln!("Watch error: {:?}", e);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Flush pending batch if needed
                if pending_lines > 0 && last_flush.elapsed() >= MAX_BATCH_AGE {
                    process_batch_worker(
                        worker,
                        extractor,
                        &buffer,
                        &app,
                        &source_name,
                        window_visible,
                        &monitors,
                        &monitor_id,
                        None,
                    );
                    buffer.clear();
                    pending_lines = 0;
                    last_flush = std::time::Instant::now();
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("[DEBUG] File watcher disconnected");
                break;
            }
        }

        // Update window visibility cache
        if last_visibility_check.elapsed() >= VISIBILITY_CHECK_INTERVAL {
            window_visible = app
                .get_webview_window("main")
                .and_then(|w| w.is_visible().ok())
                .unwrap_or(false);
            last_visibility_check = std::time::Instant::now();
        }

        // Emit periodic updates
        let interval = if window_visible {
            STATS_UPDATE_INTERVAL_VISIBLE
        } else {
            STATS_UPDATE_INTERVAL_HIDDEN
        };

        if last_stats_update.elapsed() >= interval {
            let _ = app.emit("databases-updated", ());
            let _ = app.emit("monitors-updated", ());
            last_stats_update = std::time::Instant::now();
        }
    }

    // Flush remaining buffer on exit
    if !buffer.is_empty() {
        process_batch_worker(
            worker,
            extractor,
            &buffer,
            &app,
            &source_name,
            window_visible,
            &monitors,
            &monitor_id,
            None,
        );
    }

    eprintln!("[DEBUG] File monitor {} exiting", monitor_id);
}

// Read the last N lines of a file (best-effort; returns None if file missing)
fn read_last_lines(path: &std::path::Path, max_lines: usize) -> Option<String> {
    use std::io::{BufRead, BufReader};
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);
    let mut ring = std::collections::VecDeque::with_capacity(max_lines);
    for line in reader.lines().flatten() {
        if ring.len() == max_lines {
            ring.pop_front();
        }
        ring.push_back(line);
    }
    Some(ring.into_iter().collect::<Vec<_>>().join("\n"))
}

// Dump Zeek stderr/stdout tails to our logs for diagnostics
fn log_zeek_diagnostics(temp_dir: &std::path::Path, max_lines: usize) {
    let stderr_log = temp_dir.join("zeek-stderr.log");
    let stdout_log = temp_dir.join("zeek-stdout.log");
    if let Some(tail) = read_last_lines(&stderr_log, max_lines) {
        eprintln!("[DEBUG] ===== zeek-stderr.log tail (last {} lines) =====\n{}\n==============================================", max_lines, tail);
    } else {
        eprintln!(
            "[DEBUG] zeek-stderr.log not available at {}",
            stderr_log.display()
        );
    }
    if let Some(tail) = read_last_lines(&stdout_log, max_lines) {
        eprintln!("[DEBUG] ===== zeek-stdout.log tail (last {} lines) =====\n{}\n==============================================", max_lines, tail);
    } else {
        eprintln!(
            "[DEBUG] zeek-stdout.log not available at {}",
            stdout_log.display()
        );
    }
}

fn run_system_logs_monitor_worker(
    app: tauri::AppHandle,
    monitors: Arc<Mutex<HashMap<String, Monitor>>>,
    monitor_id: String,
    worker: &mut Worker,
    extractor: &Extractor,
) {
    eprintln!("[DEBUG] Starting system logs monitor {}", monitor_id);
    // Check if monitor is still enabled
    let is_enabled = {
        let monitors_lock = monitors.lock().unwrap();
        monitors_lock
            .get(&monitor_id)
            .map(|m| m.enabled)
            .unwrap_or(false)
    };

    if !is_enabled {
        return;
    }

    // Start log stream process (macOS)
    let mut child = match Command::new("log")
        .args([
            "stream",
            "--style",
            "syslog",
            "--level",
            "info",
            "--color",
            "none",
            "--no-backtrace",
        ])
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("Failed to start log stream: {}", e);
            // Update monitor state to error
            if let Ok(mut monitors_lock) = monitors.lock() {
                if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                    monitor.state = MonitorState::Error {
                        message: format!("Failed to start log stream: {}", e),
                    };
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
            return;
        }
    };

    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);

    let mut last_stats_update = std::time::Instant::now();
    // Update UI more frequently when window is visible, less when hidden
    const STATS_UPDATE_INTERVAL_VISIBLE: std::time::Duration = std::time::Duration::from_secs(1);
    const STATS_UPDATE_INTERVAL_HIDDEN: std::time::Duration = std::time::Duration::from_secs(30);

    // Cache window visibility to avoid expensive checks on every line
    let mut window_visible = app
        .get_webview_window("main")
        .and_then(|w| w.is_visible().ok())
        .unwrap_or(false);
    let mut last_visibility_check = std::time::Instant::now();
    const VISIBILITY_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

    // Micro-batching state
    let mut buffer: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut pending_lines: usize = 0;
    const MAX_BATCH_LINES: usize = 200;
    const MAX_BATCH_BYTES: usize = 128 * 1024;
    const MAX_BATCH_AGE: std::time::Duration = std::time::Duration::from_millis(250);
    let mut last_flush = std::time::Instant::now();

    for line in reader.lines() {
        // Check if monitor is still enabled before processing each line
        let is_enabled = {
            let monitors_lock = monitors.lock().unwrap();
            monitors_lock
                .get(&monitor_id)
                .map(|m| m.enabled)
                .unwrap_or(false)
        };

        if !is_enabled {
            eprintln!(
                "[DEBUG] System logs monitor {} disabled, killing process",
                monitor_id
            );
            // Kill the process immediately
            let _ = child.kill();
            // Wait for it to terminate
            let _ = child.wait();
            break;
        }

        if let Ok(line) = line {
            // Update line count immediately
            {
                let mut monitors_lock = monitors.lock().unwrap();
                if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                    monitor.stats.lines_processed += 1;
                }
            }

            // Accumulate line into batch
            buffer.extend_from_slice(line.as_bytes());
            buffer.push(b'\n');
            pending_lines += 1;

            // Check if we should flush the batch
            let should_flush = pending_lines >= MAX_BATCH_LINES
                || buffer.len() >= MAX_BATCH_BYTES
                || last_flush.elapsed() >= MAX_BATCH_AGE;

            if should_flush {
                process_batch_worker(
                    worker,
                    extractor,
                    &buffer,
                    &app,
                    "System Logs",
                    window_visible,
                    &monitors,
                    &monitor_id,
                    None,
                );
                buffer.clear();
                pending_lines = 0;
                last_flush = std::time::Instant::now();
            }

            // Periodically update window visibility cache
            if last_visibility_check.elapsed() >= VISIBILITY_CHECK_INTERVAL {
                window_visible = app
                    .get_webview_window("main")
                    .and_then(|w| w.is_visible().ok())
                    .unwrap_or(false);
                last_visibility_check = std::time::Instant::now();
            }

            // Periodically emit updates (only if window is visible or enough time has passed)
            let interval = if window_visible {
                STATS_UPDATE_INTERVAL_VISIBLE
            } else {
                STATS_UPDATE_INTERVAL_HIDDEN
            };

            if last_stats_update.elapsed() >= interval {
                let _ = app.emit("databases-updated", ());
                let _ = app.emit("monitors-updated", ());
                last_stats_update = std::time::Instant::now();
            }
        }
    }

    // Flush remaining buffer on exit
    if !buffer.is_empty() {
        process_batch_worker(
            worker,
            extractor,
            &buffer,
            &app,
            "System Logs",
            window_visible,
            &monitors,
            &monitor_id,
            None,
        );
    }

    eprintln!("[DEBUG] System logs monitor {} exiting", monitor_id);
    std::thread::sleep(std::time::Duration::from_secs(1));
}

fn run_zeek_monitor_worker(
    app: tauri::AppHandle,
    monitors: Arc<Mutex<HashMap<String, Monitor>>>,
    monitor_id: String,
    interface: String,
    worker: &mut Worker,
    extractor: &Extractor,
) {
    eprintln!(
        "[DEBUG] Starting Zeek packet capture on interface {}",
        interface
    );

    // App state handle and restart policy
    let app_state: tauri::State<AppState> = app.state();
    let mut restart_backoff = std::time::Duration::from_secs(2);
    let mut restart_attempts: u32 = 0;

    // Check if monitor is still enabled
    let is_enabled = {
        let monitors_lock = monitors.lock().unwrap();
        monitors_lock
            .get(&monitor_id)
            .map(|m| m.enabled)
            .unwrap_or(false)
    };

    if !is_enabled {
        return;
    }

    // Check if we have an existing Zeek process and log directory
    let (existing_pid, existing_log_dir) = {
        let monitors_lock = monitors.lock().unwrap();
        if let Some(monitor) = monitors_lock.get(&monitor_id) {
            let pid = monitor.zeek_pid;
            let log_dir =
                if let MonitorConfig::ZeekPacketCapture { zeek_log_dir, .. } = &monitor.config {
                    zeek_log_dir.clone()
                } else {
                    None
                };
            (pid, log_dir)
        } else {
            (None, None)
        }
    };

    // Verify if the existing process is actually running
    // Use 'ps' instead of 'kill -0' because Zeek runs as root and we can't signal it without privileges
    let process_running = if let Some(pid) = existing_pid {
        let status = Command::new("ps")
            .args(["-p", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if status {
            eprintln!("[DEBUG] Found existing Zeek process with PID: {}", pid);
        } else {
            eprintln!("[DEBUG] Stored PID {} is no longer running", pid);
        }
        status
    } else {
        false
    };

    // If process is running and we have a log directory, resume tailing
    let (zeek_pid, temp_dir) = if process_running && existing_log_dir.is_some() {
        let log_dir = PathBuf::from(existing_log_dir.unwrap());
        eprintln!("[DEBUG] Resuming log monitoring from existing Zeek process");
        eprintln!("[DEBUG] Log directory: {}", log_dir.display());

        // Make sure the PID is tracked for cleanup on shutdown
        if let (Some(pid), Some(state)) = (existing_pid, app.try_state::<AppState>()) {
            let mut pids = state.zeek_pids.lock().unwrap();
            if !pids.contains(&pid) {
                pids.push(pid);
                eprintln!("[DEBUG] Added existing PID {} to cleanup tracking", pid);
            }
        }

        (existing_pid, log_dir)
    } else {
        // Need to start a new Zeek process
        eprintln!("[DEBUG] Starting new Zeek process");

        // Find zeek binary
        let zeek_path = match Command::new("which").arg("zeek").output() {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            }
            _ => {
                let error_msg = "Zeek not found. Install via: brew install zeek";
                eprintln!("[ERROR] {}", error_msg);
                if let Ok(mut monitors_lock) = monitors.lock() {
                    if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                        monitor.state = MonitorState::Error {
                            message: error_msg.to_string(),
                        };
                    }
                }
                return;
            }
        };

        eprintln!("[DEBUG] Found zeek at: {}", zeek_path);

        // Create temp directory for zeek logs
        let temp_dir = std::env::temp_dir().join(format!("matchy-zeek-{}", uuid::Uuid::new_v4()));
        if let Err(e) = create_dir_all(&temp_dir) {
            let error_msg = format!("Failed to create temp directory: {}", e);
            eprintln!("[ERROR] {}", error_msg);
            if let Ok(mut monitors_lock) = monitors.lock() {
                if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                    monitor.state = MonitorState::Error { message: error_msg };
                }
            }
            return;
        }

        let pid_file = temp_dir.join("zeek.pid");
        let stdout_log = temp_dir.join("zeek-stdout.log");
        let stderr_log = temp_dir.join("zeek-stderr.log");
        eprintln!(
            "[DEBUG] Zeek logs will be written to: {}",
            temp_dir.display()
        );

        // Launch Zeek in background and write PID, then force script to exit
        let zeek_command = format!(
            "sh -c 'cd {}; {} -i {} -C tuning/json-logs Log::flush_interval=100msec >{} 2>{} </dev/null & echo $! > {}' &",
            temp_dir.display(),
            zeek_path,
            interface,
            stdout_log.display(),
            stderr_log.display(),
            pid_file.display()
        );

        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            zeek_command.replace("\"", "\\\"")
        );

        eprintln!("[DEBUG] Starting elevated Zeek process...");
        eprintln!("[DEBUG] Command: {}", zeek_command);

        // Run osascript and wait for it to complete
        match Command::new("osascript").args(["-e", &script]).output() {
            Ok(output) if output.status.success() => {
                eprintln!("[DEBUG] Zeek started successfully");
            }
            Ok(output) => {
                let error_msg = format!(
                    "Failed to start Zeek: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                eprintln!("[ERROR] {}", error_msg);
                if let Ok(mut monitors_lock) = monitors.lock() {
                    if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                        monitor.state = MonitorState::Error { message: error_msg };
                    }
                }
                return;
            }
            Err(e) => {
                let error_msg = if e.kind() == std::io::ErrorKind::NotFound {
                    "osascript not found (required for privilege escalation on macOS)".to_string()
                } else {
                    format!("Failed to execute osascript: {}", e)
                };
                eprintln!("[ERROR] {}", error_msg);
                if let Ok(mut monitors_lock) = monitors.lock() {
                    if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                        monitor.state = MonitorState::Error { message: error_msg };
                    }
                }
                return;
            }
        }

        // Wait a moment for Zeek to start and write its PID
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Check for Zeek errors
        if let Ok(stderr_content) = std::fs::read_to_string(&stderr_log) {
            if !stderr_content.is_empty() {
                eprintln!("[DEBUG] Zeek stderr output:\n{}", stderr_content);
            }
        }

        // Read the Zeek PID from the file
        let new_pid = match std::fs::read_to_string(&pid_file) {
            Ok(pid_str) => {
                match pid_str.trim().parse::<i32>() {
                    Ok(pid) => {
                        eprintln!("[DEBUG] Zeek running with PID: {}", pid);
                        // Register PID for cleanup on shutdown
                        if let Some(state) = app.try_state::<AppState>() {
                            state.zeek_pids.lock().unwrap().push(pid);
                        }
                        Some(pid)
                    }
                    Err(e) => {
                        eprintln!("[WARN] Failed to parse Zeek PID from '{}': {}", pid_str, e);
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("[WARN] Failed to read Zeek PID file: {}", e);
                eprintln!("[WARN] Zeek may not have started or PID file not created yet");
                None
            }
        };

        // Store PID and log directory in monitor config
        if let Some(pid) = new_pid {
            if let Ok(mut monitors_lock) = monitors.lock() {
                if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                    monitor.zeek_pid = Some(pid);
                    if let MonitorConfig::ZeekPacketCapture { zeek_log_dir, .. } =
                        &mut monitor.config
                    {
                        *zeek_log_dir = Some(temp_dir.to_string_lossy().to_string());
                    }
                    // Save monitors to disk
                    let _ = save_monitors_to_disk(&monitors_lock, &app);
                }
            }
        }

        (new_pid, temp_dir)
    };

    // Make mutable so we can update on restart
    let mut zeek_pid = zeek_pid;
    let mut temp_dir = temp_dir;

    // Register all Zeek log files
    eprintln!(
        "[DEBUG] Registering Zeek logs with global watcher: {}",
        temp_dir.display()
    );

    if let Err(e) = app_state.file_watcher.add_directory_pattern(
        temp_dir.clone(),
        "*.log".to_string(),
        monitor_id.clone(),
    ) {
        eprintln!("[ERROR] Failed to watch Zeek logs: {}", e);
        if let Ok(mut monitors_lock) = monitors.lock() {
            if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                monitor.state = MonitorState::Error {
                    message: format!(
                        "Failed to watch Zeek logs via global watcher (will fallback): {}",
                        e
                    ),
                };
            }
        }
        // Fallback: directly tail key Zeek logs (conn/dns/ssl) if global watcher is unavailable
        let conn_log_path = temp_dir.join("conn.log");
        let dns_log_path = temp_dir.join("dns.log");
        let ssl_log_path = temp_dir.join("ssl.log");

        let mut watcher_threads = Vec::new();
        // Snapshot databases for building per-thread workers
        let databases_snapshot = {
            let app_state2: tauri::State<AppState> = app.state();
            let guard = app_state2.databases.lock().unwrap();
            guard.clone()
        };

        for (log_path, source_name) in [
            (conn_log_path, "Zeek:conn"),
            (dns_log_path, "Zeek:dns"),
            (ssl_log_path, "Zeek:ssl"),
        ] {
            let app_clone = app.clone();
            let monitors_clone = monitors.clone();
            let monitor_id_clone = monitor_id.clone();
            let databases_clone = databases_snapshot.clone();

            watcher_threads.push(std::thread::spawn(move || {
                // Build worker and extractor for this thread
                let (mut worker_local, extractor_local) =
                    match build_worker_and_extractor(&databases_clone) {
                        Ok(w) => w,
                        Err(err) => {
                            eprintln!("Failed to build worker for {}: {}", source_name, err);
                            return;
                        }
                    };

                // If the file doesn't exist yet, wait a little while for Zeek to create it
                let mut attempts = 0;
                while !log_path.exists() && attempts < 60 {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    attempts += 1;
                    let is_enabled = {
                        let ml = monitors_clone.lock().unwrap();
                        ml.get(&monitor_id_clone)
                            .map(|m| m.enabled)
                            .unwrap_or(false)
                    };
                    if !is_enabled {
                        return;
                    }
                }
                if !log_path.exists() {
                    eprintln!("[WARN] Zeek log file not created: {}", log_path.display());
                    return;
                }

                eprintln!("[DEBUG] Fallback monitoring of {}", log_path.display());
                tail_file_with_notify_fallback(
                    log_path,
                    app_clone,
                    monitors_clone,
                    monitor_id_clone,
                    source_name.to_string(),
                    &mut worker_local,
                    &extractor_local,
                );
            }));
        }

        // Detach: monitor loop below will continue doing health checks and cleanup on disable
    }

    // Wait for monitor to be disabled and perform health checks
    let mut last_health_check = std::time::Instant::now();
    const HEALTH_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

    loop {
        let is_enabled = {
            let monitors_lock = monitors.lock().unwrap();
            monitors_lock
                .get(&monitor_id)
                .map(|m| m.enabled)
                .unwrap_or(false)
        };

        if !is_enabled {
            eprintln!("[DEBUG] Zeek monitor {} disabled, cleaning up", monitor_id);

            // Unregister from global watcher
            let _ = app_state.file_watcher.remove_monitor(monitor_id.clone());

            // Kill the Zeek process using osascript (requires password prompt)
            if let Some(pid) = zeek_pid {
                eprintln!(
                    "[DEBUG] Requesting elevated privileges to kill Zeek PID {}",
                    pid
                );

                let script = format!(
                    "do shell script \"kill -9 {}\" with administrator privileges",
                    pid
                );

                match Command::new("osascript").args(["-e", &script]).output() {
                    Ok(output) if output.status.success() => {
                        eprintln!("[DEBUG] Successfully killed Zeek process {}", pid);
                    }
                    Ok(output) => {
                        eprintln!(
                            "[WARN] Failed to kill Zeek: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                    Err(e) => {
                        eprintln!("[WARN] Failed to execute kill command: {}", e);
                    }
                }

                // Remove from tracked PIDs
                if let Some(state) = app.try_state::<AppState>() {
                    state.zeek_pids.lock().unwrap().retain(|&p| p != pid);
                }
            } else {
                eprintln!("[WARN] No Zeek PID available, cannot kill process");
            }

            // Clean up temp directory
            if let Err(e) = std::fs::remove_dir_all(&temp_dir) {
                eprintln!("[WARN] Failed to remove temp directory: {}", e);
            }
            break;
        }

        // Periodic health check of Zeek process
        if last_health_check.elapsed() >= HEALTH_CHECK_INTERVAL {
            if let Some(pid) = zeek_pid {
                let is_alive = Command::new("ps")
                    .args(["-p", &pid.to_string()])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);

                if !is_alive {
                    eprintln!("[ERROR] Zeek process {} died unexpectedly!", pid);

                    // Log diagnostics: tail Zeek stderr/stdout
                    log_zeek_diagnostics(&temp_dir, 200);

                    // Update monitor state
                    if let Ok(mut monitors_lock) = monitors.lock() {
                        if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                            monitor.state = MonitorState::Error {
                                message: format!("Zeek process {} died unexpectedly", pid),
                            };
                        }
                    }

                    // Unregister from global watcher for this monitor
                    let _ = app_state.file_watcher.remove_monitor(monitor_id.clone());

                    // Remove from tracked PIDs
                    if let Some(state) = app.try_state::<AppState>() {
                        state.zeek_pids.lock().unwrap().retain(|&p| p != pid);
                    }

                    // Preserve old temp_dir for inspection
                    eprintln!(
                        "[WARN] Preserving Zeek log directory for diagnostics: {}",
                        temp_dir.display()
                    );

                    eprintln!("[DEBUG] Zeek process {} health check: OK", pid);
                }
            } else {
                // No PID: attempt to (re)start Zeek with backoff while enabled
                eprintln!("[WARN] Zeek not running (no PID). Attempting auto-start...");
                let zeek_path = match Command::new("which").arg("zeek").output() {
                    Ok(output) if output.status.success() => {
                        String::from_utf8_lossy(&output.stdout).trim().to_string()
                    }
                    _ => {
                        eprintln!("[ERROR] Zeek not found. Install via: brew install zeek");
                        last_health_check = std::time::Instant::now();
                        continue;
                    }
                };
                let new_temp_dir =
                    std::env::temp_dir().join(format!("matchy-zeek-{}", uuid::Uuid::new_v4()));
                if let Err(e) = create_dir_all(&new_temp_dir) {
                    eprintln!("[ERROR] Failed to create temp directory: {}", e);
                    last_health_check = std::time::Instant::now();
                    continue;
                }
                let pid_file = new_temp_dir.join("zeek.pid");
                let stdout_log = new_temp_dir.join("zeek-stdout.log");
                let stderr_log = new_temp_dir.join("zeek-stderr.log");
                let zeek_command = format!(
                    "sh -c 'cd {}; {} -i {} -C tuning/json-logs Log::flush_interval=100msec >{} 2>{} </dev/null & echo $! > {}' &",
                    new_temp_dir.display(),
                    zeek_path,
                    interface,
                    stdout_log.display(),
                    stderr_log.display(),
                    pid_file.display()
                );
                let script = format!(
                    "do shell script \"{}\" with administrator privileges",
                    zeek_command.replace("\"", "\\\"")
                );
                match Command::new("osascript").args(["-e", &script]).output() {
                    Ok(output) if output.status.success() => {}
                    Ok(output) => {
                        eprintln!(
                            "[ERROR] Failed to start Zeek: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        last_health_check = std::time::Instant::now();
                        continue;
                    }
                    Err(e) => {
                        eprintln!("[ERROR] Failed to execute osascript: {}", e);
                        last_health_check = std::time::Instant::now();
                        continue;
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
                if let Some(new_pid) = std::fs::read_to_string(&pid_file)
                    .ok()
                    .and_then(|s| s.trim().parse::<i32>().ok())
                {
                    eprintln!("[INFO] Zeek started with PID {}", new_pid);
                    if let Some(state) = app.try_state::<AppState>() {
                        let mut pids = state.zeek_pids.lock().unwrap();
                        if !pids.contains(&new_pid) {
                            pids.push(new_pid);
                        }
                    }
                    if let Ok(mut monitors_lock) = monitors.lock() {
                        if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                            monitor.zeek_pid = Some(new_pid);
                            if let MonitorConfig::ZeekPacketCapture { zeek_log_dir, .. } =
                                &mut monitor.config
                            {
                                *zeek_log_dir = Some(new_temp_dir.to_string_lossy().to_string());
                            }
                            monitor.state = MonitorState::Running;
                            let _ = save_monitors_to_disk(&monitors_lock, &app);
                        }
                    }
                    temp_dir = new_temp_dir;
                    zeek_pid = Some(new_pid);
                    if let Err(e) = app_state.file_watcher.add_directory_pattern(
                        temp_dir.clone(),
                        "*.log".to_string(),
                        monitor_id.clone(),
                    ) {
                        eprintln!("[ERROR] Failed to watch Zeek logs: {}", e);
                    }
                } else {
                    eprintln!(
                        "[ERROR] Zeek did not write PID; preserving logs at {}",
                        new_temp_dir.display()
                    );
                    log_zeek_diagnostics(&new_temp_dir, 100);
                }
            }
            last_health_check = std::time::Instant::now();
        }

        // Sleep briefly before checking again
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    eprintln!("[DEBUG] Zeek monitor {} exiting", monitor_id);
}

fn send_hit_notification(app: &tauri::AppHandle, hit: &Hit) -> Result<(), String> {
    use tauri_plugin_notification::NotificationExt;

    let title = format!("Intelligence Hit: {}", hit.match_type);
    let body = format!("Matched: {}\nSource: {}", hit.matched_text, hit.source);

    app.notification()
        .builder()
        .title(title)
        .body(body)
        .show()
        .map_err(|e| format!("Notification error: {}", e))?;

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let databases = Arc::new(Mutex::new(HashMap::new()));
    let monitors = Arc::new(Mutex::new(HashMap::new()));
    let monitor_threads = Arc::new(Mutex::new(HashMap::new()));
    let zeek_pids = Arc::new(Mutex::new(Vec::new()));
    let _zeek_pids_clone = zeek_pids.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .setup(move |app| {
            // Start the global file watcher BEFORE creating AppState
            let file_watcher_handle = start_global_file_watcher(
                app.handle().clone(),
                databases.clone(),
                monitors.clone(),
            );

            // Set up AppState with file watcher
            app.manage(AppState {
                databases: databases.clone(),
                monitors: monitors.clone(),
                monitor_threads: monitor_threads.clone(),
                zeek_pids: zeek_pids.clone(),
                file_watcher: Arc::new(file_watcher_handle),
            });

            // Load databases from disk
            let loaded_databases = load_databases_from_disk(&app.handle());
            let database_count = loaded_databases.len();
            *databases.lock().unwrap() = loaded_databases;

            // Notify global watcher to reload databases
            let app_state: tauri::State<AppState> = app.state();
            if database_count > 0 {
                eprintln!(
                    "[DEBUG] Notifying global watcher of {} loaded databases",
                    database_count
                );
                let _ = app_state.file_watcher.reload_databases();
            }

            // Load monitors from disk
            let mut loaded_monitors = load_monitors_from_disk(&app.handle());

            // Ensure we always have a system logs monitor
            let has_system_monitor = loaded_monitors
                .values()
                .any(|m| m.monitor_type == MonitorType::SystemLogs);

            if !has_system_monitor {
                let system_monitor_id = Uuid::new_v4().to_string();
                let system_monitor = Monitor {
                    id: system_monitor_id.clone(),
                    name: "System Logs".to_string(),
                    monitor_type: MonitorType::SystemLogs,
                    config: MonitorConfig::SystemLogs,
                    enabled: false,
                    stats: MonitorStatsData::default(),
                    state: MonitorState::Paused,
                    last_activity: None,
                    zeek_pid: None,
                };
                loaded_monitors.insert(system_monitor_id, system_monitor);
            }

            // Collect monitors that were enabled (save their enabled state)
            let monitors_to_start: Vec<Monitor> = loaded_monitors
                .values()
                .filter(|m| m.enabled)
                .cloned()
                .collect();

            // Reset runtime state (stats, last_activity) but preserve enabled status and Zeek process info
            for monitor in loaded_monitors.values_mut() {
                // Keep the enabled flag, zeek_pid, and zeek_log_dir as-is (so we can resume existing Zeek processes)
                monitor.stats = MonitorStatsData::default();
                monitor.state = if monitor.enabled {
                    MonitorState::Running
                } else {
                    MonitorState::Paused
                };
                monitor.last_activity = None;
                // zeek_pid and config.zeek_log_dir are intentionally preserved
            }

            *monitors.lock().unwrap() = loaded_monitors;

            // Restart monitors that were enabled
            if !monitors_to_start.is_empty() {
                eprintln!(
                    "[INFO] Restarting {} monitor(s) that were enabled",
                    monitors_to_start.len()
                );
                let app_handle = app.handle().clone();
                let databases_clone = databases.clone();
                let monitors_clone = monitors.clone();
                let monitor_threads_clone = monitor_threads.clone();

                // Start monitors in a separate thread to avoid blocking setup
                std::thread::spawn(move || {
                    // Small delay to ensure app is fully initialized
                    std::thread::sleep(std::time::Duration::from_millis(500));

                    for monitor in monitors_to_start {
                        eprintln!("[INFO] Starting monitor: {} ({})", monitor.name, monitor.id);
                        start_single_monitor(
                            monitor,
                            app_handle.clone(),
                            databases_clone.clone(),
                            monitors_clone.clone(),
                            monitor_threads_clone.clone(),
                        );
                    }

                    // Emit event to update frontend
                    let _ = app_handle.emit("monitors-updated", ());
                });
            }

            // Setup system tray
            setup_tray(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Hide window instead of closing
                window.hide().unwrap();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            pick_file,
            pick_any_file,
            load_database,
            unload_database,
            list_databases,
            query_databases,
            list_monitors,
            add_monitor,
            remove_monitor,
            toggle_monitor,
            get_monitor,
            update_monitor,
            list_network_interfaces,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(move |app, event| {
            match event {
                tauri::RunEvent::Reopen { .. } => {
                    // Show window when dock icon is clicked (macOS)
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. } => {
                    // Note: We intentionally do NOT kill Zeek processes on app exit
                    // Zeek runs as root and we can't kill it without prompting for password again
                    // Instead, we leave it running and resume monitoring on next app start
                    // Users can disable the Zeek monitor in the app if they want to stop packet capture
                    eprintln!("[INFO] App exiting. Zeek processes will continue running.");
                    eprintln!(
                        "[INFO] To stop packet capture, disable the Zeek monitor in the app."
                    );
                }
                _ => {}
            }
        });
}

fn setup_tray(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::menu::{MenuBuilder, MenuItemBuilder};
    use tauri::tray::TrayIconBuilder;
    use tauri::Manager;

    let show_item = MenuItemBuilder::with_id("show", "Show Window").build(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

    let menu = MenuBuilder::new(app)
        .item(&show_item)
        .separator()
        .item(&quit_item)
        .build()?;

    // Load custom tray icon - fail if not found
    let icon_path = app
        .path()
        .resolve("icons/tray-icon.png", tauri::path::BaseDirectory::Resource)?;

    eprintln!("[DEBUG] Loading tray icon from: {:?}", icon_path);

    let tray_icon = tauri::image::Image::from_path(&icon_path)
        .map_err(|e| format!("Failed to load tray icon from {:?}: {}", icon_path, e))?;

    TrayIconBuilder::new()
        .icon(tray_icon)
        .menu(&menu)
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;

    Ok(())
}
