use matchy::{Database, QueryResult as MatchyQueryResult};
use matchy::extractor::Extractor;
use matchy::processing::Worker;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::thread::JoinHandle;
use tauri::{Emitter, Manager};
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::fs::{File, metadata, create_dir_all};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use uuid::Uuid;
use chrono::Utc;

#[derive(Clone)]
struct DatabaseEntry {
    id: String,
    path: String,
    db: Arc<Mutex<Database>>,
    size_bytes: u64,
}

#[derive(Clone, Default)]
struct MonitorStats {
    lines_processed: u64,
    items_extracted: u64,
    last_activity: String,
}

// New monitor architecture
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum MonitorType {
    SystemLogs,
    LogFile,
    ApiEndpoint,
    FilesystemScan,
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
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct MonitorStatsData {
    lines_processed: u64,
    items_extracted: u64,
    hits_found: u64,
}

struct AppState {
    databases: Arc<Mutex<HashMap<String, DatabaseEntry>>>,
    // Legacy monitoring fields (kept for backward compatibility during migration)
    monitoring_enabled: Arc<Mutex<bool>>,
    monitor_stats: Arc<Mutex<MonitorStats>>,
    // New monitors system
    monitors: Arc<Mutex<HashMap<String, Monitor>>>,
    // Thread handles for active monitors
    monitor_threads: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
struct MonitorStatus {
    enabled: bool,
    database_count: usize,
    lines_processed: u64,
    items_extracted: u64,
    last_activity: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ExtractedValue {
    value: String,
    item_type: String,
    timestamp: String,
    matched: bool,
}

#[tauri::command]
async fn pick_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    
    let file_path = app.dialog()
        .file()
        .add_filter("Matchy Database", &["mxy"])
        .blocking_pick_file();
    
    Ok(file_path.map(|p| p.to_string()))
}

#[tauri::command]
async fn pick_any_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    
    let file_path = app.dialog()
        .file()
        .blocking_pick_file();
    
    Ok(file_path.map(|p| p.to_string()))
}

#[tauri::command]
fn load_database(path: String, state: tauri::State<'_, AppState>, app: tauri::AppHandle) -> Result<DatabaseInfo, String> {
    match Database::from(&path).open() {
        Ok(db) => {
            let size_bytes = std::fs::metadata(&path)
                .map(|m| m.len())
                .unwrap_or(0);
            
            let size_human = format_size(size_bytes);
            let stats = db.stats();
            let mode = format!("{:?}", db.mode());
            
            // Get indicator counts
            let ip_count = db.ip_count();
            let literal_count = db.literal_count();
            let glob_count = db.glob_count();
            let total_count = ip_count + literal_count + glob_count;
            
            // Extract description and build_epoch from metadata
            let (description, build_epoch) = db.metadata()
                .and_then(|meta| {
                    if let matchy::data_section::DataValue::Map(map) = meta {
                        let description = if let Some(matchy::data_section::DataValue::Map(desc_map)) = map.get("description") {
                            // Try English first
                            if let Some(matchy::data_section::DataValue::String(desc)) = desc_map.get("en") {
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
            
            Ok(info)
        }
        Err(e) => Err(format!("Failed to open database: {}", e)),
    }
}

#[tauri::command]
fn unload_database(id: String, state: tauri::State<'_, AppState>, app: tauri::AppHandle) -> Result<(), String> {
    state.inner().databases.lock().unwrap().remove(&id);
    
    // Save updated database paths to disk
    let databases = state.inner().databases.lock().unwrap().clone();
    let _ = save_database_paths_to_disk(&databases, &app);
    
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
        let (description, build_epoch) = db.metadata()
            .and_then(|meta| {
                if let matchy::data_section::DataValue::Map(map) = meta {
                    let description = if let Some(matchy::data_section::DataValue::Map(desc_map)) = map.get("description") {
                        // Try English first
                        if let Some(matchy::data_section::DataValue::String(desc)) = desc_map.get("en") {
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
fn query_databases(query: String, state: tauri::State<'_, AppState>, app: tauri::AppHandle) -> Result<Vec<Hit>, String> {
    let databases = state.inner().databases.lock().unwrap();
    let mut hits = Vec::new();
    
    for entry in databases.values() {
        let db = entry.db.lock().unwrap();
        if let Ok(Some(result)) = db.lookup(&query) {
            let (data_values, matched_indicators): (Vec<serde_json::Value>, Vec<String>) = match result {
                MatchyQueryResult::Ip { data, prefix_len } => {
                    let indicator = format!("{}/{}", query, prefix_len);
                    (vec![serde_json::to_value(&data).unwrap_or(serde_json::Value::Null)], vec![indicator])
                }
                MatchyQueryResult::Pattern { data, pattern_ids } => {
                    let indicators: Vec<String> = pattern_ids
                        .iter()
                        .map(|id| db.get_pattern_string(*id).unwrap_or_else(|| query.clone()))
                        .collect();
                    let values = data.iter()
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

#[tauri::command]
fn set_monitoring(enabled: bool, state: tauri::State<'_, AppState>, _app: tauri::AppHandle) -> Result<MonitorStatus, String> {
    *state.inner().monitoring_enabled.lock().unwrap() = enabled;
    let db_count = state.inner().databases.lock().unwrap().len();
    
    // Reset stats when enabling
    if enabled {
        *state.inner().monitor_stats.lock().unwrap() = MonitorStats::default();
    }
    
    let stats = state.inner().monitor_stats.lock().unwrap();
    Ok(MonitorStatus {
        enabled,
        database_count: db_count,
        lines_processed: stats.lines_processed,
        items_extracted: stats.items_extracted,
        last_activity: stats.last_activity.clone(),
    })
}

#[tauri::command]
fn get_monitor_status(state: tauri::State<'_, AppState>) -> Result<MonitorStatus, String> {
    let enabled = *state.inner().monitoring_enabled.lock().unwrap();
    let db_count = state.inner().databases.lock().unwrap().len();
    let stats = state.inner().monitor_stats.lock().unwrap();
    
    Ok(MonitorStatus {
        enabled,
        database_count: db_count,
        lines_processed: stats.lines_processed,
        items_extracted: stats.items_extracted,
        last_activity: stats.last_activity.clone(),
    })
}

// New monitor management commands
// Helper functions for monitor persistence
fn get_monitors_config_path(app: &tauri::AppHandle) -> PathBuf {
    let app_data = app.path().app_data_dir()
        .expect("Failed to get app data directory");
    app_data.join("monitors.json")
}

fn get_databases_config_path(app: &tauri::AppHandle) -> PathBuf {
    let app_data = app.path().app_data_dir()
        .expect("Failed to get app data directory");
    app_data.join("databases.json")
}

fn save_monitors_to_disk(monitors: &HashMap<String, Monitor>, app: &tauri::AppHandle) -> Result<(), String> {
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
        Ok(json) => {
            match serde_json::from_str(&json) {
                Ok(monitors) => monitors,
                Err(e) => {
                    eprintln!("Failed to parse monitors config: {}", e);
                    HashMap::new()
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read monitors config: {}", e);
            HashMap::new()
        }
    }
}

fn save_database_paths_to_disk(databases: &HashMap<String, DatabaseEntry>, app: &tauri::AppHandle) -> Result<(), String> {
    let config_path = get_databases_config_path(app);
    
    // Ensure parent directory exists
    if let Some(parent) = config_path.parent() {
        create_dir_all(parent).map_err(|e| format!("Failed to create config directory: {}", e))?;
    }
    
    // Extract just the paths to save
    let paths: Vec<String> = databases.values()
        .map(|entry| entry.path.clone())
        .collect();
    
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
        Ok(json) => {
            match serde_json::from_str(&json) {
                Ok(paths) => paths,
                Err(e) => {
                    eprintln!("Failed to parse databases config: {}", e);
                    return HashMap::new();
                }
            }
        }
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
                let size_bytes = std::fs::metadata(&path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                
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
fn add_monitor(name: String, config: MonitorConfig, state: tauri::State<'_, AppState>, app: tauri::AppHandle) -> Result<Monitor, String> {
    let id = Uuid::new_v4().to_string();
    
    let monitor_type = match &config {
        MonitorConfig::SystemLogs => MonitorType::SystemLogs,
        MonitorConfig::LogFile { .. } => MonitorType::LogFile,
        MonitorConfig::ApiEndpoint { .. } => MonitorType::ApiEndpoint,
        MonitorConfig::FilesystemScan { .. } => MonitorType::FilesystemScan,
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
    };
    
    state.inner().monitors.lock().unwrap().insert(id, monitor.clone());
    
    // Save to disk
    let monitors = state.inner().monitors.lock().unwrap().clone();
    let _ = save_monitors_to_disk(&monitors, &app);
    
    // Emit monitors-updated event
    let _ = app.emit("monitors-updated", ());
    
    Ok(monitor)
}

#[tauri::command]
fn remove_monitor(id: String, state: tauri::State<'_, AppState>, app: tauri::AppHandle) -> Result<(), String> {
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
fn toggle_monitor(id: String, state: tauri::State<'_, AppState>, app: tauri::AppHandle) -> Result<Monitor, String> {
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
    
    // If disabling, try to clean up the thread handle
    if !should_start {
        state.inner().monitor_threads.lock().unwrap().remove(&id);
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
    let result = state.inner().monitors.lock().unwrap()
        .get(&id)
        .cloned()
        .ok_or_else(|| "Monitor not found after toggle".to_string())?;
    
    Ok(result)
}

#[tauri::command]
fn get_monitor(id: String, state: tauri::State<'_, AppState>) -> Result<Monitor, String> {
    let monitors = state.inner().monitors.lock().unwrap();
    monitors.get(&id)
        .cloned()
        .ok_or_else(|| "Monitor not found".to_string())
}

#[tauri::command]
fn update_monitor(id: String, name: Option<String>, config: Option<MonitorConfig>, state: tauri::State<'_, AppState>, app: tauri::AppHandle) -> Result<Monitor, String> {
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
    extractor: &Extractor,
    batch: &[u8],
    app: &tauri::AppHandle,
    source_name: &str,
    window_visible: bool,
    monitors: &Arc<Mutex<HashMap<String, Monitor>>>,
    monitor_id: &str,
) {
    // Get baseline stats before processing
    let stats_before = worker.stats().clone();

    // Process the batch through worker
    let matches = match worker.process_bytes(batch) {
        Ok(m) => {
            if !m.is_empty() {
                eprintln!("[DEBUG] Worker found {} database matches", m.len());
                for match_result in &m {
                    eprintln!("[DEBUG]   - Match: {} ({})", match_result.matched_text, match_result.match_type);
                }
            }
            m
        }
        Err(e) => {
            eprintln!("Worker process error: {}", e);
            return;
        }
    };

    // Get stats after processing to see delta
    let stats_after = worker.stats();
    let candidates_delta = stats_after.candidates_tested.saturating_sub(stats_before.candidates_tested);

    // Emit extracted values for all candidates (only if window is visible)
    if window_visible && candidates_delta > 0 {
        // Extract all items from the batch
        let extracted_matches = extractor.extract_from_chunk(batch);
        for item in extracted_matches {
            let (item_type, value) = match &item.item {
                matchy::extractor::ExtractedItem::Ipv4(addr) => ("IPv4", addr.to_string()),
                matchy::extractor::ExtractedItem::Ipv6(addr) => ("IPv6", addr.to_string()),
                matchy::extractor::ExtractedItem::Domain(s) => ("Domain", s.to_string()),
                matchy::extractor::ExtractedItem::Email(s) => ("Email", s.to_string()),
                matchy::extractor::ExtractedItem::Hash(hash_type, s) => {
                    let type_name = match hash_type {
                        matchy::extractor::HashType::Md5 => "MD5",
                        matchy::extractor::HashType::Sha1 => "SHA1",
                        matchy::extractor::HashType::Sha256 => "SHA256",
                        matchy::extractor::HashType::Sha384 => "SHA384",
                    };
                    (type_name, s.to_string())
                },
                matchy::extractor::ExtractedItem::Bitcoin(s) => ("Bitcoin", s.to_string()),
                matchy::extractor::ExtractedItem::Ethereum(s) => ("Ethereum", s.to_string()),
                matchy::extractor::ExtractedItem::Monero(s) => ("Monero", s.to_string()),
            };
            
            // Extracted values are just candidates - they're not hits yet
            // The matched flag should always be false here
            let extracted = ExtractedValue {
                value,
                item_type: item_type.to_string(),
                timestamp: Utc::now().to_rfc3339(),
                matched: false,
            };
            let _ = app.emit("extracted-value", extracted);
        }
    }

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

        let (data_values, matched_indicators): (Vec<serde_json::Value>, Vec<String>) = match m.result {
            MatchyQueryResult::Ip { data, prefix_len } => {
                let indicator = format!("{}/{}", matched_text, prefix_len);
                (vec![serde_json::to_value(&data).unwrap_or(serde_json::Value::Null)], vec![indicator])
            }
            MatchyQueryResult::Pattern { data, pattern_ids } => {
                // Pattern IDs themselves serve as indicators - no need to resolve strings
                let indicators: Vec<String> = pattern_ids.iter()
                    .map(|id| format!("pattern_{}", id))
                    .collect();
                let values = data.iter()
                    .filter_map(|opt_dv| opt_dv.as_ref().and_then(|dv| serde_json::to_value(dv).ok()))
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
            log_line: None,
        };

        eprintln!("[DEBUG] Hit: {} ({})", hit.matched_text, hit.match_type);

        // Send notification (always)
        if let Err(e) = send_hit_notification(app, &hit) {
            eprintln!("Failed to send notification: {}", e);
        }

        // Emit to frontend (only if window is visible)
        if window_visible {
            let _ = app.emit("hit", &hit);
        }
    }
}

// Build a Worker and Extractor from current databases
fn build_worker_and_extractor(databases: &HashMap<String, DatabaseEntry>) -> Result<(Worker, Extractor), String> {
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
            eprintln!("[DEBUG] Monitor {} already has a running thread", monitor_id);
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
                let (mut worker, extractor) = match build_worker_and_extractor(&databases_snapshot) {
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
                    let (mut worker, extractor) = match build_worker_and_extractor(&databases_snapshot) {
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
                })            } else {
                return; // Invalid config
            }
        }
        _ => {
            eprintln!("[DEBUG] Monitor type {:?} not yet implemented", monitor.monitor_type);
            return;
        }
    };
    
    // Store thread handle
    monitor_threads.lock().unwrap().insert(monitor_id.clone(), handle);
}

fn run_log_file_monitor_worker(
    app: tauri::AppHandle,
    monitors: Arc<Mutex<HashMap<String, Monitor>>>,
    monitor_id: String,
    file_path: String,
    worker: &mut Worker,
    extractor: &Extractor,
) {
    eprintln!("[DEBUG] Starting log file monitor for {} ({})", monitor_id, file_path);
    // Check if monitor is still enabled
    let is_enabled = {
        let monitors_lock = monitors.lock().unwrap();
        monitors_lock.get(&monitor_id)
            .map(|m| m.enabled)
            .unwrap_or(false)
    };
    
    if !is_enabled {
        return;
    }
    
    // Open the file and seek to end
    let mut file = match File::open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open log file {}: {}", file_path, e);
            if let Ok(mut monitors_lock) = monitors.lock() {
                if let Some(monitor) = monitors_lock.get_mut(&monitor_id) {
                    monitor.state = MonitorState::Error { 
                        message: format!("Failed to open file: {}", e) 
                    };
                }
            }
            return;
        }
    };
    
    // Seek to end of file (we only read new content)
    let _ = file.seek(SeekFrom::End(0));
    
    // Get initial inode for rotation detection
    let mut current_inode = match metadata(&file_path) {
        Ok(m) => m.ino(),
        Err(_) => 0,
    };
    
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    
    let mut last_stats_update = std::time::Instant::now();
    // Update UI more frequently when window is visible, less when hidden
    const STATS_UPDATE_INTERVAL_VISIBLE: std::time::Duration = std::time::Duration::from_secs(1);
    const STATS_UPDATE_INTERVAL_HIDDEN: std::time::Duration = std::time::Duration::from_secs(30);
    
    // Cache window visibility to avoid expensive checks on every line
    let mut window_visible = app.get_webview_window("main")
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
    
    loop {
        // Check if monitor is still enabled
        let is_enabled = {
            let monitors_lock = monitors.lock().unwrap();
            monitors_lock.get(&monitor_id)
                .map(|m| m.enabled)
                .unwrap_or(false)
        };
        
        if !is_enabled {
            eprintln!("[DEBUG] Log file monitor {} disabled, exiting", monitor_id);
            break;
        }
        
        // Check for file rotation (inode changed)
        if let Ok(m) = metadata(&file_path) {
            let new_inode = m.ino();
            if new_inode != current_inode {
                eprintln!("[DEBUG] Log file rotated, reopening: {}", file_path);
                current_inode = new_inode;
                
                // Reopen file
                match File::open(&file_path) {
                    Ok(f) => {
                        file = f;
                        let reader = BufReader::new(file);
                        lines = reader.lines();
                    }
                    Err(e) => {
                        eprintln!("Failed to reopen log file after rotation: {}", e);
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        continue;
                    }
                }
            }
        }
        
        // Try to read a line
        match lines.next() {
            Some(Ok(line)) => {
                let source_name = std::path::Path::new(&file_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&file_path);

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
                    process_batch_worker(worker, extractor, &buffer, &app, source_name, window_visible, &monitors, &monitor_id);
                    buffer.clear();
                    pending_lines = 0;
                    last_flush = std::time::Instant::now();
                }
                
                // Periodically update window visibility cache
                if last_visibility_check.elapsed() >= VISIBILITY_CHECK_INTERVAL {
                    window_visible = app.get_webview_window("main")
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
            Some(Err(_)) => {
                // Error reading, wait a bit
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            None => {
                // No more data available, wait and retry
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
    
    // Flush remaining buffer on exit
    if !buffer.is_empty() {
        let source_name = std::path::Path::new(&file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&file_path);
        process_batch_worker(worker, extractor, &buffer, &app, source_name, window_visible, &monitors, &monitor_id);
    }
    
    eprintln!("[DEBUG] Log file monitor {} exiting", monitor_id);
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
        monitors_lock.get(&monitor_id)
            .map(|m| m.enabled)
            .unwrap_or(false)
    };
    
    if !is_enabled {
        return;
    }
    
    // Start log stream process (macOS)
    let mut child = match Command::new("log")
        .args(["stream", "--style", "syslog", "--level", "info", "--color", "none", "--no-backtrace"])
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
                        message: format!("Failed to start log stream: {}", e) 
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
    let mut window_visible = app.get_webview_window("main")
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
            monitors_lock.get(&monitor_id)
                .map(|m| m.enabled)
                .unwrap_or(false)
        };
        
        if !is_enabled {
            eprintln!("[DEBUG] System logs monitor {} disabled, killing process", monitor_id);
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
                process_batch_worker(worker, extractor, &buffer, &app, "System Logs", window_visible, &monitors, &monitor_id);
                buffer.clear();
                pending_lines = 0;
                last_flush = std::time::Instant::now();
            }
            
            // Periodically update window visibility cache
            if last_visibility_check.elapsed() >= VISIBILITY_CHECK_INTERVAL {
                window_visible = app.get_webview_window("main")
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
        process_batch_worker(worker, extractor, &buffer, &app, "System Logs", window_visible, &monitors, &monitor_id);
    }

    eprintln!("[DEBUG] System logs monitor {} exiting", monitor_id);
    std::thread::sleep(std::time::Duration::from_secs(1));
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
    let monitoring_enabled = Arc::new(Mutex::new(false));
    let monitor_stats = Arc::new(Mutex::new(MonitorStats::default()));
    
    // Initialize with empty monitors for now - will load in setup
    let monitors = Arc::new(Mutex::new(HashMap::new()));
    
    
    let monitor_threads = Arc::new(Mutex::new(HashMap::new()));
    
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState {
            databases: databases.clone(),
            monitoring_enabled: monitoring_enabled.clone(),
            monitor_stats: monitor_stats.clone(),
            monitors: monitors.clone(),
            monitor_threads: monitor_threads.clone(),
        })
        .setup(move |app| {
            // Load databases from disk
            let loaded_databases = load_databases_from_disk(&app.handle());
            *databases.lock().unwrap() = loaded_databases;
            
            // Load monitors from disk
            let mut loaded_monitors = load_monitors_from_disk(&app.handle());
            
            // Ensure we always have a system logs monitor
            let has_system_monitor = loaded_monitors.values()
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
                };
                loaded_monitors.insert(system_monitor_id, system_monitor);
            }
            
            // Collect monitors that were enabled (save their enabled state)
            let monitors_to_start: Vec<Monitor> = loaded_monitors.values()
                .filter(|m| m.enabled)
                .cloned()
                .collect();
            
            // Reset runtime state (stats, last_activity) but preserve enabled status
            for monitor in loaded_monitors.values_mut() {
                // Keep the enabled flag as-is
                monitor.stats = MonitorStatsData::default();
                monitor.state = if monitor.enabled { MonitorState::Running } else { MonitorState::Paused };
                monitor.last_activity = None;
            }
            
            *monitors.lock().unwrap() = loaded_monitors;
            
            // Restart monitors that were enabled
            if !monitors_to_start.is_empty() {
                eprintln!("[INFO] Restarting {} monitor(s) that were enabled", monitors_to_start.len());
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
            set_monitoring,
            get_monitor_status,
            // New monitor commands
            list_monitors,
            add_monitor,
            remove_monitor,
            toggle_monitor,
            get_monitor,
            update_monitor,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            if let tauri::RunEvent::Reopen { .. } = event {
                // Show window when dock icon is clicked (macOS)
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        });
}

fn setup_tray(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::tray::TrayIconBuilder;
    use tauri::menu::{MenuBuilder, MenuItemBuilder};
    
    let show_item = MenuItemBuilder::with_id("show", "Show Window").build(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
    
    let menu = MenuBuilder::new(app)
        .item(&show_item)
        .separator()
        .item(&quit_item)
        .build()?;
    
    TrayIconBuilder::new()
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&menu)
        .on_menu_event(move |app, event| {
            match event.id().as_ref() {
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
            }
        })
        .build(app)?;
    
    Ok(())
}

