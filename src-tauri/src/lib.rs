use matchy::{Database, QueryResult as MatchyQueryResult};
use matchy::extractor::{PatternExtractor, ExtractedItem};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tauri::{Emitter, Manager};
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
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

struct AppState {
    databases: Arc<Mutex<HashMap<String, DatabaseEntry>>>,
    monitoring_enabled: Arc<Mutex<bool>>,
    monitor_stats: Arc<Mutex<MonitorStats>>,
}

// Holds references to tray menu items we may want to update dynamically
#[derive(Clone)]
struct TrayState {
    monitor_item: tauri::menu::MenuItem<tauri::Wry>,
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct MonitorStatus {
    enabled: bool,
    database_count: usize,
    lines_processed: u64,
    items_extracted: u64,
    last_activity: String,
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
fn load_database(path: String, state: tauri::State<'_, AppState>) -> Result<DatabaseInfo, String> {
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
            };
            
            state.inner().databases.lock().unwrap().insert(id, entry);
            
            Ok(info)
        }
        Err(e) => Err(format!("Failed to open database: {}", e)),
    }
}

#[tauri::command]
fn unload_database(id: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.inner().databases.lock().unwrap().remove(&id);
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
                        .filter_map(|id| db.get_pattern_string(*id))
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
fn set_monitoring(enabled: bool, state: tauri::State<'_, AppState>, app: tauri::AppHandle) -> Result<MonitorStatus, String> {
    *state.inner().monitoring_enabled.lock().unwrap() = enabled;
    let db_count = state.inner().databases.lock().unwrap().len();
    
    // Reset stats when enabling
    if enabled {
        *state.inner().monitor_stats.lock().unwrap() = MonitorStats::default();
    }

    // Update tray menu label if available
    update_tray_monitor_label(&app, enabled);
    
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

fn process_log_line(line: &str, databases: &HashMap<String, DatabaseEntry>, extractor: &PatternExtractor) -> (Vec<Hit>, u64) {
    let mut hits = Vec::new();
    let mut extracted_count = 0u64;
    
    for match_item in extractor.extract_from_line(line.as_bytes()) {
        extracted_count += 1;
        let (query_str, match_type) = match &match_item.item {
            ExtractedItem::Domain(s) => (s.to_string(), "Domain"),
            ExtractedItem::Email(s) => (s.to_string(), "Email"),
            ExtractedItem::Ipv4(ip) => (ip.to_string(), "IPv4"),
            ExtractedItem::Ipv6(ip) => (ip.to_string(), "IPv6"),
        };
        
        for entry in databases.values() {
            let db = entry.db.lock().unwrap();
            if let Ok(Some(result)) = db.lookup(&query_str) {
                let (data_values, matched_indicators): (Vec<serde_json::Value>, Vec<String>) = match result {
                    MatchyQueryResult::Ip { data, prefix_len } => {
                        let indicator = format!("{}/{}", query_str, prefix_len);
                        (vec![serde_json::to_value(&data).unwrap_or(serde_json::Value::Null)], vec![indicator])
                    }
                    MatchyQueryResult::Pattern { data, pattern_ids } => {
                        eprintln!("[DEBUG] Pattern match for '{}': pattern_ids = {:?}, data.len() = {}", 
                                 query_str, pattern_ids, data.len());
                        let indicators: Vec<String> = pattern_ids
                            .iter()
                            .filter_map(|id| db.get_pattern_string(*id))
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
                
                eprintln!("[DEBUG] After match: matched_indicators = {:?}, data_values.len() = {}",
                         matched_indicators, data_values.len());
                
                // Show hit if we have indicators (even without data)
                if !matched_indicators.is_empty() {
                    hits.push(Hit {
                        id: Uuid::new_v4().to_string(),
                        timestamp: Utc::now().to_rfc3339(),
                        matched_text: query_str.clone(),
                        match_type: match_type.to_string(),
                        source: "log".to_string(),
                        database_id: entry.id.clone(),
                        matched_indicators,
                        data: data_values,
                    });
                }
            }
        }
    }
    
    (hits, extracted_count)
}

fn start_log_monitoring(app: tauri::AppHandle, state: Arc<Mutex<HashMap<String, DatabaseEntry>>>, 
                       monitoring: Arc<Mutex<bool>>, stats: Arc<Mutex<MonitorStats>>) {
    std::thread::spawn(move || {
        // Create extractor once per thread
        let extractor = match PatternExtractor::new() {
            Ok(e) => e,
            Err(err) => {
                eprintln!("Failed to create pattern extractor: {}", err);
                return;
            }
        };
        
        loop {
            // Check if monitoring is enabled
            if !*monitoring.lock().unwrap() {
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
            
            // Start log stream process (macOS)
            let mut child = match Command::new("log")
                .args(["stream", "--style", "syslog", "--level", "info"])
                .stdout(Stdio::piped())
                .spawn()
            {
                Ok(child) => child,
                Err(e) => {
                    eprintln!("Failed to start log stream: {}", e);
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    continue;
                }
            };
            
            let stdout = child.stdout.take().unwrap();
            let reader = BufReader::new(stdout);
            
            let mut last_stats_update = std::time::Instant::now();
            const STATS_UPDATE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
            
            for line in reader.lines() {
                if !*monitoring.lock().unwrap() {
                    let _ = child.kill();
                    break;
                }
                
                if let Ok(line) = line {
                    // Update line count
                    {
                        let mut s = stats.lock().unwrap();
                        s.lines_processed += 1;
                    }
                    
                    let databases = state.lock().unwrap().clone();
                    let (hits, extracted_count) = process_log_line(&line, &databases, &extractor);
                    
                    // Update extraction count
                    if extracted_count > 0 {
                        let mut s = stats.lock().unwrap();
                        s.items_extracted += extracted_count;
                        s.last_activity = Utc::now().format("%H:%M:%S").to_string();
                    }
                    
                    for hit in hits {
                        eprintln!("[DEBUG] Found hit: {} (type: {}, indicators: {:?})", 
                                 hit.matched_text, hit.match_type, hit.matched_indicators);
                        
                        // Send notification
                        if let Err(e) = send_hit_notification(&app, &hit) {
                            eprintln!("Failed to send notification: {}", e);
                        }
                        
                        // Emit to frontend
                        match app.emit("hit", &hit) {
                            Ok(_) => eprintln!("[DEBUG] Successfully emitted hit to frontend"),
                            Err(e) => eprintln!("[DEBUG] Failed to emit hit: {}", e),
                        }
                    }
                    
                    // Periodically emit database stats update (every second)
                    if last_stats_update.elapsed() >= STATS_UPDATE_INTERVAL {
                        let _ = app.emit("databases-updated", ());
                        last_stats_update = std::time::Instant::now();
                    }
                }
            }
            
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    });
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
    
    let app_state = AppState {
        databases: databases.clone(),
        monitoring_enabled: monitoring_enabled.clone(),
        monitor_stats: monitor_stats.clone(),
    };
    
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .manage(app_state)
        .setup(move |app| {
            // Setup system tray
            setup_tray(app)?;
            
            // Start log monitoring in background
            start_log_monitoring(
                app.handle().clone(),
                databases.clone(),
                monitoring_enabled.clone(),
                monitor_stats.clone(),
            );
            
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
            load_database,
            unload_database,
            list_databases,
            query_databases,
            set_monitoring,
            get_monitor_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn setup_tray(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::tray::TrayIconBuilder;
    use tauri::menu::{MenuBuilder, MenuItemBuilder};
    
    let show_item = MenuItemBuilder::with_id("show", "Show Window").build(app)?;
let monitor_item = MenuItemBuilder::with_id("monitor", "Start Monitoring").build(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;
    
    // Store the monitor menu item so we can update the label later
    app.manage(TrayState { monitor_item: monitor_item.clone() });
    
    let menu = MenuBuilder::new(app)
        .item(&show_item)
        .item(&monitor_item)
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
                "monitor" => {
                    if let Some(state) = app.try_state::<AppState>() {
                        let mut enabled = state.inner().monitoring_enabled.lock().unwrap();
                        *enabled = !*enabled;

                        // Update tray label
                        update_tray_monitor_label(app, *enabled);
                        
                        // Emit event to frontend
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.emit("monitoring-changed", *enabled);
                        }
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

fn update_tray_monitor_label(app: &tauri::AppHandle, enabled: bool) {
    if let Some(tray_state) = app.try_state::<TrayState>() {
let text = if enabled { "Stop Monitoring" } else { "Start Monitoring" };
        let _ = tray_state.monitor_item.set_text(text);
    }
}
