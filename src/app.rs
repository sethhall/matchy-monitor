use leptos::task::spawn_local;
use web_sys;
use leptos::{ev::SubmitEvent, prelude::*};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], catch)]
    async fn invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;
    
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"])]
    async fn listen(event: &str, handler: &JsValue) -> JsValue;
    
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    
    #[wasm_bindgen(js_namespace = console)]
    fn error(s: &str);
}

// Helper functions for localStorage
fn get_local_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn load_collapse_state(key: &str, default: bool) -> bool {
    let result = get_local_storage()
        .and_then(|storage| storage.get_item(key).ok()?)
        .and_then(|value| {
            log(&format!("Loading state for {}: {:?}", key, value));
            value.parse::<bool>().ok()
        })
        .unwrap_or_else(|| {
            log(&format!("Using default for {}: {}", key, default));
            default
        });
    log(&format!("Final state for {}: {}", key, result));
    result
}

fn save_collapse_state(key: &str, value: bool) {
    if let Some(storage) = get_local_storage() {
        match storage.set_item(key, &value.to_string()) {
            Ok(_) => log(&format!("Saved state for {}: {}", key, value)),
            Err(e) => error(&format!("Failed to save state for {}: {:?}", key, e)),
        }
    } else {
        error(&format!("localStorage not available for {}", key));
    }
}

fn load_hits_from_storage() -> Vec<Hit> {
    get_local_storage()
        .and_then(|storage| storage.get_item("hits").ok()?)
        .and_then(|json| {
            log(&format!("Loading hits from storage: {} bytes", json.len()));
            serde_json::from_str(&json).ok()
        })
        .unwrap_or_else(|| {
            log("No hits found in storage, starting fresh");
            Vec::new()
        })
}

fn save_hits_to_storage(hits: &[Hit]) {
    if let Some(storage) = get_local_storage() {
        match serde_json::to_string(hits) {
            Ok(json) => {
                match storage.set_item("hits", &json) {
                    Ok(_) => log(&format!("Saved {} hits to storage", hits.len())),
                    Err(e) => error(&format!("Failed to save hits to storage: {:?}", e)),
                }
            }
            Err(e) => error(&format!("Failed to serialize hits: {:?}", e)),
        }
    } else {
        error("localStorage not available for hits");
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DatabaseStatsInfo {
    total_queries: u64,
    queries_with_match: u64,
    cache_hit_rate: f64,
    match_rate: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IndicatorCounts {
    total: usize,
    ip: usize,
    literal: usize,
    glob: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Hit {
    id: String,
    timestamp: String,
    matched_text: String,
    match_type: String,
    source: String,
    database_id: String,
    matched_indicators: Vec<String>,
    data: Vec<serde_json::Value>,
    log_line: Option<String>,
}



// New monitor structures matching backend
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum MonitorState {
    Running,
    Paused,
    Scheduled,
    Completed,
    Error { message: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct MonitorStatsData {
    lines_processed: u64,
    items_extracted: u64,
    hits_found: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Monitor {
    id: String,
    name: String,
    monitor_type: MonitorTypeInfo,
    config: MonitorConfigInfo,
    enabled: bool,
    stats: MonitorStatsData,
    state: MonitorState,
    last_activity: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum MonitorConfigInfo {
    SystemLogs,
    LogFile { path: String },
    ApiEndpoint { url: String, interval_secs: u64 },
    FilesystemScan { path: String, recursive: bool },
    ZeekPacketCapture { interface: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum MonitorTypeInfo {
    SystemLogs,
    LogFile,
    ApiEndpoint,
    FilesystemScan,
    ZeekPacketCapture,
}

#[component]
pub fn App() -> impl IntoView {
    let (databases, set_databases) = signal::<Vec<DatabaseInfo>>(Vec::new());
    let (hits, set_hits) = signal::<Vec<Hit>>(load_hits_from_storage());
    let (query, _set_query) = signal(String::new());
    let (_status, set_status) = signal(String::new());
    let (monitors, set_monitors) = signal::<Vec<Monitor>>(Vec::new());
    let (show_add_modal, set_show_add_modal) = signal(false);
    let (show_edit_modal, set_show_edit_modal) = signal(false);
    let (edit_monitor_id, set_edit_monitor_id) = signal(String::new());
    let (selected_monitor_type, set_selected_monitor_type) = signal("log_file".to_string());
    let (monitor_name, set_monitor_name) = signal(String::new());
    let (log_file_path, set_log_file_path) = signal(String::new());
    let (network_interfaces, set_network_interfaces) = signal::<Vec<String>>(Vec::new());
    let (selected_interface, set_selected_interface) = signal(String::new());
    let (show_error_modal, set_show_error_modal) = signal(false);
    let (error_message, set_error_message) = signal(String::new());
    let (databases_expanded, set_databases_expanded) = signal(load_collapse_state("databases_expanded", true));
    let (monitors_expanded, set_monitors_expanded) = signal(load_collapse_state("monitors_expanded", true));
    
    // Load databases and monitors on mount
    Effect::new(move |_| {
        spawn_local(async move {
            if let Ok(res) = invoke("list_databases", JsValue::NULL).await {
                if let Ok(dbs) = serde_wasm_bindgen::from_value::<Vec<DatabaseInfo>>(res) {
                    set_databases.set(dbs);
                }
            }
        });
        
        spawn_local(async move {
            if let Ok(res) = invoke("list_monitors", JsValue::NULL).await {
                if let Ok(mons) = serde_wasm_bindgen::from_value::<Vec<Monitor>>(res) {
                    set_monitors.set(mons);
                }
            }
        });
    });
    
    // Listen for hit events
    Effect::new(move |_| {
        spawn_local(async move {
            let closure = Closure::wrap(Box::new(move |event: JsValue| {
                log("Received hit event");
                match js_sys::Reflect::get(&event, &"payload".into()) {
                    Ok(payload) => {
                        match serde_wasm_bindgen::from_value::<Hit>(payload) {
                            Ok(hit) => {
                                log(&format!("Parsed hit: {:?}", hit));
                                set_hits.update(|hits| {
                                    hits.insert(0, hit);
                                    // Keep more hits now - 500 instead of 100
                                    if hits.len() > 500 {
                                        hits.truncate(500);
                                    }
                                    // Save to localStorage after updating
                                    save_hits_to_storage(hits);
                                });
                            }
                            Err(e) => {
                                error(&format!("Failed to parse hit: {:?}", e));
                            }
                        }
                    }
                    Err(e) => {
                        error(&format!("Failed to get payload: {:?}", e));
                    }
                }
            }) as Box<dyn FnMut(JsValue)>);
            
            let _ = listen("hit", closure.as_ref()).await;
            closure.forget();
        });
    });
    
    
    // Listen for database updates
    Effect::new(move |_| {
        spawn_local(async move {
            let closure = Closure::wrap(Box::new(move |_event: JsValue| {
                // Refresh database list
                spawn_local(async move {
                    if let Ok(res) = invoke("list_databases", JsValue::NULL).await {
                        if let Ok(dbs) = serde_wasm_bindgen::from_value::<Vec<DatabaseInfo>>(res) {
                            set_databases.set(dbs);
                        }
                    }
                });
            }) as Box<dyn FnMut(JsValue)>);
            
            let _ = listen("databases-updated", closure.as_ref()).await;
            closure.forget();
        });
    });
    
    // Listen for monitor updates
    Effect::new(move |_| {
        spawn_local(async move {
            let closure = Closure::wrap(Box::new(move |_event: JsValue| {
                // Refresh monitors list
                spawn_local(async move {
                    if let Ok(res) = invoke("list_monitors", JsValue::NULL).await {
                        if let Ok(mons) = serde_wasm_bindgen::from_value::<Vec<Monitor>>(res) {
                            set_monitors.set(mons);
                        }
                    }
                });
            }) as Box<dyn FnMut(JsValue)>);
            
            let _ = listen("monitors-updated", closure.as_ref()).await;
            closure.forget();
        });
    });
    
    let add_database = move |_| {
        spawn_local(async move {
            match invoke("pick_file", JsValue::NULL).await {
                Ok(res) => {
                    if let Ok(Some(path)) = serde_wasm_bindgen::from_value::<Option<String>>(res) {
                        let path_clone = path.clone();
                        let args = serde_wasm_bindgen::to_value(&serde_json::json!({"path": path})).unwrap();
                        
                        // Now invoke can fail properly with Result
                        match invoke("load_database", args).await {
                            Ok(result_value) => {
                                // Parse the successful result
                                match serde_wasm_bindgen::from_value::<DatabaseInfo>(result_value) {
                                    Ok(info) => {
                                        set_databases.update(|dbs| dbs.push(info));
                                    }
                                    Err(e) => {
                                        let error_msg = format!("Failed to parse database info: {:?}", e);
                                        error(&error_msg);
                                        set_error_message.set(error_msg);
                                        set_show_error_modal.set(true);
                                    }
                                }
                            }
                            Err(err) => {
                                // Error from Tauri command - extract the message
                                let error_msg = err.as_string().unwrap_or_else(|| {
                                    js_sys::Reflect::get(&err, &"message".into())
                                        .ok()
                                        .and_then(|v| v.as_string())
                                        .unwrap_or_else(|| "Unknown error occurred while loading database".to_string())
                                });
                                
                                error(&format!("Failed to load {}: {}", path_clone, error_msg));
                                set_error_message.set(error_msg);
                                set_show_error_modal.set(true);
                            }
                        }
                    }
                }
                Err(e) => {
                    error(&format!("Failed to pick file: {:?}", e));
                }
            }
        });
    };
    
    let remove_database = move |id: String| {
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&serde_json::json!({"id": id})).unwrap();
            if invoke("unload_database", args).await.is_ok() {
                set_databases.update(|dbs| dbs.retain(|db| db.id != id));
            }
        });
    };
    
    let _run_query = move |_ev: SubmitEvent| {
        _ev.prevent_default();
        let q = query.get_untracked();
        if q.is_empty() { return; }
        
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&serde_json::json!({"query": q})).unwrap();
            if let Ok(res) = invoke("query_databases", args).await {
                if let Ok(new_hits) = serde_wasm_bindgen::from_value::<Vec<Hit>>(res) {
                    if new_hits.is_empty() {
                        set_status.set(format!("No hits for: {}", q));
                    } else {
                        set_status.set(format!("Found {} hits", new_hits.len()));
                        set_hits.update(|hits| {
                            for hit in new_hits.into_iter().rev() {
                                hits.insert(0, hit);
                            }
                            // Keep more hits now - 500 instead of 100
                            if hits.len() > 500 {
                                hits.truncate(500);
                            }
                            // Save to localStorage after updating
                            save_hits_to_storage(hits);
                        });
                    }
                }
            }
        });
    };
    
    view! {
        <main style="display: flex; flex-direction: column; height: 100vh; background: #f8f9fa; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; position: relative;">
            // Drag region header  
            <div class="titlebar" style="height: 32px; background: #f9fafb; border-bottom: 1px solid #e5e7eb; flex-shrink: 0;">
                <div data-tauri-drag-region style="width: 100%; height: 100%;"></div>
            </div>
            
            <div style="display: flex; flex: 1; overflow: hidden;">
                // Sidebar - Database List and Monitors
                <div style="width: 280px; background: #f9fafb; border-right: 1px solid #e5e7eb; overflow-y: auto; padding: 1rem; display: flex; flex-direction: column; gap: 1.5rem;">
                    // Databases section
                    <div>
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                            <h2 style="margin: 0; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.8px; color: #6b7280; font-weight: 700; cursor: pointer; user-select: none; flex: 1;"
                                on:click=move |_| {
                                    set_databases_expanded.update(|expanded| {
                                        *expanded = !*expanded;
                                        save_collapse_state("databases_expanded", *expanded);
                                    });
                                }>
                                {move || if databases_expanded.get() { "▼ Databases" } else { "▶ Databases" }}
                            </h2>
                            <div style="display: flex; align-items: center; gap: 0.375rem;">
                                <span style="background: #3b82f6; color: white; border-radius: 10px; padding: 0.25rem 0.5rem; font-size: 0.875rem; font-weight: 600; min-width: 1.25rem; text-align: center;">
                                    {move || databases.get().len()}
                                </span>
                                <button
                                    on:click=add_database
                                    style="background: none; border: none; color: #3b82f6; cursor: pointer; padding: 0.25rem 0.5rem; font-size: 1rem; line-height: 1; transition: all 0.15s; border-radius: 4px; font-weight: 600;"
                                    onmouseover="this.style.background='#eff6ff'; this.style.color='#2563eb'"
                                    onmouseout="this.style.background='none'; this.style.color='#3b82f6'"
                                    title="Add Database"
                                >
                                    "+"
                                </button>
                            </div>
                        </div>
                    <div style=move || format!(
                        "overflow: hidden; transition: max-height 0.33s ease-in-out; {}",
                        if databases_expanded.get() {
                            "max-height: 2000px;"
                        } else {
                            "max-height: 0;"
                        }
                    )>
                    {move || {
                        let dbs = databases.get();
                        if dbs.is_empty() {
                            view! {
                                <div style="text-align: center; padding: 2rem 0; color: #9ca3af;">
                                    <div style="font-size: 2rem; margin-bottom: 0.5rem;">"📁"</div>
                                    <p style="font-size: 0.8125rem; margin: 0;">"No databases loaded"</p>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                                    {dbs.into_iter().map(|db| {
                                        let id = db.id.clone();
                                        let filename = std::path::Path::new(&db.path)
                                            .file_name()
                                            .and_then(|n| n.to_str())
                                            .unwrap_or(&db.path)
                                            .to_string();
                                        
                                        view! {
                                            <div style="padding: 0.625rem; background: white; border-radius: 6px; font-size: 0.75rem; transition: all 0.2s; border: 1px solid #e5e7eb; box-shadow: 0 1px 2px rgba(0,0,0,0.02);"
                                                 onmouseover="this.style.boxShadow='0 2px 8px rgba(0,0,0,0.08)'; this.style.borderColor='#d1d5db'"
                                                 onmouseout="this.style.boxShadow='0 1px 2px rgba(0,0,0,0.02)'; this.style.borderColor='#e5e7eb'">
                                                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.375rem;">
                                                    <div style="font-weight: 600; word-break: break-all; color: #111827; line-height: 1.3; font-size: 0.8125rem;">
                                                        {filename}
                                                    </div>
                                                    <button
                                                        on:click=move |_| remove_database(id.clone())
                                                        style="background: none; border: none; color: #9ca3af; cursor: pointer; padding: 0; font-size: 1.125rem; line-height: 1; transition: all 0.15s; margin-left: 0.5rem; flex-shrink: 0; border-radius: 3px;"
                                                        onmouseover="this.style.color='#ef4444'; this.style.background='#fee2e2'"
                                                        onmouseout="this.style.color='#9ca3af'; this.style.background='none'"
                                                    >
                                                        "×"
                                                    </button>
                                                </div>
                                                
                                                // Show description if available
                                                {db.description.as_ref().map(|desc| {
                                                    view! {
                                                        <div style="margin-bottom: 0.5rem; padding: 0.375rem; background: #f9fafb; border-radius: 4px; border-left: 3px solid #3b82f6;">
                                                            <p style="margin: 0; color: #374151; font-size: 0.6875rem; line-height: 1.4; font-style: italic;">
                                                                {desc.clone()}
                                                            </p>
                                                        </div>
                                                    }.into_any()
                                                }).unwrap_or_else(|| view! { <></> }.into_any())}
                                                
                                                // Show build date if available
                                                {db.build_epoch.map(|epoch| {
                                                    // Format Unix timestamp to human-readable date
                                                    let date = chrono::DateTime::from_timestamp(epoch as i64, 0)
                                                        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
                                                        .unwrap_or_else(|| "Unknown date".to_string());
                                                    
                                                    view! {
                                                        <div style="margin-bottom: 0.5rem; color: #6b7280; font-size: 0.6875rem;">
                                                            <span style="font-weight: 500;">"Built: "</span>
                                                            <span>{date}</span>
                                                        </div>
                                                    }.into_any()
                                                }).unwrap_or_else(|| view! { <></> }.into_any())}
                                                
                                                // Compact stats in two rows
                                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
                                                    <span style="color: #6b7280; font-size: 0.6875rem;">{db.size_human.clone()}</span>
                                                    <span style="color: #6b7280; font-size: 0.6875rem;">
                                                        <span style="font-weight: 600; color: #111827;">{format!("{}", db.indicator_counts.total)}</span>
                                                        <span>" indicators"</span>
                                                    </span>
                                                </div>
                                                
                                                <div style="display: flex; justify-content: space-between; align-items: center; color: #6b7280; font-size: 0.6875rem;">
                                                    <span>{format!("{}/{}", db.stats.queries_with_match, db.stats.total_queries)}</span>
                                                    <span style="color: #3b82f6; font-weight: 600;">{format!("{:.0}%", db.stats.match_rate * 100.0)}</span>
                                                </div>
                                            </div>
                                        }
                                    }).collect::<Vec<_>>()}
                                </div>
                            }.into_any()
                        }
                    }}
                    </div>
                    </div>
                    
                    // Monitors section
                    <div>
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                            <h2 style="margin: 0; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.8px; color: #6b7280; font-weight: 700; cursor: pointer; user-select: none; flex: 1;"
                                on:click=move |_| {
                                    set_monitors_expanded.update(|expanded| {
                                        *expanded = !*expanded;
                                        save_collapse_state("monitors_expanded", *expanded);
                                    });
                                }>
                                {move || if monitors_expanded.get() { "▼ Monitors" } else { "▶ Monitors" }}
                            </h2>
                            <div style="display: flex; align-items: center; gap: 0.375rem;">
                                <span style="background: #3b82f6; color: white; border-radius: 10px; padding: 0.25rem 0.5rem; font-size: 0.875rem; font-weight: 600; min-width: 1.25rem; text-align: center;">
                                    {move || monitors.get().len()}
                                </span>
                                <button
                                    on:click=move |_| set_show_add_modal.set(true)
                                    style="background: none; border: none; color: #3b82f6; cursor: pointer; padding: 0.25rem 0.5rem; font-size: 1rem; line-height: 1; transition: all 0.15s; border-radius: 4px; font-weight: 600;"
                                    onmouseover="this.style.background='#eff6ff'; this.style.color='#2563eb'"
                                    onmouseout="this.style.background='none'; this.style.color='#3b82f6'"
                                    title="Add Monitor"
                                >
                                    "+"
                                </button>
                            </div>
                        </div>
                        
                    <div style=move || format!(
                        "overflow: hidden; transition: max-height 0.33s ease-in-out; {}",
                        if monitors_expanded.get() {
                            "max-height: 2000px;"
                        } else {
                            "max-height: 0;"
                        }
                    )>
                        {move || {
                            let monitor_list = monitors.get();
                            if monitor_list.is_empty() {
                                view! {
                                    <div style="text-align: center; padding: 2rem 0; color: #9ca3af;">
                                        <div style="font-size: 2rem; margin-bottom: 0.5rem;">"📊"</div>
                                        <p style="font-size: 0.8125rem; margin: 0;">"No monitors"</p>
                                    </div>
                                }.into_any()
                            } else {
                                view! {
                                    <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                                        {monitor_list.into_iter().map(|monitor| {
                                            let monitor_id = monitor.id.clone();
                                            let monitor_id_for_remove = monitor.id.clone();
                                            let monitor_id_for_edit = monitor.id.clone();
                                            let monitor_for_edit = monitor.clone();
                                            let is_system = monitor.monitor_type == MonitorTypeInfo::SystemLogs;
                                            
                                            let toggle_fn = move |_| {
                                                let id = monitor_id.clone();
                                                spawn_local(async move {
                                                    let args = serde_wasm_bindgen::to_value(&serde_json::json!({"id": id})).unwrap();
                                                    let _ = invoke("toggle_monitor", args).await.ok();
                                                });
                                            };
                                            
                                            let remove_fn = move |_| {
                                                let id = monitor_id_for_remove.clone();
                                                spawn_local(async move {
                                                    let args = serde_wasm_bindgen::to_value(&serde_json::json!({"id": id})).unwrap();
                                                    let _ = invoke("remove_monitor", args).await.ok();
                                                });
                                            };
                                            
                                            let edit_fn = move |_| {
                                                if !is_system && !monitor_for_edit.enabled {
                                                    // Populate edit modal with current values
                                                    set_edit_monitor_id.set(monitor_id_for_edit.clone());
                                                    set_monitor_name.set(monitor_for_edit.name.clone());
                                                    
                                                    // Set config based on monitor config
                                                    match &monitor_for_edit.config {
                        MonitorConfigInfo::LogFile { path } => {
                                                            set_selected_monitor_type.set("log_file".to_string());
                                                            set_log_file_path.set(path.clone());
                                                        }
                                                        MonitorConfigInfo::ZeekPacketCapture { interface } => {
                                                            set_selected_monitor_type.set("zeek_packet_capture".to_string());
                                                            set_selected_interface.set(interface.clone());
                                                        }
                                                        _ => {}
                                                    }
                                                    
                                                    set_show_edit_modal.set(true);
                                                }
                                            };
                                            
                                            view! {
                                                <MonitorCardNew 
                                                    monitor=monitor 
                                                    on_toggle=toggle_fn
                                                    on_remove=remove_fn
                                                    on_edit=edit_fn
                                                    can_remove=!is_system
                                                />
                                            }
                                        }).collect::<Vec<_>>()}
                                    </div>
                                }.into_any()
                            }
                        }}
                    </div>
                    </div>
                </div>
                
                // Main Content - Hit Feed
                <div style="flex: 1; overflow-y: auto; padding: 1.5rem 2rem; background: white;">
                    <h2 style="margin: 0 0 1.25rem 0; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.8px; color: #6b7280; font-weight: 700;">
                        "Intelligence Hits"
                    </h2>
                    
                    {move || {
                        let hit_list = hits.get();
                        if hit_list.is_empty() {
                            view! {
                                <div style="text-align: center; padding: 4rem 0; color: #9ca3af;">
                                    <div style="font-size: 3rem; margin-bottom: 1rem;">"🔍"</div>
                                    <p style="font-size: 0.9375rem; margin: 0; font-weight: 500;">"No hits yet"</p>
                                    <p style="font-size: 0.8125rem; margin: 0.5rem 0 0 0; color: #d1d5db;">"Try querying or enable log monitoring"</p>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <div style="display: flex; flex-direction: column; gap: 1rem;">
                                    {hit_list.into_iter().map(|hit| {
                                        view! {
                                            <HitCard hit=hit />
                                        }
                                    }).collect::<Vec<_>>()}
                                </div>
                            }.into_any()
                        }
                    }}
                </div>
            </div>
            
            // Add Monitor Modal
            {move || {
                if show_add_modal.get() {
                    view! {
                        <AddMonitorModal
                            _show=show_add_modal
                            set_show=set_show_add_modal
                            selected_type=selected_monitor_type
                            set_selected_type=set_selected_monitor_type
                            monitor_name=monitor_name
                            set_monitor_name=set_monitor_name
                            log_file_path=log_file_path
                            set_log_file_path=set_log_file_path
                            network_interfaces=network_interfaces
                            set_network_interfaces=set_network_interfaces
                            selected_interface=selected_interface
                            set_selected_interface=set_selected_interface
                        />
                    }.into_any()
                } else {
                    view! { <></> }.into_any()
                }
            }}
            
            // Edit Monitor Modal
            {move || {
                if show_edit_modal.get() {
                    view! {
                        <EditMonitorModal
                            _show=show_edit_modal
                            set_show=set_show_edit_modal
                            monitor_id=edit_monitor_id
                            selected_type=selected_monitor_type
                            _set_selected_type=set_selected_monitor_type
                            monitor_name=monitor_name
                            set_monitor_name=set_monitor_name
                            log_file_path=log_file_path
                            set_log_file_path=set_log_file_path
                        />
                    }.into_any()
                } else {
                    view! { <></> }.into_any()
                }
            }}
            
            // Error Modal
            {move || {
                if show_error_modal.get() {
                    view! {
                        <ErrorModal
                            message=error_message
                            set_show=set_show_error_modal
                        />
                    }.into_any()
                } else {
                    view! { <></> }.into_any()
                }
            }}
            
        </main>
    }
}

#[component]
fn AddMonitorModal(
    _show: ReadSignal<bool>,
    set_show: WriteSignal<bool>,
    selected_type: ReadSignal<String>,
    set_selected_type: WriteSignal<String>,
    monitor_name: ReadSignal<String>,
    set_monitor_name: WriteSignal<String>,
    log_file_path: ReadSignal<String>,
    set_log_file_path: WriteSignal<String>,
    network_interfaces: ReadSignal<Vec<String>>,
    set_network_interfaces: WriteSignal<Vec<String>>,
    selected_interface: ReadSignal<String>,
    set_selected_interface: WriteSignal<String>,
) -> impl IntoView {
    // Load network interfaces when modal opens
    Effect::new(move |_| {
        spawn_local(async move {
            if let Ok(res) = invoke("list_network_interfaces", JsValue::NULL).await {
                if let Ok(ifaces) = serde_wasm_bindgen::from_value::<Vec<String>>(res) {
                    set_network_interfaces.set(ifaces.clone());
                    // Set default interface if available
                    if !ifaces.is_empty() && selected_interface.get_untracked().is_empty() {
                        set_selected_interface.set(ifaces[0].clone());
                    }
                }
            }
        });
    });
    
    let pick_log_file = move |_| {
        spawn_local(async move {
            if let Ok(res) = invoke("pick_any_file", JsValue::NULL).await {
                if let Ok(Some(path)) = serde_wasm_bindgen::from_value::<Option<String>>(res) {
                    set_log_file_path.set(path);
                }
            }
        });
    };
    
    let create_monitor = move |_: leptos::ev::MouseEvent| {
        let mon_type = selected_type.get_untracked();
        let name = monitor_name.get_untracked();
        let file_path = log_file_path.get_untracked();
        
        if name.is_empty() {
            return;
        }
        
        spawn_local(async move {
            let config = if mon_type == "log_file" {
                if file_path.is_empty() {
                    return;
                }
                serde_json::json!({
                    "type": "log_file",
                    "path": file_path
                })
            } else if mon_type == "zeek_packet_capture" {
                let interface = selected_interface.get_untracked();
                if interface.is_empty() {
                    return;
                }
                serde_json::json!({
                    "type": "zeek_packet_capture",
                    "interface": interface
                })
            } else {
                return;
            };
            
            let args = serde_wasm_bindgen::to_value(&serde_json::json!({
                "name": name,
                "config": config
            })).unwrap();
            
            if invoke("add_monitor", args).await.is_ok() {
                // Reset form and close modal
                set_monitor_name.set(String::new());
                set_log_file_path.set(String::new());
                set_selected_interface.set(String::new());
                set_show.set(false);
            }
        });
    };
    
    view! {
        <div style="position: fixed; inset: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;">
            <div style="background: white; border-radius: 12px; padding: 1.5rem; width: 90%; max-width: 500px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                    <h2 style="margin: 0; font-size: 1.25rem; font-weight: 700; color: #111827;">"Add Monitor"</h2>
                    <button
                        on:click=move |_| set_show.set(false)
                        style="background: none; border: none; color: #9ca3af; cursor: pointer; font-size: 1.5rem; padding: 0.25rem; line-height: 1; border-radius: 4px; transition: all 0.15s;"
                        onmouseover="this.style.color='#ef4444'; this.style.background='#fee2e2'"
                        onmouseout="this.style.color='#9ca3af'; this.style.background='none'"
                    >
                        "×"
                    </button>
                </div>
                
                // Monitor Name
                <div style="margin-bottom: 1.25rem;">
                    <label style="display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 0.5rem;">"Monitor Name"</label>
                    <input
                        placeholder="My Custom Monitor"
                        on:input=move |ev| set_monitor_name.set(event_target_value(&ev))
                        prop:value=move || monitor_name.get()
                        style="width: 100%; padding: 0.625rem; border: 1.5px solid #e5e7eb; border-radius: 8px; font-size: 0.875rem; transition: all 0.2s;"
                        onfocus="this.style.borderColor='#3b82f6'; this.style.boxShadow='0 0 0 3px rgba(59, 130, 246, 0.1)'"
                        onblur="this.style.borderColor='#e5e7eb'; this.style.boxShadow='none'"
                    />
                </div>
                
                // Monitor Type
                <div style="margin-bottom: 1.25rem;">
                    <label style="display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 0.5rem;">"Monitor Type"</label>
                    <select
                        on:change=move |ev| set_selected_type.set(event_target_value(&ev))
                        prop:value=move || selected_type.get()
                        style="width: 100%; padding: 0.625rem; border: 1.5px solid #e5e7eb; border-radius: 8px; font-size: 0.875rem; background: white; cursor: pointer;"
                    >
                        <option value="log_file">"📄 Log File"</option>
                        <option value="zeek_packet_capture">"📡 Zeek Packet Capture"</option>
                    </select>
                </div>
                
                // Log File Configuration
                {move || {
                    let mon_type = selected_type.get();
                    if mon_type == "log_file" {
                        view! {
                            <div style="margin-bottom: 1.25rem; padding: 1rem; background: #f9fafb; border-radius: 8px;">
                                <label style="display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 0.5rem;">"Log File Path"</label>
                                <div style="display: flex; gap: 0.5rem;">
                                    <input
                                        placeholder="/var/log/app.log"
                                        prop:value=move || log_file_path.get()
                                        on:input=move |ev| set_log_file_path.set(event_target_value(&ev))
                                        style="flex: 1; padding: 0.625rem; border: 1.5px solid #e5e7eb; border-radius: 8px; font-size: 0.875rem; font-family: 'SF Mono', monospace;"
                                    />
                                    <button
                                        on:click=pick_log_file
                                        style="padding: 0.625rem 1rem; background: #3b82f6; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 0.875rem; font-weight: 500; transition: all 0.2s;"
                                        onmouseover="this.style.background='#2563eb'"
                                        onmouseout="this.style.background='#3b82f6'"
                                    >
                                        "Browse"
                                    </button>
                                </div>
                            </div>
                        }.into_any()
                    } else if mon_type == "zeek_packet_capture" {
                        view! {
                            <div style="margin-bottom: 1.25rem; padding: 1rem; background: #fff7ed; border-radius: 8px; border: 1px solid #fed7aa;">
                                <label style="display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 0.5rem;">"Network Interface"</label>
                                <select
                                    on:change=move |ev| set_selected_interface.set(event_target_value(&ev))
                                    prop:value=move || selected_interface.get()
                                    style="width: 100%; padding: 0.625rem; border: 1.5px solid #e5e7eb; border-radius: 8px; font-size: 0.875rem; background: white; cursor: pointer; font-family: 'SF Mono', monospace;"
                                >
                                    {move || {
                                        network_interfaces.get().into_iter().map(|iface| {
                                            let iface_clone = iface.clone();
                                            view! {
                                                <option value={iface}>{iface_clone}</option>
                                            }
                                        }).collect::<Vec<_>>()
                                    }}
                                </select>
                                <p style="margin: 0.75rem 0 0 0; font-size: 0.75rem; color: #92400e; line-height: 1.4;">
                                    "⚠️ Requires administrator password. Zeek must be installed (brew install zeek)."
                                </p>
                            </div>
                        }.into_any()
                    } else {
                        view! { <></> }.into_any()
                    }
                }}
                
                // Actions
                <div style="display: flex; gap: 0.75rem; justify-content: flex-end; margin-top: 1.5rem;">
                    <button
                        on:click=move |_| set_show.set(false)
                        style="padding: 0.625rem 1.25rem; background: white; color: #6b7280; border: 1.5px solid #e5e7eb; border-radius: 8px; cursor: pointer; font-size: 0.875rem; font-weight: 500; transition: all 0.2s;"
                        onmouseover="this.style.background='#f9fafb'"
                        onmouseout="this.style.background='white'"
                    >
                        "Cancel"
                    </button>
                    <button
                        on:click=create_monitor
                        style="padding: 0.625rem 1.25rem; background: #3b82f6; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 0.875rem; font-weight: 500; transition: all 0.2s;"
                        onmouseover="this.style.background='#2563eb'"
                        onmouseout="this.style.background='#3b82f6'"
                    >
                        "Create Monitor"
                    </button>
                </div>
            </div>
        </div>
    }
}

#[component]
fn EditMonitorModal(
    _show: ReadSignal<bool>,
    set_show: WriteSignal<bool>,
    monitor_id: ReadSignal<String>,
    selected_type: ReadSignal<String>,
    _set_selected_type: WriteSignal<String>,
    monitor_name: ReadSignal<String>,
    set_monitor_name: WriteSignal<String>,
    log_file_path: ReadSignal<String>,
    set_log_file_path: WriteSignal<String>,
) -> impl IntoView {
    let pick_log_file = move |_| {
        spawn_local(async move {
            if let Ok(res) = invoke("pick_any_file", JsValue::NULL).await {
                if let Ok(Some(path)) = serde_wasm_bindgen::from_value::<Option<String>>(res) {
                    set_log_file_path.set(path);
                }
            }
        });
    };
    
    let update_monitor = move |_: leptos::ev::MouseEvent| {
        let id = monitor_id.get_untracked();
        let mon_type = selected_type.get_untracked();
        let name = monitor_name.get_untracked();
        let file_path = log_file_path.get_untracked();
        
        if name.is_empty() {
            return;
        }
        
        spawn_local(async move {
            let config = if mon_type == "log_file" {
                if file_path.is_empty() {
                    return;
                }
                serde_json::json!({
                    "type": "log_file",
                    "path": file_path
                })
            } else {
                return;
            };
            
            let args = serde_wasm_bindgen::to_value(&serde_json::json!({
                "id": id,
                "name": name,
                "config": config
            })).unwrap();
            
            if invoke("update_monitor", args).await.is_ok() {
                // Reset form and close modal
                set_monitor_name.set(String::new());
                set_log_file_path.set(String::new());
                set_show.set(false);
            }
        });
    };
    
    view! {
        <div style="position: fixed; inset: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;">
            <div style="background: white; border-radius: 12px; padding: 1.5rem; width: 90%; max-width: 500px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                    <h2 style="margin: 0; font-size: 1.25rem; font-weight: 700; color: #111827;">"Edit Monitor"</h2>
                    <button
                        on:click=move |_| set_show.set(false)
                        style="background: none; border: none; color: #9ca3af; cursor: pointer; font-size: 1.5rem; padding: 0.25rem; line-height: 1; border-radius: 4px; transition: all 0.15s;"
                        onmouseover="this.style.color='#ef4444'; this.style.background='#fee2e2'"
                        onmouseout="this.style.color='#9ca3af'; this.style.background='none'"
                    >
                        "×"
                    </button>
                </div>
                
                // Monitor Name
                <div style="margin-bottom: 1.25rem;">
                    <label style="display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 0.5rem;">"Monitor Name"</label>
                    <input
                        placeholder="My Custom Monitor"
                        on:input=move |ev| set_monitor_name.set(event_target_value(&ev))
                        prop:value=move || monitor_name.get()
                        style="width: 100%; padding: 0.625rem; border: 1.5px solid #e5e7eb; border-radius: 8px; font-size: 0.875rem; transition: all 0.2s;"
                        onfocus="this.style.borderColor='#3b82f6'; this.style.boxShadow='0 0 0 3px rgba(59, 130, 246, 0.1)'"
                        onblur="this.style.borderColor='#e5e7eb'; this.style.boxShadow='none'"
                    />
                </div>
                
                // Monitor Type (read-only for now)
                <div style="margin-bottom: 1.25rem;">
                    <label style="display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 0.5rem;">"Monitor Type"</label>
                    <select
                        disabled
                        prop:value=move || selected_type.get()
                        style="width: 100%; padding: 0.625rem; border: 1.5px solid #e5e7eb; border-radius: 8px; font-size: 0.875rem; background: #f9fafb; cursor: not-allowed;"
                    >
                        <option value="log_file">"📄 Log File"</option>
                    </select>
                </div>
                
                // Log File Configuration
                {move || {
                    if selected_type.get() == "log_file" {
                        view! {
                            <div style="margin-bottom: 1.25rem; padding: 1rem; background: #f9fafb; border-radius: 8px;">
                                <label style="display: block; font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 0.5rem;">"Log File Path"</label>
                                <div style="display: flex; gap: 0.5rem;">
                                    <input
                                        placeholder="/var/log/app.log"
                                        prop:value=move || log_file_path.get()
                                        on:input=move |ev| set_log_file_path.set(event_target_value(&ev))
                                        style="flex: 1; padding: 0.625rem; border: 1.5px solid #e5e7eb; border-radius: 8px; font-size: 0.875rem; font-family: 'SF Mono', monospace;"
                                    />
                                    <button
                                        on:click=pick_log_file
                                        style="padding: 0.625rem 1rem; background: #3b82f6; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 0.875rem; font-weight: 500; transition: all 0.2s;"
                                        onmouseover="this.style.background='#2563eb'"
                                        onmouseout="this.style.background='#3b82f6'"
                                    >
                                        "Browse"
                                    </button>
                                </div>
                            </div>
                        }.into_any()
                    } else {
                        view! { <></> }.into_any()
                    }
                }}
                
                // Actions
                <div style="display: flex; gap: 0.75rem; justify-content: flex-end; margin-top: 1.5rem;">
                    <button
                        on:click=move |_| set_show.set(false)
                        style="padding: 0.625rem 1.25rem; background: white; color: #6b7280; border: 1.5px solid #e5e7eb; border-radius: 8px; cursor: pointer; font-size: 0.875rem; font-weight: 500; transition: all 0.2s;"
                        onmouseover="this.style.background='#f9fafb'"
                        onmouseout="this.style.background='white'"
                    >
                        "Cancel"
                    </button>
                    <button
                        on:click=update_monitor
                        style="padding: 0.625rem 1.25rem; background: #3b82f6; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 0.875rem; font-weight: 500; transition: all 0.2s;"
                        onmouseover="this.style.background='#2563eb'"
                        onmouseout="this.style.background='#3b82f6'"
                    >
                        "Update Monitor"
                    </button>
                </div>
            </div>
        </div>
    }
}

#[component]
fn MonitorCardNew(
    monitor: Monitor,
    on_toggle: impl Fn(leptos::ev::MouseEvent) + 'static,
    on_remove: impl Fn(leptos::ev::MouseEvent) + 'static,
    on_edit: impl Fn(leptos::ev::MouseEvent) + 'static,
    can_remove: bool,
) -> impl IntoView {
    let type_icon = match &monitor.monitor_type {
        MonitorTypeInfo::SystemLogs => "💻",
        MonitorTypeInfo::LogFile => "📄",
        MonitorTypeInfo::ApiEndpoint => "🌐",
        MonitorTypeInfo::FilesystemScan => "🔍",
        MonitorTypeInfo::ZeekPacketCapture => "📡",
    };
    
    view! {
        <div style="padding: 0.875rem; background: white; border-radius: 8px; font-size: 0.8125rem; transition: all 0.2s; border: 1px solid #e5e7eb; box-shadow: 0 1px 2px rgba(0,0,0,0.02); cursor: pointer;"
             onmouseover="this.style.boxShadow='0 2px 8px rgba(0,0,0,0.08)'; this.style.borderColor='#d1d5db'"
             onmouseout="this.style.boxShadow='0 1px 2px rgba(0,0,0,0.02)'; this.style.borderColor='#e5e7eb'"
             on:dblclick=on_edit>
            
            // Header with name, toggle, and remove button
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                <div style="display: flex; align-items: center; gap: 0.5rem; flex: 1; min-width: 0;">
                    <span style="font-size: 1.25rem;">{type_icon}</span>
                    <span style="font-weight: 600; color: #111827; font-size: 0.875rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{monitor.name.clone()}</span>
                </div>
                <div style="display: flex; gap: 0.5rem; align-items: center;">
                    {if can_remove {
                        view! {
                            <button
                                on:click=on_remove
                                style="background: none; border: none; color: #9ca3af; cursor: pointer; padding: 0.125rem; font-size: 1.125rem; line-height: 1; transition: all 0.15s; border-radius: 4px;"
                                onmouseover="this.style.color='#ef4444'; this.style.background='#fee2e2'"
                                onmouseout="this.style.color='#9ca3af'; this.style.background='none'"
                            >
                                "×"
                            </button>
                        }.into_any()
                    } else {
                        view! { <></> }.into_any()
                    }}
                    <button
                        on:click=on_toggle
                        style=format!(
                            "padding: 0.25rem 0.5rem; background: {}; color: {}; border: 1px solid {}; border-radius: 6px; cursor: pointer; font-size: 0.6875rem; font-weight: 600; transition: all 0.15s;",
                            if monitor.enabled { "#10b981" } else { "#f3f4f6" },
                            if monitor.enabled { "white" } else { "#6b7280" },
                            if monitor.enabled { "#10b981" } else { "#d1d5db" }
                        )
                    >
                        {if monitor.enabled { "ON" } else { "OFF" }}
                    </button>
                </div>
            </div>
            
            // Status indicator
            {if monitor.enabled && monitor.state == MonitorState::Running {
                view! {
                    <div>
                        <div style="display: flex; align-items: center; gap: 0.375rem; margin-bottom: 0.625rem; padding: 0.375rem 0.5rem; background: #ecfdf5; border-radius: 6px;">
                            <span style="color: #10b981; font-weight: 600; font-size: 0.625rem; animation: pulse 2s ease-in-out infinite;">"●"</span>
                            <span style="color: #065f46; font-weight: 600; font-size: 0.6875rem; text-transform: uppercase; letter-spacing: 0.3px;">"Live"</span>
                        </div>
                        
                        <div style="color: #6b7280; font-size: 0.75rem; margin-bottom: 0.375rem;">
                            <span style="font-weight: 600; color: #111827;">{format!("{}", monitor.stats.lines_processed)}</span>
                            <span>" lines processed"</span>
                        </div>
                        
                        <div style="color: #6b7280; font-size: 0.75rem; margin-bottom: 0.375rem;">
                            <span style="font-weight: 600; color: #111827;">{format!("{}", monitor.stats.items_extracted)}</span>
                            <span>" items extracted"</span>
                        </div>
                        
                        {if let Some(last_activity) = &monitor.last_activity {
                            view! {
                                <div style="color: #9ca3af; font-size: 0.6875rem; margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid #f3f4f6;">
                                    {format!("Last: {}", last_activity)}
                                </div>
                            }.into_any()
                        } else {
                            view! { <></> }.into_any()
                        }}
                    </div>
                }.into_any()
            } else if let MonitorState::Error { message } = &monitor.state {
                view! {
                    <div style="color: #ef4444; font-size: 0.75rem; padding: 0.5rem; background: #fee2e2; border-radius: 6px;">
                        <div style="font-weight: 600; margin-bottom: 0.25rem;">"Error"</div>
                        <div>{message.clone()}</div>
                    </div>
                }.into_any()
            } else {
                view! {
                    <div style="color: #9ca3af; font-size: 0.75rem; font-style: italic;">
                        "Inactive"
                    </div>
                }.into_any()
            }}
        </div>
    }
}


#[component]
fn HitCard(hit: Hit) -> impl IntoView {
    let (accent_color, bg_color) = if hit.source == "log" {
        ("#3b82f6", "#eff6ff")
    } else {
        ("#8b5cf6", "#f5f3ff")
    };
    let matched_text = hit.matched_text.clone();
    let match_type = hit.match_type.clone();
    let timestamp = format_timestamp(&hit.timestamp);
    let source = hit.source.clone();
    
    view! {
        <div style=format!("background: white; padding: 1.125rem; border-radius: 10px; border: 1px solid #e5e7eb; border-left: 3px solid {}; transition: all 0.2s; box-shadow: 0 1px 3px rgba(0,0,0,0.05);", accent_color)
             onmouseover=format!("this.style.boxShadow='0 4px 12px rgba(0,0,0,0.1)'; this.style.borderLeftColor='{}'", accent_color)
             onmouseout=format!("this.style.boxShadow='0 1px 3px rgba(0,0,0,0.05)'; this.style.borderLeftColor='{}'", accent_color)>
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.875rem; gap: 1rem;">
                <div style="display: flex; align-items: center; gap: 0.625rem; flex-wrap: wrap; min-width: 0;">
                    <span style="font-weight: 700; font-size: 0.9375rem; color: #111827; word-break: break-all; font-family: 'SF Mono', 'Monaco', monospace;">
                        {matched_text}
                    </span>
                    <span style=format!("padding: 0.25rem 0.625rem; background: {}; border-radius: 6px; font-size: 0.6875rem; color: {}; font-weight: 600; flex-shrink: 0; text-transform: uppercase; letter-spacing: 0.3px;", bg_color, accent_color)>
                        {match_type}
                    </span>
                </div>
                <div style="font-size: 0.75rem; color: #9ca3af; flex-shrink: 0; font-weight: 500;">
                    {timestamp}
                </div>
            </div>
            
            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.875rem;">
                <span style="font-size: 0.75rem; color: #6b7280; font-weight: 500;">"Source:"</span>
                <span style=format!("padding: 0.125rem 0.5rem; background: {}; color: {}; border-radius: 4px; font-size: 0.75rem; font-weight: 600;", bg_color, accent_color)>
                    {source}
                </span>
            </div>
            
            // Display log line if available
            {if let Some(log_line) = &hit.log_line {
                view! {
                    <div style="margin-bottom: 0.875rem; padding: 0.75rem; background: #f9fafb; border-radius: 6px; border-left: 3px solid #e5e7eb;">
                        <div style="font-size: 0.6875rem; color: #6b7280; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 0.375rem;">"Log Line"</div>
                        <div style="font-family: 'SF Mono', 'Monaco', monospace; font-size: 0.75rem; color: #374151; word-break: break-all; line-height: 1.5;">
                            {log_line.clone()}
                        </div>
                    </div>
                }.into_any()
            } else {
                view! { <></> }.into_any()
            }}
            
            // Display matched indicators
            {if !hit.matched_indicators.is_empty() {
                view! {
                    <div style="display: flex; align-items: start; gap: 0.5rem; margin-bottom: 0.875rem;">
                        <span style="font-size: 0.75rem; color: #6b7280; font-weight: 500; flex-shrink: 0;">"Matched:"</span>
                        <div style="display: flex; flex-wrap: wrap; gap: 0.375rem;">
                            {hit.matched_indicators.iter().map(|indicator| {
                                view! {
                                    <span style="padding: 0.125rem 0.5rem; background: #fef3c7; color: #92400e; border-radius: 4px; font-size: 0.6875rem; font-weight: 600; font-family: 'SF Mono', 'Monaco', monospace;">
                                        {indicator.clone()}
                                    </span>
                                }
                            }).collect::<Vec<_>>()}
                        </div>
                    </div>
                }.into_any()
            } else {
                view! { <></> }.into_any()
            }}
            
            // Display data fields
            <div style="background: #f9fafb; padding: 0.875rem; border-radius: 8px; font-size: 0.8125rem; border: 1px solid #f3f4f6;">
                {hit.data.iter().map(|data| {
                    view! {
                        <DataDisplay data=data.clone() />
                    }
                }).collect::<Vec<_>>()}
            </div>
        </div>
    }
}

#[component]
fn DataDisplay(data: serde_json::Value) -> impl IntoView {
    if let Some(obj) = data.as_object() {
        view! {
            <div style="display: grid; grid-template-columns: minmax(120px, auto) 1fr; gap: 0.75rem; row-gap: 0.5rem;">
                {obj.iter().map(|(key, value)| {
                    let key_str = format!("{}:", key);
                    let formatted_value = format_value(value);
                    view! {
                        <div style="font-weight: 600; color: #6b7280; font-size: 0.75rem;">
                            {key_str}
                        </div>
                        <div style="word-break: break-word; color: #111827; font-size: 0.8125rem; font-family: 'SF Mono', 'Monaco', monospace;">
                            {formatted_value}
                        </div>
                    }
                }).collect::<Vec<_>>()}
            </div>
        }.into_any()
    } else {
        view! {
            <pre style="margin: 0; white-space: pre-wrap; word-break: break-word; color: #111827; font-size: 0.75rem; font-family: 'SF Mono', 'Monaco', monospace;">
                {serde_json::to_string_pretty(&data).unwrap_or_else(|_| "Invalid data".into())}
            </pre>
        }.into_any()
    }
}

fn format_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Array(arr) => {
            if arr.is_empty() {
                "[]".into()
            } else {
                format!("[{}]", arr.iter()
                    .map(format_value)
                    .collect::<Vec<_>>()
                    .join(", "))
            }
        }
        serde_json::Value::Object(_) => "[Object]".into(),
        serde_json::Value::Null => "null".into(),
    }
}

fn format_timestamp(timestamp: &str) -> String {
    // Parse ISO 8601 timestamp and format as human-readable
    // Example input: "2025-01-22T14:30:45.123Z"
    // Example output: "Jan 22, 14:30:45"
    
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(timestamp) {
        // Format as "Mon DD, HH:MM:SS"
        let local = dt.with_timezone(&chrono::Local);
        return local.format("%b %d, %H:%M:%S").to_string();
    }
    
    // Fallback to just showing time if parsing fails
    if let Some(time_part) = timestamp.split('T').nth(1) {
        if let Some(time_only) = time_part.split('.').next() {
            return time_only.to_string();
        }
    }
    timestamp.to_string()
}

#[component]
fn ErrorModal(
    message: ReadSignal<String>,
    set_show: WriteSignal<bool>,
) -> impl IntoView {
    view! {
        <div style="position: fixed; inset: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;">
            <div style="background: white; border-radius: 12px; padding: 1.5rem; width: 90%; max-width: 500px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);">
                <div style="display: flex; align-items: start; gap: 1rem; margin-bottom: 1.5rem;">
                    <div style="font-size: 2rem; line-height: 1;">"⚠️"</div>
                    <div style="flex: 1;">
                        <h2 style="margin: 0 0 0.5rem 0; font-size: 1.25rem; font-weight: 700; color: #111827;">"Failed to Load Database"</h2>
                        <p style="margin: 0; font-size: 0.875rem; color: #6b7280; line-height: 1.5;">
                            "The selected file could not be loaded as a Matchy database."
                        </p>
                    </div>
                    <button
                        on:click=move |_| set_show.set(false)
                        style="background: none; border: none; color: #9ca3af; cursor: pointer; font-size: 1.5rem; padding: 0.25rem; line-height: 1; border-radius: 4px; transition: all 0.15s; flex-shrink: 0;"
                        onmouseover="this.style.color='#ef4444'; this.style.background='#fee2e2'"
                        onmouseout="this.style.color='#9ca3af'; this.style.background='none'"
                    >
                        "×"
                    </button>
                </div>
                
                <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem;">
                    <div style="font-size: 0.75rem; font-weight: 600; color: #991b1b; margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.5px;">"Error Details"</div>
                    <div style="font-family: 'SF Mono', 'Monaco', monospace; font-size: 0.8125rem; color: #dc2626; word-break: break-word; line-height: 1.5;">
                        {move || message.get()}
                    </div>
                </div>
                
                <div style="display: flex; justify-content: flex-end;">
                    <button
                        on:click=move |_| set_show.set(false)
                        style="padding: 0.625rem 1.25rem; background: #3b82f6; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 0.875rem; font-weight: 500; transition: all 0.2s;"
                        onmouseover="this.style.background='#2563eb'"
                        onmouseout="this.style.background='#3b82f6'"
                    >
                        "OK"
                    </button>
                </div>
            </div>
        </div>
    }
}

