use leptos::task::spawn_local;
use leptos::{ev::SubmitEvent, prelude::*};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"])]
    async fn invoke(cmd: &str, args: JsValue) -> JsValue;
    
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"])]
    async fn listen(event: &str, handler: &JsValue) -> JsValue;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DatabaseInfo {
    id: String,
    path: String,
    size_bytes: u64,
    size_human: String,
    mode: String,
    stats: DatabaseStatsInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DatabaseStatsInfo {
    total_queries: u64,
    queries_with_match: u64,
    cache_hit_rate: f64,
    match_rate: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Hit {
    id: String,
    timestamp: String,
    matched_text: String,
    match_type: String,
    source: String,
    database_id: String,
    data: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MonitorStatus {
    enabled: bool,
    database_count: usize,
    lines_processed: u64,
    items_extracted: u64,
    last_activity: String,
}

#[component]
pub fn App() -> impl IntoView {
    let (databases, set_databases) = signal::<Vec<DatabaseInfo>>(Vec::new());
    let (hits, set_hits) = signal::<Vec<Hit>>(Vec::new());
    let (query, set_query) = signal(String::new());
    let (monitoring, set_monitoring) = signal(false);
    let (status, set_status) = signal(String::new());
    let (monitor_stats, set_monitor_stats) = signal(MonitorStatus {
        enabled: false,
        database_count: 0,
        lines_processed: 0,
        items_extracted: 0,
        last_activity: String::new(),
    });
    
    // Load databases on mount
    Effect::new(move |_| {
        spawn_local(async move {
            let res = invoke("list_databases", JsValue::NULL).await;
            if let Ok(dbs) = serde_wasm_bindgen::from_value::<Vec<DatabaseInfo>>(res) {
                set_databases.set(dbs);
            }
        });
        
        // Get monitoring status
        spawn_local(async move {
            let res = invoke("get_monitor_status", JsValue::NULL).await;
            if let Ok(status) = serde_wasm_bindgen::from_value::<MonitorStatus>(res) {
                set_monitoring.set(status.enabled);
                set_monitor_stats.set(status);
            }
        });
    });
    
    // Listen for hit events
    Effect::new(move |_| {
        spawn_local(async move {
            let closure = Closure::wrap(Box::new(move |event: JsValue| {
                if let Ok(hit) = serde_wasm_bindgen::from_value::<Hit>(
                    js_sys::Reflect::get(&event, &"payload".into()).unwrap()
                ) {
                    set_hits.update(|hits| {
                        hits.insert(0, hit);
                        if hits.len() > 100 {
                            hits.truncate(100);
                        }
                    });
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
                    let res = invoke("list_databases", JsValue::NULL).await;
                    if let Ok(dbs) = serde_wasm_bindgen::from_value::<Vec<DatabaseInfo>>(res) {
                        set_databases.set(dbs);
                    }
                });
            }) as Box<dyn FnMut(JsValue)>);
            
            let _ = listen("databases-updated", closure.as_ref()).await;
            closure.forget();
        });
    });
    
    let add_database = move |_| {
        spawn_local(async move {
            let res = invoke("pick_file", JsValue::NULL).await;
            if let Ok(Some(path)) = serde_wasm_bindgen::from_value::<Option<String>>(res) {
                let args = serde_wasm_bindgen::to_value(&serde_json::json!({"path": path})).unwrap();
                let res = invoke("load_database", args).await;
                if let Ok(info) = serde_wasm_bindgen::from_value::<DatabaseInfo>(res) {
                    set_databases.update(|dbs| dbs.push(info));
                    set_status.set(format!("Loaded database: {}", path));
                } else {
                    set_status.set("Failed to load database".into());
                }
            }
        });
    };
    
    let remove_database = move |id: String| {
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&serde_json::json!({"id": id})).unwrap();
            let _ = invoke("unload_database", args).await;
            set_databases.update(|dbs| dbs.retain(|db| db.id != id));
        });
    };
    
    let run_query = move |_ev: SubmitEvent| {
        _ev.prevent_default();
        let q = query.get_untracked();
        if q.is_empty() { return; }
        
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&serde_json::json!({"query": q})).unwrap();
            let res = invoke("query_databases", args).await;
            if let Ok(new_hits) = serde_wasm_bindgen::from_value::<Vec<Hit>>(res) {
                if new_hits.is_empty() {
                    set_status.set(format!("No hits for: {}", q));
                } else {
                    set_status.set(format!("Found {} hits", new_hits.len()));
                    set_hits.update(|hits| {
                        for hit in new_hits.into_iter().rev() {
                            hits.insert(0, hit);
                        }
                        if hits.len() > 100 {
                            hits.truncate(100);
                        }
                    });
                }
            }
        });
    };
    
    let toggle_monitoring = move |_| {
        let enabled = !monitoring.get_untracked();
        spawn_local(async move {
            let args = serde_wasm_bindgen::to_value(&serde_json::json!({"enabled": enabled})).unwrap();
            let res = invoke("set_monitoring", args).await;
            if let Ok(status) = serde_wasm_bindgen::from_value::<MonitorStatus>(res) {
                set_monitoring.set(status.enabled);
                set_monitor_stats.set(status.clone());
                set_status.set(if status.enabled {
                    format!("Monitoring enabled - {} database(s)", status.database_count)
                } else {
                    "Monitoring disabled".into()
                });
            }
        });
    };
    
    // Poll monitoring stats when enabled
    Effect::new(move |_| {
        let is_monitoring = monitoring.get();
        if is_monitoring {
            spawn_local(async move {
                loop {
                    if !monitoring.get_untracked() {
                        break;
                    }
                    
                    let res = invoke("get_monitor_status", JsValue::NULL).await;
                    if let Ok(status) = serde_wasm_bindgen::from_value::<MonitorStatus>(res) {
                        set_monitor_stats.set(status);
                    }
                    
                    // Wait 1 second
                    gloo_timers::future::TimeoutFuture::new(1000).await;
                }
            });
        }
    });
    
    view! {
        <main style="display: flex; flex-direction: column; height: 100vh; background: #f8f9fa; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
            // Toolbar
            <div style="display: flex; align-items: center; padding: 1rem 1.5rem; background: white; border-bottom: 1px solid #e5e7eb; gap: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <button
                    on:click=add_database
                    style="padding: 0.5rem 1rem; background: #3b82f6; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 0.875rem; font-weight: 500; transition: all 0.2s; box-shadow: 0 1px 2px rgba(59, 130, 246, 0.3);"
                    onmouseover="this.style.background='#2563eb'; this.style.boxShadow='0 2px 4px rgba(59, 130, 246, 0.4)'"
                    onmouseout="this.style.background='#3b82f6'; this.style.boxShadow='0 1px 2px rgba(59, 130, 246, 0.3)'"
                >
                    "+ Add Database"
                </button>
                
                <form on:submit=run_query style="display: flex; flex: 1; gap: 0.625rem; max-width: 550px;">
                    <input
                        placeholder="Search IP, domain, hash..."
                        on:input=move |ev| set_query.set(event_target_value(&ev))
                        prop:value=move || query.get()
                        style="flex: 1; padding: 0.625rem 1rem; border: 1.5px solid #e5e7eb; border-radius: 8px; font-size: 0.875rem; background: white; transition: all 0.2s; box-shadow: 0 1px 2px rgba(0,0,0,0.02);"
                        onfocus="this.style.borderColor='#3b82f6'; this.style.boxShadow='0 0 0 3px rgba(59, 130, 246, 0.1)'"
                        onblur="this.style.borderColor='#e5e7eb'; this.style.boxShadow='0 1px 2px rgba(0,0,0,0.02)'"
                    />
                    <button
                        type="submit"
                        style="padding: 0.625rem 1.25rem; background: #3b82f6; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 0.875rem; font-weight: 500; transition: all 0.2s; box-shadow: 0 1px 2px rgba(59, 130, 246, 0.3);"
                        onmouseover="this.style.background='#2563eb'; this.style.boxShadow='0 2px 4px rgba(59, 130, 246, 0.4)'"
                        onmouseout="this.style.background='#3b82f6'; this.style.boxShadow='0 1px 2px rgba(59, 130, 246, 0.3)'"
                    >
                        "Search"
                    </button>
                </form>
                
                <button
                    on:click=toggle_monitoring
                    style=move || format!("padding: 0.625rem 1rem; background: {}; color: {}; border: 1.5px solid {}; border-radius: 8px; cursor: pointer; font-size: 0.875rem; font-weight: 500; transition: all 0.2s; box-shadow: {};",
                        if monitoring.get() { "#10b981" } else { "white" },
                        if monitoring.get() { "white" } else { "#6b7280" },
                        if monitoring.get() { "#10b981" } else { "#e5e7eb" },
                        if monitoring.get() { "0 1px 2px rgba(16, 185, 129, 0.3)" } else { "0 1px 2px rgba(0,0,0,0.02)" }
                    )
                >
                    {move || if monitoring.get() { "⏸ Monitoring" } else { "▶ Monitor Logs" }}
                </button>
                
                // Show monitoring stats when active
                {move || {
                    let stats = monitor_stats.get();
                    if stats.enabled {
                        view! {
                            <div style="display: flex; gap: 0.75rem; align-items: center; padding: 0.5rem 0.875rem; background: #ecfdf5; border: 1px solid #d1fae5; border-radius: 8px; font-size: 0.8125rem; color: #065f46;">
                                <div style="display: flex; align-items: center; gap: 0.375rem;">
                                    <span style="color: #10b981; font-weight: 600; animation: pulse 2s ease-in-out infinite;">"●"</span>
                                    <span style="color: #065f46; font-weight: 600;">"Live"</span>
                                </div>
                                <div style="color: #047857; font-weight: 500;">{format!("{}", stats.lines_processed)}</div>
                                <div style="color: #047857; font-weight: 500;">{format!("{} extracted", stats.items_extracted)}</div>
                                {if !stats.last_activity.is_empty() {
                                    view! {
                                        <div style="color: #059669; font-size: 0.75rem;">
                                            {format!("Last: {}", stats.last_activity)}
                                        </div>
                                    }.into_any()
                                } else {
                                    view! { <></> }.into_any()
                                }}
                            </div>
                        }.into_any()
                    } else {
                        view! { <></> }.into_any()
                    }
                }}
                
                <div style="margin-left: auto; color: #6b7280; font-size: 0.8125rem; font-weight: 500;">
                    {move || status.get()}
                </div>
            </div>
            
            <div style="display: flex; flex: 1; overflow: hidden;">
                // Sidebar - Database List
                <div style="width: 300px; background: #f9fafb; border-right: 1px solid #e5e7eb; overflow-y: auto; padding: 1.25rem;">
                    <h2 style="margin: 0 0 1rem 0; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.8px; color: #6b7280; font-weight: 700;">
                        "Databases"
                    </h2>
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
                                            <div style="padding: 0.875rem; background: white; border-radius: 8px; font-size: 0.8125rem; transition: all 0.2s; border: 1px solid #e5e7eb; box-shadow: 0 1px 2px rgba(0,0,0,0.02);"
                                                 onmouseover="this.style.boxShadow='0 2px 8px rgba(0,0,0,0.08)'; this.style.borderColor='#d1d5db'"
                                                 onmouseout="this.style.boxShadow='0 1px 2px rgba(0,0,0,0.02)'; this.style.borderColor='#e5e7eb'">
                                                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.625rem;">
                                                    <div style="font-weight: 600; word-break: break-all; color: #111827; line-height: 1.4; font-size: 0.875rem;">
                                                        {filename}
                                                    </div>
                                                    <button
                                                        on:click=move |_| remove_database(id.clone())
                                                        style="background: none; border: none; color: #9ca3af; cursor: pointer; padding: 0.125rem; font-size: 1.25rem; line-height: 1; transition: all 0.15s; margin-left: 0.625rem; flex-shrink: 0; border-radius: 4px;"
                                                        onmouseover="this.style.color='#ef4444'; this.style.background='#fee2e2'"
                                                        onmouseout="this.style.color='#9ca3af'; this.style.background='none'"
                                                    >
                                                        "×"
                                                    </button>
                                                </div>
                                                <div style="color: #6b7280; font-size: 0.75rem; margin-bottom: 0.375rem;">
                                                    {db.size_human.clone()}
                                                </div>
                                                <div style="display: flex; align-items: center; gap: 0.5rem; color: #6b7280; font-size: 0.75rem;">
                                                    <span>{format!("{} queries", db.stats.total_queries)}</span>
                                                    <span style="color: #d1d5db;">"·"</span>
                                                    <span style="color: #3b82f6; font-weight: 600;">{format!("{:.1}%", db.stats.match_rate * 100.0)}</span>
                                                </div>
                                            </div>
                                        }
                                    }).collect::<Vec<_>>()}
                                </div>
                            }.into_any()
                        }
                    }}
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
        </main>
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
    // Just show time portion for now
    if let Some(time_part) = timestamp.split('T').nth(1) {
        if let Some(time_only) = time_part.split('.').next() {
            return time_only.to_string();
        }
    }
    timestamp.to_string()
}
