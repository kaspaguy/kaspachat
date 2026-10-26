// The desktop shell only hosts the web app: all protocol logic stays in the shared TypeScript engine. The HTTP plugin
// lets the app reach the relay/indexer without browser CORS, through the Tor built into the app (../../tor) unless the
// user chose to connect directly; content protection backs screenshot protection; notifications are the app's own
// (no push service).
use tauri::Manager;

// Starts Tor once (later calls wait for the same start) and returns its SOCKS port, which only reaches `host`.
#[tauri::command]
async fn tor_start(app: tauri::AppHandle, host: String) -> Result<u16, String> {
    static PORT: tokio::sync::OnceCell<u16> = tokio::sync::OnceCell::const_new();
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?.join("tor");
    PORT.get_or_try_init(|| kaspachat_tor::start(&dir, vec![host])).await.copied()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![tor_start])
        .run(tauri::generate_context!())
        .expect("error while running KaspaChat");
}
