mod db;
mod models;
mod parser;

use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use db::Database;
use minijinja::{context, Environment};
use models::LogsQuery;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

struct AppState {
    db: Arc<Database>,
    jinja: Environment<'static>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "logs_analysis.db".to_string());
    let db = Arc::new(Database::new(&db_path)?);

    let mut jinja = Environment::new();
    jinja.set_loader(minijinja::path_loader("templates"));

    // Adiciona funções auxiliares para manter total compatibilidade com os templates Jinja originais
    jinja.add_function("url_for", |endpoint: String, args: Option<minijinja::Value>| -> String {
        let args_val = args.unwrap_or(minijinja::Value::UNDEFINED);
        let batch_id = args_val.get_attr("batch_id").ok().and_then(|v| v.as_i64());
        let filename = args_val.get_attr("filename").ok().and_then(|v| v.as_str().map(|s| s.to_string()));

        match endpoint.as_str() {
            "static" => {
                let file = filename.unwrap_or_default();
                format!("/static/{file}")
            }
            "index" => "/".to_string(),
            "dashboard" => {
                if let Some(id) = batch_id {
                    format!("/dashboard?batch_id={id}")
                } else {
                    "/dashboard".to_string()
                }
            }
            "logs" => {
                if let Some(id) = batch_id {
                    format!("/logs?batch_id={id}")
                } else {
                    "/logs".to_string()
                }
            }
            "history" => "/history".to_string(),
            _ => format!("/{endpoint}"),
        }
    });

    // Suporte robusto a format: tanto como filter {{ num | format("{:,}") }} quanto como método {{ "{:,}".format(num) }}
    jinja.add_filter("format", |val: minijinja::Value, args: minijinja::Value| -> String {
        let fmt_str = args.as_str().unwrap_or("{:,}");
        let num_str = val.to_string();
        if fmt_str.contains("{:,}") {
            if let Ok(n) = num_str.parse::<i64>() {
                let s = n.to_string();
                let mut out = String::new();
                let len = s.len();
                for (i, c) in s.chars().enumerate() {
                    if i > 0 && (len - i) % 3 == 0 {
                        out.push(',');
                    }
                    out.push(c);
                }
                return out;
            }
        }
        num_str
    });

    let state = Arc::new(AppState {
        db: db.clone(),
        jinja,
    });

    // Tarefa periódica em background para expiração de lotes > 24h
    let db_cleanup = db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Ok(count) = db_cleanup.cleanup_expired_batches() {
                if count > 0 {
                    tracing::info!("Limpeza automática de lotes: {} removidos", count);
                }
            }
        }
    });

    // Limite de upload configurável via env MAX_UPLOAD_SIZE_MB (padrão: 1024 MB = 1GB)
    let max_upload_mb: usize = std::env::var("MAX_UPLOAD_SIZE_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024);
    let max_upload_bytes = max_upload_mb * 1024 * 1024;

    let app = Router::new()
        .route("/", get(handle_index))
        .route("/upload", post(handle_upload))
        .route("/dashboard", get(handle_dashboard))
        .route("/logs", get(handle_logs))
        .route("/history", get(handle_history))
        .route("/api/batches", get(handle_api_batches))
        .route("/api/batches/{id}/toggle-persist", post(handle_api_toggle_persist))
        .route("/api/batches/{id}/delete", post(handle_api_delete_batch).delete(handle_api_delete_batch))
        .route("/api/dashboard-data", get(handle_api_dashboard_data))
        .route("/api/logs", get(handle_api_logs))
        .nest_service("/static", ServeDir::new("static"))
        .layer(CorsLayer::permissive())
        .layer(DefaultBodyLimit::max(max_upload_bytes))
        .with_state(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5000);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("============================================================");
    println!("🚀 IIS Log Analyzer (Rust High-Performance Engine)");
    println!("🌐 Servidor rodando em: http://localhost:{}", port);
    println!("============================================================");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn get_active_batch_context(db: &Database, batch_id: Option<i64>) -> (Option<models::AnalysisBatch>, Vec<models::AnalysisBatch>, Option<i64>) {
    let all_batches = db.list_batches().unwrap_or_default();
    let active_id = batch_id.or_else(|| all_batches.first().map(|b| b.id));
    let active_batch = active_id.and_then(|id| all_batches.iter().find(|b| b.id == id).cloned());
    (active_batch, all_batches, active_id)
}

async fn handle_index(
    State(state): State<Arc<AppState>>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let batch_id = query.get("batch_id").and_then(|v| v.parse::<i64>().ok());
    let (active_batch, all_batches, active_id) = get_active_batch_context(&state.db, batch_id);
    let stats = state.db.get_stats_meta(active_id);
    let has_data = stats.as_ref().map(|s| s.total_lines > 0).unwrap_or(false);

    let tmpl = match state.jinja.get_template("index.html") {
        Ok(t) => t,
        Err(e) => return Html(format!("Erro ao carregar template: {e}")).into_response(),
    };

    let ctx = context! {
        request => context! { endpoint => "index" },
        stats => stats,
        has_data => has_data,
        cpu_count => num_cpus::get(),
        all_batches => all_batches,
        active_batch_id => active_id,
        active_batch => active_batch,
        total_batches_count => all_batches.len(),
    };

    match tmpl.render(ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => Html(format!("Erro de renderização: {e}")).into_response(),
    }
}

async fn handle_upload(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut filename = "logfile.log".to_string();
    let mut cores: usize = num_cpus::get();
    let mut is_persistent = false;
    let temp_dir = std::env::temp_dir();
    let temp_filepath = temp_dir.join(format!("upload_{}.log", uuid::Uuid::new_v4()));
    let mut temp_file: Option<std::fs::File> = None;
    let mut total_bytes_received: usize = 0;

    tracing::info!("Iniciando recebimento de upload multipart...");

    loop {
        match multipart.next_field().await {
            Ok(Some(mut field)) => {
                let name = field.name().unwrap_or_default().to_string();
                if name == "logfile" {
                    if let Some(fname) = field.file_name() {
                        filename = fname.to_string();
                    }
                    tracing::info!("Recebendo campo 'logfile': {}", filename);

                    match std::fs::File::create(&temp_filepath) {
                        Ok(mut f) => {
                            use std::io::Write;
                            while let Ok(Some(chunk)) = field.chunk().await {
                                total_bytes_received += chunk.len();
                                if let Err(e) = f.write_all(&chunk) {
                                    tracing::error!("Erro ao gravar chunk em disco: {e}");
                                    let _ = std::fs::remove_file(&temp_filepath);
                                    return (
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        Json(serde_json::json!({
                                            "success": false,
                                            "error": format!("Falha de E/S ao salvar arquivo: {e}")
                                        })),
                                    ).into_response();
                                }
                            }
                            temp_file = Some(f);
                        }
                        Err(e) => {
                            tracing::error!("Erro ao criar arquivo temporário {:?}: {e}", temp_filepath);
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({
                                    "success": false,
                                    "error": format!("Falha ao criar arquivo temporário: {e}")
                                })),
                            ).into_response();
                        }
                    }
                } else if name == "cores" {
                    if let Ok(text) = field.text().await {
                        if let Ok(c) = text.parse::<usize>() {
                            cores = c;
                        }
                    }
                } else if name == "is_persistent" {
                    if let Ok(text) = field.text().await {
                        is_persistent = text == "true" || text == "1";
                    }
                }
            }
            Ok(None) => {
                // Fim dos campos
                break;
            }
            Err(e) => {
                tracing::error!("Erro de parsing multipart: {e}");
                let _ = std::fs::remove_file(&temp_filepath);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "success": false,
                        "error": format!("Erro na transmissão do arquivo (excedeu limite ou conexão interrompida): {e}")
                    })),
                ).into_response();
            }
        }
    }

    // Fecha o arquivo antes do processamento Rayon
    drop(temp_file);

    tracing::info!("Upload finalizado. Arquivo: {}, Tamanho: {} bytes, Cores selecionados: {}", filename, total_bytes_received, cores);

    if total_bytes_received == 0 {
        let _ = std::fs::remove_file(&temp_filepath);
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": "Nenhum arquivo enviado ou arquivo vazio."
            })),
        ).into_response();
    }

    let filepath_clone = temp_filepath.clone();
    let db = state.db.clone();
    let fname_clone = filename.clone();

    // Executa o processamento Rayon em threadpool bloqueante para liberar o runtime assíncrono Tokio
    let parse_result = tokio::task::spawn_blocking(move || {
        let (records, stats) = parser::parse_iis_log_multicore(&filepath_clone, cores);
        let save_res = db.save_records(&records, &stats, &fname_clone, is_persistent);
        let _ = std::fs::remove_file(&filepath_clone);
        (save_res, stats)
    }).await;

    match parse_result {
        Ok((Ok(batch_id), stats)) => {
            Json(serde_json::json!({
                "success": true,
                "batch_id": batch_id,
                "stats": stats,
                "redirect": format!("/dashboard?batch_id={batch_id}")
            })).into_response()
        }
        Ok((Err(e), _)) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Erro de banco de dados: {e}")
                })),
            ).into_response()
        }
        Err(e) => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Erro no processador: {e}")
                })),
            ).into_response()
        }
    }
}

async fn handle_dashboard(
    State(state): State<Arc<AppState>>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let batch_id = query.get("batch_id").and_then(|v| v.parse::<i64>().ok());
    let (active_batch, all_batches, active_id) = get_active_batch_context(&state.db, batch_id);
    let stats = state.db.get_stats_meta(active_id);
    let has_data = stats.as_ref().map(|s| s.total_lines > 0).unwrap_or(false);

    if !has_data {
        return Redirect::to("/").into_response();
    }

    let tmpl = match state.jinja.get_template("dashboard.html") {
        Ok(t) => t,
        Err(e) => return Html(format!("Erro template: {e}")).into_response(),
    };

    let ctx = context! {
        request => context! { endpoint => "dashboard" },
        stats => stats,
        batch_id => active_id,
        all_batches => all_batches,
        active_batch_id => active_id,
        active_batch => active_batch,
        total_batches_count => all_batches.len(),
    };

    match tmpl.render(ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => Html(format!("Erro renderização: {e}")).into_response(),
    }
}

async fn handle_logs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let batch_id = query.get("batch_id").and_then(|v| v.parse::<i64>().ok());
    let (active_batch, all_batches, active_id) = get_active_batch_context(&state.db, batch_id);
    let stats = state.db.get_stats_meta(active_id);
    let has_data = stats.as_ref().map(|s| s.total_lines > 0).unwrap_or(false);
    let filter_options = state.db.get_distinct_filter_values(active_id).unwrap_or(models::FilterOptions {
        methods: Vec::new(),
        statuses: Vec::new(),
        ports: Vec::new(),
    });

    let tmpl = match state.jinja.get_template("logs.html") {
        Ok(t) => t,
        Err(e) => return Html(format!("Erro template: {e}")).into_response(),
    };

    let ctx = context! {
        request => context! { endpoint => "logs" },
        stats => stats,
        has_data => has_data,
        filter_options => filter_options,
        batch_id => active_id,
        all_batches => all_batches,
        active_batch_id => active_id,
        active_batch => active_batch,
        total_batches_count => all_batches.len(),
    };

    match tmpl.render(ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => Html(format!("Erro renderização: {e}")).into_response(),
    }
}

async fn handle_history(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let all_batches = state.db.list_batches().unwrap_or_default();
    let (active_batch, _, active_id) = get_active_batch_context(&state.db, None);

    let tmpl = match state.jinja.get_template("history.html") {
        Ok(t) => t,
        Err(e) => return Html(format!("Erro template: {e}")).into_response(),
    };

    let ctx = context! {
        request => context! { endpoint => "history" },
        batches => all_batches,
        all_batches => all_batches,
        active_batch_id => active_id,
        active_batch => active_batch,
        total_batches_count => all_batches.len(),
    };

    match tmpl.render(ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => Html(format!("Erro renderização: {e}")).into_response(),
    }
}

async fn handle_api_batches(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match state.db.list_batches() {
        Ok(batches) => Json(serde_json::to_value(batches).unwrap()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

async fn handle_api_toggle_persist(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match state.db.toggle_batch_persistence(id) {
        Ok(Some((is_p, expires))) => Json(serde_json::json!({
            "success": true,
            "data": {
                "is_persistent": is_p,
                "expires_at": expires
            }
        })).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"success": false, "error": "Lote não encontrado."}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"success": false, "error": e.to_string()}))).into_response(),
    }
}

async fn handle_api_delete_batch(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match state.db.delete_batch(id) {
        Ok(_) => Json(serde_json::json!({
            "success": true,
            "message": "Análise excluída com sucesso."
        })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"success": false, "error": e.to_string()}))).into_response(),
    }
}

async fn handle_api_dashboard_data(
    State(state): State<Arc<AppState>>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let batch_id = query.get("batch_id").and_then(|v| v.parse::<i64>().ok());
    let include_port = query.get("include_port")
        .map(|v| !matches!(v.to_lowercase().as_str(), "false" | "0" | "no"))
        .unwrap_or(true);

    match state.db.get_dashboard_data(batch_id, include_port) {
        Ok(Some(data)) => Json(serde_json::to_value(data).unwrap()).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Nenhum dado encontrado"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

async fn handle_api_logs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LogsQuery>,
) -> impl IntoResponse {
    match state.db.query_logs(query) {
        Ok(response) => Json(serde_json::to_value(response).unwrap()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}
