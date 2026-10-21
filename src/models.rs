use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisBatch {
    pub id: i64,
    pub batch_uuid: String,
    pub filename: String,
    pub uploaded_at: String,
    pub is_persistent: bool,
    pub expires_at: Option<String>,
    pub remaining_time: String,
    pub is_expired: bool,
    pub total_lines: i64,
    pub elapsed_seconds: f64,
    pub cores_used: i32,
    pub lines_per_second: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    pub id: Option<i64>,
    pub batch_id: Option<i64>,
    pub timestamp: String,
    pub log_date: String,
    pub log_time: String,
    pub client_ip: String,
    pub method: String,
    pub uri_stem: String,
    pub uri_query: String,
    pub status: i32,
    pub substatus: i64,
    pub win32_status: i64,
    pub time_taken: i64,
    pub user_agent: String,
    pub referer: String,
    pub server_ip: String,
    pub server_port: i64,
    pub username: String,
    pub x_forwarded_for: String,
    pub raw_log: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsMeta {
    pub total_lines: i64,
    pub elapsed_seconds: f64,
    pub cores_used: i32,
    pub lines_per_second: i64,
    pub filename: String,
    pub uploaded_at: String,
    pub is_persistent: bool,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusGroupCount {
    pub status_group: String,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusCount {
    pub status: i32,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MethodCount {
    pub method: String,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UriCount {
    pub uri_stem: String,
    pub count: i64,
    pub avg_time: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpCount {
    pub client_ip: String,
    pub x_forwarded_for: String,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlowestUri {
    pub uri_stem: String,
    pub avg_time: f64,
    pub max_time: i64,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TimelinePoint {
    pub time_slot: String,
    pub count: i64,
    pub errors: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MinuteUri {
    pub minute_slot: String,
    pub uri_stem: String,
    pub count: i64,
    pub avg_time: f64,
    pub errors: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MinuteIp {
    pub minute_slot: String,
    pub client_ip: String,
    pub x_forwarded_for: String,
    pub count: i64,
    pub avg_time: f64,
    pub errors: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotalIp {
    pub client_ip: String,
    pub x_forwarded_for: String,
    pub count: i64,
    pub avg_time: f64,
    pub errors: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MinuteMethod {
    pub minute_slot: String,
    pub method: String,
    pub count: i64,
    pub avg_time: f64,
    pub errors: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DashboardData {
    pub batch_id: i64,
    pub total_requests: i64,
    pub unique_ips: i64,
    pub total_errors: i64,
    pub error_rate: f64,
    pub avg_time: f64,
    pub max_time: i64,
    pub min_time: i64,
    pub status_groups: Vec<StatusGroupCount>,
    pub top_statuses: Vec<StatusCount>,
    pub methods: Vec<MethodCount>,
    pub top_uris: Vec<UriCount>,
    pub top_ips: Vec<IpCount>,
    pub slowest_uris: Vec<SlowestUri>,
    pub timeline: Vec<TimelinePoint>,
    pub minute_by_uri: Vec<MinuteUri>,
    pub minute_by_ip: Vec<MinuteIp>,
    pub total_by_ip: Vec<TotalIp>,
    pub minute_by_method: Vec<MinuteMethod>,
}

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    pub batch_id: Option<i64>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
    pub status: Option<String>,
    pub method: Option<String>,
    pub ip: Option<String>,
    pub uri: Option<String>,
    pub min_time: Option<i64>,
    pub xff: Option<String>,
    pub query: Option<String>,
    pub port: Option<i64>,
    pub sort_by: Option<String>,
    pub sort_dir: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LogsResponse {
    pub records: Vec<LogRecord>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
    pub total_pages: i64,
    pub batch_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct FilterOptions {
    pub methods: Vec<String>,
    pub statuses: Vec<i32>,
    pub ports: Vec<i64>,
}
