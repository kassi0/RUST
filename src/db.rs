use crate::models::*;
use chrono::{Duration, Utc};
use rusqlite::{params, Connection, Result};
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.init_db()?;
        Ok(db)
    }

    pub fn init_db(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS analysis_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_uuid TEXT UNIQUE,
                filename TEXT,
                uploaded_at TEXT,
                is_persistent INTEGER DEFAULT 0,
                expires_at TEXT,
                total_lines INTEGER DEFAULT 0,
                elapsed_seconds REAL DEFAULT 0,
                cores_used INTEGER DEFAULT 1,
                lines_per_second INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS iis_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id INTEGER,
                timestamp TEXT,
                log_date TEXT,
                log_time TEXT,
                client_ip TEXT,
                method TEXT,
                uri_stem TEXT,
                uri_query TEXT,
                status INTEGER,
                substatus INTEGER,
                win32_status INTEGER,
                time_taken INTEGER,
                user_agent TEXT,
                referer TEXT,
                server_ip TEXT,
                server_port INTEGER,
                username TEXT,
                x_forwarded_for TEXT,
                raw_log TEXT
            );

            CREATE TABLE IF NOT EXISTS analysis_meta (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_batch_id ON iis_logs(batch_id);
            CREATE INDEX IF NOT EXISTS idx_status ON iis_logs(status);
            CREATE INDEX IF NOT EXISTS idx_method ON iis_logs(method);
            CREATE INDEX IF NOT EXISTS idx_client_ip ON iis_logs(client_ip);
            CREATE INDEX IF NOT EXISTS idx_uri_stem ON iis_logs(uri_stem);
            CREATE INDEX IF NOT EXISTS idx_time_taken ON iis_logs(time_taken);
            CREATE INDEX IF NOT EXISTS idx_timestamp ON iis_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_xff ON iis_logs(x_forwarded_for);
            CREATE INDEX IF NOT EXISTS idx_server_port ON iis_logs(server_port);
            ",
        )?;

        Ok(())
    }

    pub fn cleanup_expired_batches(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let now_str = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let mut stmt = conn.prepare(
            "SELECT id FROM analysis_batches 
             WHERE (is_persistent = 0 OR is_persistent IS NULL)
               AND expires_at IS NOT NULL 
               AND expires_at <= ?1",
        )?;

        let expired_ids: Vec<i64> = stmt
            .query_map([&now_str], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();

        for id in &expired_ids {
            conn.execute("DELETE FROM iis_logs WHERE batch_id = ?1", params![id])?;
            conn.execute("DELETE FROM analysis_batches WHERE id = ?1", params![id])?;
        }

        Ok(expired_ids.len())
    }

    pub fn list_batches(&self) -> Result<Vec<AnalysisBatch>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, batch_uuid, filename, uploaded_at, is_persistent, expires_at,
                    total_lines, elapsed_seconds, cores_used, lines_per_second
             FROM analysis_batches
             ORDER BY id DESC",
        )?;

        let now_utc = Utc::now();
        let rows = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let batch_uuid: String = row.get(1)?;
            let filename: String = row.get(2)?;
            let uploaded_at: String = row.get(3)?;
            let is_persistent_int: i32 = row.get(4)?;
            let is_persistent = is_persistent_int != 0;
            let expires_at: Option<String> = row.get(5)?;
            let total_lines: i64 = row.get(6)?;
            let elapsed_seconds: f64 = row.get(7)?;
            let cores_used: i32 = row.get(8)?;
            let lines_per_second: i64 = row.get(9)?;

            let mut remaining_str = "Permanente".to_string();
            let mut expired = false;

            if !is_persistent {
                if let Some(ref exp) = expires_at {
                    if let Ok(exp_dt) = chrono::NaiveDateTime::parse_from_str(exp, "%Y-%m-%d %H:%M:%S") {
                        let exp_utc = chrono::DateTime::<Utc>::from_naive_utc_and_offset(exp_dt, Utc);
                        let delta = exp_utc.signed_duration_since(now_utc);
                        if delta.num_seconds() <= 0 {
                            remaining_str = "Expirado".to_string();
                            expired = true;
                        } else {
                            let hours = delta.num_hours();
                            let mins = delta.num_minutes() % 60;
                            remaining_str = format!("Expira em {hours}h {mins:02}m");
                        }
                    } else {
                        remaining_str = "24 horas".to_string();
                    }
                }
            }

            Ok(AnalysisBatch {
                id,
                batch_uuid,
                filename,
                uploaded_at,
                is_persistent,
                expires_at,
                remaining_time: remaining_str,
                is_expired: expired,
                total_lines,
                elapsed_seconds,
                cores_used,
                lines_per_second,
            })
        })?;

        let mut batches = Vec::new();
        for r in rows {
            if let Ok(b) = r {
                batches.push(b);
            }
        }
        Ok(batches)
    }

    pub fn get_latest_batch_id(&self) -> Option<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id FROM analysis_batches ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok()
    }

    pub fn get_batch(&self, batch_id: i64) -> Option<AnalysisBatch> {
        let conn = self.conn.lock().unwrap();
        let now_utc = Utc::now();
        conn.query_row(
            "SELECT id, batch_uuid, filename, uploaded_at, is_persistent, expires_at,
                    total_lines, elapsed_seconds, cores_used, lines_per_second
             FROM analysis_batches
             WHERE id = ?1",
            params![batch_id],
            |row| {
                let id: i64 = row.get(0)?;
                let batch_uuid: String = row.get(1)?;
                let filename: String = row.get(2)?;
                let uploaded_at: String = row.get(3)?;
                let is_persistent_int: i32 = row.get(4)?;
                let is_persistent = is_persistent_int != 0;
                let expires_at: Option<String> = row.get(5)?;
                let total_lines: i64 = row.get(6)?;
                let elapsed_seconds: f64 = row.get(7)?;
                let cores_used: i32 = row.get(8)?;
                let lines_per_second: i64 = row.get(9)?;

                let mut remaining_str = "Permanente".to_string();
                let mut expired = false;

                if !is_persistent {
                    if let Some(ref exp) = expires_at {
                        if let Ok(exp_dt) = chrono::NaiveDateTime::parse_from_str(exp, "%Y-%m-%d %H:%M:%S") {
                            let exp_utc = chrono::DateTime::<Utc>::from_naive_utc_and_offset(exp_dt, Utc);
                            let delta = exp_utc.signed_duration_since(now_utc);
                            if delta.num_seconds() <= 0 {
                                remaining_str = "Expirado".to_string();
                                expired = true;
                            } else {
                                let hours = delta.num_hours();
                                let mins = delta.num_minutes() % 60;
                                remaining_str = format!("Expira em {hours}h {mins:02}m");
                            }
                        }
                    }
                }

                Ok(AnalysisBatch {
                    id,
                    batch_uuid,
                    filename,
                    uploaded_at,
                    is_persistent,
                    expires_at,
                    remaining_time: remaining_str,
                    is_expired: expired,
                    total_lines,
                    elapsed_seconds,
                    cores_used,
                    lines_per_second,
                })
            },
        )
        .ok()
    }

    pub fn delete_batch(&self, batch_id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM iis_logs WHERE batch_id = ?1", params![batch_id])?;
        conn.execute("DELETE FROM analysis_batches WHERE id = ?1", params![batch_id])?;
        Ok(())
    }

    pub fn toggle_batch_persistence(&self, batch_id: i64) -> Result<Option<(bool, Option<String>)>> {
        let conn = self.conn.lock().unwrap();
        let current_persistent: Option<i32> = conn
            .query_row(
                "SELECT is_persistent FROM analysis_batches WHERE id = ?1",
                params![batch_id],
                |r| r.get(0),
            )
            .ok();

        if let Some(cur) = current_persistent {
            let new_persistent = cur == 0;
            let new_expires = if new_persistent {
                None
            } else {
                Some((Utc::now() + Duration::hours(24)).format("%Y-%m-%d %H:%M:%S").to_string())
            };

            conn.execute(
                "UPDATE analysis_batches SET is_persistent = ?1, expires_at = ?2 WHERE id = ?3",
                params![if new_persistent { 1 } else { 0 }, &new_expires, batch_id],
            )?;

            return Ok(Some((new_persistent, new_expires)));
        }

        Ok(None)
    }

    pub fn save_records(
        &self,
        records: &[LogRecord],
        stats: &serde_json::Value,
        filename: &str,
        is_persistent: bool,
    ) -> Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        let batch_uuid = Uuid::new_v4().to_string();
        let now_str = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let expires_at_str = if !is_persistent {
            Some((Utc::now() + Duration::hours(24)).format("%Y-%m-%d %H:%M:%S").to_string())
        } else {
            None
        };

        let total_lines = stats.get("total_lines").and_then(|v| v.as_i64()).unwrap_or(records.len() as i64);
        let elapsed_seconds = stats.get("elapsed_seconds").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let cores_used = stats.get("cores_used").and_then(|v| v.as_i64()).unwrap_or(1) as i32;
        let lines_per_second = stats.get("lines_per_second").and_then(|v| v.as_i64()).unwrap_or(0);

        let tx = conn.transaction()?;

        tx.execute(
            "INSERT INTO analysis_batches (
                batch_uuid, filename, uploaded_at, is_persistent, expires_at,
                total_lines, elapsed_seconds, cores_used, lines_per_second
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                batch_uuid,
                filename,
                now_str,
                if is_persistent { 1 } else { 0 },
                expires_at_str,
                total_lines,
                elapsed_seconds,
                cores_used,
                lines_per_second
            ],
        )?;

        let batch_id = tx.last_insert_rowid();

        {
            let mut stmt = tx.prepare(
                "INSERT INTO iis_logs (
                    batch_id, timestamp, log_date, log_time, client_ip, method, uri_stem,
                    uri_query, status, substatus, win32_status, time_taken,
                    user_agent, referer, server_ip, server_port, username,
                    x_forwarded_for, raw_log
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            )?;

            for r in records {
                stmt.execute(params![
                    batch_id,
                    &r.timestamp,
                    &r.log_date,
                    &r.log_time,
                    &r.client_ip,
                    &r.method,
                    &r.uri_stem,
                    &r.uri_query,
                    r.status,
                    r.substatus,
                    r.win32_status,
                    r.time_taken,
                    &r.user_agent,
                    &r.referer,
                    &r.server_ip,
                    r.server_port,
                    &r.username,
                    &r.x_forwarded_for,
                    &r.raw_log
                ])?;
            }
        }

        tx.commit()?;
        Ok(batch_id)
    }

    pub fn get_stats_meta(&self, batch_id: Option<i64>) -> Option<StatsMeta> {
        let b_id = batch_id.or_else(|| self.get_latest_batch_id())?;
        let b = self.get_batch(b_id)?;
        Some(StatsMeta {
            total_lines: b.total_lines,
            elapsed_seconds: b.elapsed_seconds,
            cores_used: b.cores_used,
            lines_per_second: b.lines_per_second,
            filename: b.filename,
            uploaded_at: b.uploaded_at,
            is_persistent: b.is_persistent,
            expires_at: b.expires_at,
        })
    }

    pub fn get_dashboard_data(&self, batch_id: Option<i64>, include_port: bool) -> Result<Option<DashboardData>> {
        let b_id = match batch_id.or_else(|| self.get_latest_batch_id()) {
            Some(id) => id,
            None => return Ok(None),
        };

        let conn = self.conn.lock().unwrap();

        let total_requests: i64 = conn.query_row(
            "SELECT COUNT(*) FROM iis_logs WHERE batch_id = ?1",
            params![b_id],
            |r| r.get(0),
        )?;

        if total_requests == 0 {
            return Ok(None);
        }

        let (avg_time, max_time, min_time): (f64, i64, i64) = conn.query_row(
            "SELECT COALESCE(AVG(time_taken), 0), COALESCE(MAX(time_taken), 0), COALESCE(MIN(time_taken), 0)
             FROM iis_logs WHERE batch_id = ?1",
            params![b_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;

        let mut stmt = conn.prepare(
            "SELECT 
                CASE 
                    WHEN status >= 200 AND status < 300 THEN '2xx Success'
                    WHEN status >= 300 AND status < 400 THEN '3xx Redirect'
                    WHEN status >= 400 AND status < 500 THEN '4xx Client Error'
                    WHEN status >= 500 THEN '5xx Server Error'
                    ELSE 'Other'
                END as status_group,
                COUNT(*) as count
             FROM iis_logs
             WHERE batch_id = ?1
             GROUP BY status_group
             ORDER BY count DESC",
        )?;

        let status_groups: Vec<StatusGroupCount> = stmt
            .query_map(params![b_id], |r| {
                Ok(StatusGroupCount {
                    status_group: r.get(0)?,
                    count: r.get(1)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        let mut stmt = conn.prepare(
            "SELECT status, COUNT(*) as count 
             FROM iis_logs 
             WHERE batch_id = ?1
             GROUP BY status 
             ORDER BY count DESC 
             LIMIT 10",
        )?;

        let top_statuses: Vec<StatusCount> = stmt
            .query_map(params![b_id], |r| {
                Ok(StatusCount {
                    status: r.get(0)?,
                    count: r.get(1)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        let mut stmt = conn.prepare(
            "SELECT method, COUNT(*) as count 
             FROM iis_logs 
             WHERE batch_id = ?1
             GROUP BY method 
             ORDER BY count DESC",
        )?;

        let methods: Vec<MethodCount> = stmt
            .query_map(params![b_id], |r| {
                Ok(MethodCount {
                    method: r.get(0)?,
                    count: r.get(1)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        let mut stmt = conn.prepare(
            "SELECT uri_stem, COUNT(*) as count, ROUND(AVG(time_taken), 1) as avg_time
             FROM iis_logs 
             WHERE batch_id = ?1
             GROUP BY uri_stem 
             ORDER BY count DESC 
             LIMIT 10",
        )?;

        let top_uris: Vec<UriCount> = stmt
            .query_map(params![b_id], |r| {
                Ok(UriCount {
                    uri_stem: r.get(0)?,
                    count: r.get(1)?,
                    avg_time: r.get(2)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        let (xff_expr, ip_calc_expr) = if include_port {
            (
                "x_forwarded_for",
                "CASE WHEN x_forwarded_for IS NOT NULL AND x_forwarded_for != '-' AND x_forwarded_for != '' THEN x_forwarded_for ELSE client_ip END"
            )
        } else {
            (
                "CASE WHEN x_forwarded_for IS NOT NULL AND x_forwarded_for != '-' AND x_forwarded_for != '' THEN CASE WHEN INSTR(x_forwarded_for, ':') > 0 THEN SUBSTR(x_forwarded_for, 1, INSTR(x_forwarded_for, ':') - 1) ELSE x_forwarded_for END ELSE '-' END",
                "CASE WHEN x_forwarded_for IS NOT NULL AND x_forwarded_for != '-' AND x_forwarded_for != '' THEN CASE WHEN INSTR(x_forwarded_for, ':') > 0 THEN SUBSTR(x_forwarded_for, 1, INSTR(x_forwarded_for, ':') - 1) ELSE x_forwarded_for END ELSE CASE WHEN INSTR(client_ip, ':') > 0 THEN SUBSTR(client_ip, 1, INSTR(client_ip, ':') - 1) ELSE client_ip END END"
            )
        };

        let top_ips_sql = format!(
            "SELECT MIN(client_ip), {xff_expr} as xff_display, COUNT(*) as count 
             FROM iis_logs 
             WHERE batch_id = ?1
             GROUP BY xff_display 
             ORDER BY count DESC 
             LIMIT 10"
        );

        let mut stmt = conn.prepare(&top_ips_sql)?;
        let top_ips: Vec<IpCount> = stmt
            .query_map(params![b_id], |r| {
                Ok(IpCount {
                    client_ip: r.get(0)?,
                    x_forwarded_for: r.get::<_, Option<String>>(1)?.unwrap_or_else(|| "-".to_string()),
                    count: r.get(2)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        let mut stmt = conn.prepare(
            "SELECT uri_stem, ROUND(AVG(time_taken), 1) as avg_time, MAX(time_taken) as max_time, COUNT(*) as count
             FROM iis_logs
             WHERE batch_id = ?1
             GROUP BY uri_stem
             ORDER BY avg_time DESC
             LIMIT 10",
        )?;

        let slowest_uris: Vec<SlowestUri> = stmt
            .query_map(params![b_id], |r| {
                Ok(SlowestUri {
                    uri_stem: r.get(0)?,
                    avg_time: r.get(1)?,
                    max_time: r.get(2)?,
                    count: r.get(3)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        let hours_count: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT SUBSTR(timestamp, 1, 13)) FROM iis_logs WHERE batch_id = ?1",
            params![b_id],
            |r| r.get(0),
        )?;

        let timeline_sql = if hours_count <= 2 {
            "SELECT SUBSTR(timestamp, 1, 16) as time_slot, COUNT(*) as count,
                    SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as errors
             FROM iis_logs
             WHERE batch_id = ?1 AND timestamp != ''
             GROUP BY time_slot
             ORDER BY time_slot ASC
             LIMIT 60"
        } else {
            "SELECT SUBSTR(timestamp, 1, 13) || ':00' as time_slot, COUNT(*) as count,
                    SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as errors
             FROM iis_logs
             WHERE batch_id = ?1 AND timestamp != ''
             GROUP BY time_slot
             ORDER BY time_slot ASC
             LIMIT 48"
        };

        let mut stmt = conn.prepare(timeline_sql)?;
        let timeline: Vec<TimelinePoint> = stmt
            .query_map(params![b_id], |r| {
                Ok(TimelinePoint {
                    time_slot: r.get(0)?,
                    count: r.get(1)?,
                    errors: r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        let total_errors: i64 = conn.query_row(
            "SELECT COUNT(*) FROM iis_logs WHERE batch_id = ?1 AND status >= 400",
            params![b_id],
            |r| r.get(0),
        )?;

        let error_rate = if total_requests > 0 {
            ((total_errors as f64 / total_requests as f64) * 10000.0).round() / 100.0
        } else {
            0.0
        };

        let unique_ips_sql = format!(
            "SELECT COUNT(DISTINCT {ip_calc_expr}) 
             FROM iis_logs 
             WHERE batch_id = ?1 
               AND (
                   (client_ip IS NOT NULL AND client_ip != '-' AND client_ip != '')
                   OR 
                   (x_forwarded_for IS NOT NULL AND x_forwarded_for != '-' AND x_forwarded_for != '')
               )"
        );
        let unique_ips: i64 = conn.query_row(&unique_ips_sql, params![b_id], |r| r.get(0))?;

        let mut stmt = conn.prepare(
            "SELECT 
                SUBSTR(timestamp, 1, 16) as minute_slot,
                uri_stem,
                COUNT(*) as count,
                ROUND(AVG(time_taken), 1) as avg_time,
                SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as errors
             FROM iis_logs
             WHERE batch_id = ?1 AND timestamp != '' AND uri_stem != '-'
             GROUP BY minute_slot, uri_stem
             ORDER BY count DESC
             LIMIT 50",
        )?;

        let minute_by_uri: Vec<MinuteUri> = stmt
            .query_map(params![b_id], |r| {
                Ok(MinuteUri {
                    minute_slot: r.get(0)?,
                    uri_stem: r.get(1)?,
                    count: r.get(2)?,
                    avg_time: r.get(3)?,
                    errors: r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        let minute_by_ip_sql = format!(
            "SELECT 
                SUBSTR(timestamp, 1, 16) as minute_slot,
                MIN(client_ip) as client_ip,
                {xff_expr} as xff_display,
                COUNT(*) as count,
                ROUND(AVG(time_taken), 1) as avg_time,
                SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as errors
             FROM iis_logs
             WHERE batch_id = ?1 AND timestamp != '' AND (client_ip != '-' OR x_forwarded_for != '-')
             GROUP BY minute_slot, xff_display
             ORDER BY count DESC
             LIMIT 50"
        );

        let mut stmt = conn.prepare(&minute_by_ip_sql)?;
        let minute_by_ip: Vec<MinuteIp> = stmt
            .query_map(params![b_id], |r| {
                Ok(MinuteIp {
                    minute_slot: r.get(0)?,
                    client_ip: r.get(1)?,
                    x_forwarded_for: r.get::<_, Option<String>>(2)?.unwrap_or_else(|| "-".to_string()),
                    count: r.get(3)?,
                    avg_time: r.get(4)?,
                    errors: r.get::<_, Option<i64>>(5)?.unwrap_or(0),
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        let total_by_ip_sql = format!(
            "SELECT 
                MIN(client_ip) as client_ip,
                {xff_expr} as xff_display,
                COUNT(*) as count,
                ROUND(AVG(time_taken), 1) as avg_time,
                SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as errors
             FROM iis_logs
             WHERE batch_id = ?1 AND timestamp != '' AND (client_ip != '-' OR x_forwarded_for != '-')
             GROUP BY xff_display
             ORDER BY count DESC
             LIMIT 50"
        );

        let mut stmt = conn.prepare(&total_by_ip_sql)?;
        let total_by_ip: Vec<TotalIp> = stmt
            .query_map(params![b_id], |r| {
                Ok(TotalIp {
                    client_ip: r.get(0)?,
                    x_forwarded_for: r.get::<_, Option<String>>(1)?.unwrap_or_else(|| "-".to_string()),
                    count: r.get(2)?,
                    avg_time: r.get(3)?,
                    errors: r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        let mut stmt = conn.prepare(
            "SELECT 
                SUBSTR(timestamp, 1, 16) as minute_slot,
                method,
                COUNT(*) as count,
                ROUND(AVG(time_taken), 1) as avg_time,
                SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as errors
             FROM iis_logs
             WHERE batch_id = ?1 AND timestamp != '' AND method != '-'
             GROUP BY minute_slot, method
             ORDER BY minute_slot DESC, count DESC
             LIMIT 50",
        )?;

        let minute_by_method: Vec<MinuteMethod> = stmt
            .query_map(params![b_id], |r| {
                Ok(MinuteMethod {
                    minute_slot: r.get(0)?,
                    method: r.get(1)?,
                    count: r.get(2)?,
                    avg_time: r.get(3)?,
                    errors: r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(Some(DashboardData {
            batch_id: b_id,
            total_requests,
            unique_ips,
            total_errors,
            error_rate,
            avg_time: (avg_time * 10.0).round() / 10.0,
            max_time,
            min_time,
            status_groups,
            top_statuses,
            methods,
            top_uris,
            top_ips,
            slowest_uris,
            timeline,
            minute_by_uri,
            minute_by_ip,
            total_by_ip,
            minute_by_method,
        }))
    }

    pub fn query_logs(&self, q: LogsQuery) -> Result<LogsResponse> {
        let b_id = q.batch_id.or_else(|| self.get_latest_batch_id());
        let page = q.page.unwrap_or(1).max(1);
        let per_page = q.per_page.unwrap_or(50).clamp(1, 500);

        let conn = self.conn.lock().unwrap();

        let mut where_clauses = Vec::new();
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(id) = b_id {
            where_clauses.push(format!("batch_id = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(id));
        }

        if let Some(ref st) = q.status {
            if st.contains('-') {
                let parts: Vec<&str> = st.split('-').collect();
                if parts.len() == 2 {
                    if let (Ok(s1), Ok(s2)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>()) {
                        where_clauses.push(format!("status >= ?{} AND status <= ?{}", params_vec.len() + 1, params_vec.len() + 2));
                        params_vec.push(Box::new(s1));
                        params_vec.push(Box::new(s2));
                    }
                }
            } else if st.ends_with("xx") {
                if let Ok(base_num) = st[0..1].parse::<i32>() {
                    let base = base_num * 100;
                    where_clauses.push(format!("status >= ?{} AND status < ?{}", params_vec.len() + 1, params_vec.len() + 2));
                    params_vec.push(Box::new(base));
                    params_vec.push(Box::new(base + 100));
                }
            } else if let Ok(val) = st.parse::<i32>() {
                where_clauses.push(format!("status = ?{}", params_vec.len() + 1));
                params_vec.push(Box::new(val));
            }
        }

        if let Some(ref m) = q.method {
            where_clauses.push(format!("method = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(m.to_uppercase()));
        }

        if let Some(ref ip) = q.ip {
            where_clauses.push(format!("(client_ip LIKE ?{0} OR x_forwarded_for LIKE ?{0})", params_vec.len() + 1));
            params_vec.push(Box::new(format!("%{ip}%")));
        }

        if let Some(ref xff) = q.xff {
            where_clauses.push(format!("x_forwarded_for LIKE ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(format!("%{xff}%")));
        }

        if let Some(ref uri) = q.uri {
            where_clauses.push(format!("uri_stem LIKE ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(format!("%{uri}%")));
        }

        if let Some(ref query) = q.query {
            where_clauses.push(format!("uri_query LIKE ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(format!("%{query}%")));
        }

        if let Some(port) = q.port {
            where_clauses.push(format!("server_port = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(port));
        }

        if let Some(min_time) = q.min_time {
            where_clauses.push(format!("time_taken >= ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(min_time));
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", where_clauses.join(" AND "))
        };

        let count_query = format!("SELECT COUNT(*) FROM iis_logs{where_sql}");
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|b| b.as_ref()).collect();

        let total: i64 = conn.query_row(&count_query, rusqlite::params_from_iter(params_refs.iter().copied()), |r| r.get(0))?;

        let sort_by = match q.sort_by.as_deref() {
            Some("timestamp") => "timestamp",
            Some("client_ip") => "client_ip",
            Some("method") => "method",
            Some("uri_stem") => "uri_stem",
            Some("status") => "status",
            Some("time_taken") => "time_taken",
            Some("server_port") => "server_port",
            Some("x_forwarded_for") => "x_forwarded_for",
            _ => "id",
        };

        let sort_dir = match q.sort_dir.as_deref() {
            Some(d) if d.eq_ignore_ascii_case("asc") => "ASC",
            _ => "DESC",
        };

        let offset = (page - 1) * per_page;
        let data_query = format!(
            "SELECT id, timestamp, log_date, log_time, client_ip, method, uri_stem, uri_query, status, substatus, 
                    win32_status, time_taken, user_agent, referer, server_ip, server_port, username,
                    x_forwarded_for, raw_log
             FROM iis_logs
             {where_sql}
             ORDER BY {sort_by} {sort_dir}
             LIMIT ?{} OFFSET ?{}",
            params_vec.len() + 1,
            params_vec.len() + 2
        );

        let mut data_params = params_vec;
        data_params.push(Box::new(per_page));
        data_params.push(Box::new(offset));

        let data_refs: Vec<&dyn rusqlite::ToSql> = data_params.iter().map(|b| b.as_ref()).collect();
        let mut stmt = conn.prepare(&data_query)?;

        let records: Vec<LogRecord> = stmt
            .query_map(rusqlite::params_from_iter(data_refs.iter().copied()), |r| {
                Ok(LogRecord {
                    id: Some(r.get(0)?),
                    batch_id: b_id,
                    timestamp: r.get(1)?,
                    log_date: r.get(2)?,
                    log_time: r.get(3)?,
                    client_ip: r.get(4)?,
                    method: r.get(5)?,
                    uri_stem: r.get(6)?,
                    uri_query: r.get(7)?,
                    status: r.get(8)?,
                    substatus: r.get(9)?,
                    win32_status: r.get(10)?,
                    time_taken: r.get(11)?,
                    user_agent: r.get(12)?,
                    referer: r.get(13)?,
                    server_ip: r.get(14)?,
                    server_port: r.get(15)?,
                    username: r.get(16)?,
                    x_forwarded_for: r.get(17)?,
                    raw_log: r.get(18)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        let total_pages = if total > 0 {
            (total + per_page - 1) / per_page
        } else {
            1
        };

        Ok(LogsResponse {
            records,
            total,
            page,
            per_page,
            total_pages,
            batch_id: b_id,
        })
    }

    pub fn get_distinct_filter_values(&self, batch_id: Option<i64>) -> Result<FilterOptions> {
        let b_id = batch_id.or_else(|| self.get_latest_batch_id());
        let conn = self.conn.lock().unwrap();

        let (where_m, where_s, where_p) = if let Some(id) = b_id {
            (
                format!("WHERE batch_id = {id} AND method != '-'"),
                format!("WHERE batch_id = {id} AND status != 0"),
                format!("WHERE batch_id = {id} AND server_port != 0"),
            )
        } else {
            (
                "WHERE method != '-'".to_string(),
                "WHERE status != 0".to_string(),
                "WHERE server_port != 0".to_string(),
            )
        };

        let mut stmt = conn.prepare(&format!("SELECT DISTINCT method FROM iis_logs {where_m} ORDER BY method"))?;
        let methods: Vec<String> = stmt.query_map([], |r| r.get(0))?.filter_map(|r| r.ok()).collect();

        let mut stmt = conn.prepare(&format!("SELECT DISTINCT status FROM iis_logs {where_s} ORDER BY status"))?;
        let statuses: Vec<i32> = stmt.query_map([], |r| r.get(0))?.filter_map(|r| r.ok()).collect();

        let mut stmt = conn.prepare(&format!("SELECT DISTINCT server_port FROM iis_logs {where_p} ORDER BY server_port"))?;
        let ports: Vec<i64> = stmt.query_map([], |r| r.get(0))?.filter_map(|r| r.ok()).collect();

        Ok(FilterOptions {
            methods,
            statuses,
            ports,
        })
    }
}
