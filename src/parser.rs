use crate::models::LogRecord;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

pub fn find_fields_header<P: AsRef<Path>>(filepath: P) -> (Vec<String>, u64) {
    let mut fields = Vec::new();
    let mut header_end_pos = 0u64;

    if let Ok(file) = File::open(filepath) {
        let mut reader = BufReader::new(file);
        let mut pos = 0u64;
        let mut line_buffer = String::new();

        while let Ok(bytes_read) = reader.read_line(&mut line_buffer) {
            if bytes_read == 0 {
                break;
            }
            let trimmed = line_buffer.trim();
            if trimmed.starts_with("#Fields:") {
                let parts = trimmed[8..].trim();
                fields = parts.split_whitespace().map(|s| s.to_lowercase()).collect();
                header_end_pos = pos + bytes_read as u64;
                break;
            } else if trimmed.starts_with('#') {
                header_end_pos = pos + bytes_read as u64;
            } else {
                header_end_pos = pos;
                break;
            }
            pos += bytes_read as u64;
            line_buffer.clear();
        }
    }

    (fields, header_end_pos)
}

pub fn get_file_chunks<P: AsRef<Path>>(filepath: P, start_pos: u64, num_chunks: usize) -> Vec<(u64, u64)> {
    let Ok(file) = File::open(&filepath) else { return Vec::new(); };
    let Ok(metadata) = file.metadata() else { return Vec::new(); };
    let filesize = metadata.len();

    if filesize <= start_pos || num_chunks == 0 {
        return Vec::new();
    }

    let chunk_size = (filesize - start_pos) / (num_chunks as u64);
    if chunk_size == 0 {
        return vec![(start_pos, filesize)];
    }

    let mut chunks = Vec::new();
    let mut current_pos = start_pos;
    let mut reader = BufReader::new(file);

    for i in 0..num_chunks {
        if current_pos >= filesize {
            break;
        }
        let target_pos = current_pos + chunk_size;
        if i == num_chunks - 1 || target_pos >= filesize {
            chunks.push((current_pos, filesize));
            break;
        }

        if reader.seek(SeekFrom::Start(target_pos)).is_err() {
            chunks.push((current_pos, filesize));
            break;
        }

        let mut dummy = Vec::new();
        let bytes_advanced = reader.read_until(b'\n', &mut dummy).unwrap_or(0) as u64;
        let end_pos = target_pos + bytes_advanced;

        chunks.push((current_pos, end_pos));
        current_pos = end_pos;
    }

    chunks
}

pub fn parse_chunk<P: AsRef<Path>>(
    filepath: P,
    start_pos: u64,
    end_pos: u64,
    indices: &HashMap<String, usize>,
    fields_len: usize,
) -> Vec<LogRecord> {
    let Ok(mut file) = File::open(filepath) else { return Vec::new(); };
    if file.seek(SeekFrom::Start(start_pos)).is_err() {
        return Vec::new();
    }

    let date_idx = indices.get("date").copied();
    let time_idx = indices.get("time").copied();
    let s_ip_idx = indices.get("s-ip").copied();
    let cs_method_idx = indices.get("cs-method").copied();
    let cs_uri_stem_idx = indices.get("cs-uri-stem").copied();
    let cs_uri_query_idx = indices.get("cs-uri-query").copied();
    let s_port_idx = indices.get("s-port").copied();
    let cs_username_idx = indices.get("cs-username").copied();
    let c_ip_idx = indices.get("c-ip").copied();
    let cs_user_agent_idx = indices.get("cs(user-agent)").copied();
    let cs_referer_idx = indices.get("cs(referer)").copied();
    let sc_status_idx = indices.get("sc-status").copied();
    let sc_substatus_idx = indices.get("sc-substatus").copied();
    let sc_win32_status_idx = indices.get("sc-win32-status").copied();
    let time_taken_idx = indices.get("time-taken").copied();
    let xff_idx = indices.get("x-forwarded-for").or_else(|| indices.get("cs(x-forwarded-for)")).copied();

    let mut records = Vec::new();
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut current_pos = start_pos;
    let mut line_bytes = Vec::with_capacity(1024);

    while current_pos < end_pos {
        line_bytes.clear();
        let bytes_read = match reader.read_until(b'\n', &mut line_bytes) {
            Ok(0) => break,
            Ok(n) => n as u64,
            Err(_) => break,
        };
        current_pos += bytes_read;

        if line_bytes.is_empty() || line_bytes[0] == b'#' {
            continue;
        }

        let line_str = String::from_utf8_lossy(&line_bytes);
        let trimmed = line_str.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.split(' ').collect();
        let n_parts = parts.len();

        let get_val = |opt_idx: Option<usize>, def: &str| -> String {
            if let Some(idx) = opt_idx {
                if idx < n_parts {
                    let v = parts[idx];
                    if v != "-" && !v.is_empty() {
                        return v.to_string();
                    }
                }
            }
            def.to_string()
        };

        let get_i64 = |opt_idx: Option<usize>, def: i64| -> i64 {
            if let Some(idx) = opt_idx {
                if idx < n_parts {
                    if let Ok(val) = parts[idx].parse::<i64>() {
                        return val;
                    }
                }
            }
            def
        };

        let log_date = get_val(date_idx, "");
        let log_time = get_val(time_idx, "");
        let timestamp = if !log_date.is_empty() && !log_time.is_empty() {
            format!("{log_date} {log_time}")
        } else {
            String::new()
        };

        let client_ip = get_val(c_ip_idx, "-");
        let method = get_val(cs_method_idx, "-").to_uppercase();
        let uri_stem = get_val(cs_uri_stem_idx, "-");
        let uri_query = get_val(cs_uri_query_idx, "-");
        let status = get_i64(sc_status_idx, 0) as i32;
        let substatus = get_i64(sc_substatus_idx, 0);
        let win32_status = get_i64(sc_win32_status_idx, 0);
        let time_taken = get_i64(time_taken_idx, 0);
        let user_agent = get_val(cs_user_agent_idx, "-");
        let referer = get_val(cs_referer_idx, "-");
        let server_ip = get_val(s_ip_idx, "-");
        let server_port = get_i64(s_port_idx, 80);
        let username = get_val(cs_username_idx, "-");

        let mut x_forwarded_for = "-".to_string();
        if let Some(x_idx) = xff_idx {
            x_forwarded_for = get_val(Some(x_idx), "-");
        } else if n_parts > fields_len && n_parts >= 15 {
            let last_val = parts[n_parts - 1];
            if last_val != "-" && !last_val.is_empty() {
                x_forwarded_for = last_val.to_string();
            }
        }

        records.push(LogRecord {
            id: None,
            batch_id: None,
            timestamp,
            log_date,
            log_time,
            client_ip,
            method,
            uri_stem,
            uri_query,
            status,
            substatus,
            win32_status,
            time_taken,
            user_agent,
            referer,
            server_ip,
            server_port,
            username,
            x_forwarded_for,
            raw_log: trimmed.to_string(),
        });
    }

    records
}

pub fn parse_iis_log_multicore<P: AsRef<Path> + Sync>(
    filepath: P,
    max_workers: usize,
) -> (Vec<LogRecord>, serde_json::Value) {
    let start_time = Instant::now();
    let (mut fields, header_pos) = find_fields_header(&filepath);

    if fields.is_empty() {
        fields = vec![
            "date".to_string(), "time".to_string(), "s-ip".to_string(), "cs-method".to_string(),
            "cs-uri-stem".to_string(), "cs-uri-query".to_string(), "s-port".to_string(),
            "cs-username".to_string(), "c-ip".to_string(), "cs(user-agent)".to_string(),
            "cs(referer)".to_string(), "sc-status".to_string(), "sc-substatus".to_string(),
            "sc-win32-status".to_string(), "time-taken".to_string(),
        ];
    }

    let mut field_indices: HashMap<String, usize> = HashMap::new();
    for (i, f) in fields.iter().enumerate() {
        field_indices.insert(f.clone(), i);
    }

    let workers = if max_workers == 0 {
        num_cpus::get()
    } else {
        max_workers
    };

    let chunks = get_file_chunks(&filepath, header_pos, workers);
    let path_ref = filepath.as_ref();
    let fields_len = fields.len();

    let records: Vec<LogRecord> = chunks
        .into_par_iter()
        .flat_map(|(start, end)| {
            parse_chunk(path_ref, start, end, &field_indices, fields_len)
        })
        .collect();

    let elapsed = start_time.elapsed().as_secs_f64();
    let total_lines = records.len() as i64;
    let lps = if elapsed > 0.0 {
        (total_lines as f64 / elapsed).round() as i64
    } else {
        0
    };

    let stats = serde_json::json!({
        "total_lines": total_lines,
        "elapsed_seconds": (elapsed * 100.0).round() / 100.0,
        "cores_used": workers,
        "lines_per_second": lps
    });

    (records, stats)
}
