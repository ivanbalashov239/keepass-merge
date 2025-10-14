use keepass::db::Entry;
use chrono::{DateTime, Utc};
use std::time::SystemTime;

pub fn get_modification_timestamp(entry: &Entry) -> Option<SystemTime> {
    let current_time = parse_modified_timestamp(entry)?;
    log::debug!("Analyzing entry {} for modification timestamp:", entry.uuid);
    log::debug!("  Current LastModificationTime: {}", format_timestamp(current_time));

    let history = entry.history.as_ref()?;
    let history_entries = history.get_entries();
    if history_entries.is_empty() {
        log::debug!("  No history entries, using current time");
        return Some(current_time);
    }

    // Get the latest history entry (most recent)
    let latest_history = history_entries.iter().max_by_key(|e| parse_modified_timestamp(e))?;
    let history_time = parse_modified_timestamp(latest_history)?;
    log::debug!("  Latest history LastModificationTime: {}", format_timestamp(history_time));

    // Compare key fields
    let current_title = entry.fields.get("Title");
    let current_username = entry.fields.get("UserName");
    let current_url = entry.fields.get("URL");
    let current_notes = entry.fields.get("Notes");
    let current_password = entry.fields.get("Password");

    let history_title = latest_history.fields.get("Title");
    let history_username = latest_history.fields.get("UserName");
    let history_url = latest_history.fields.get("URL");
    let history_notes = latest_history.fields.get("Notes");
    let history_password = latest_history.fields.get("Password");

    let fields_match = current_title == history_title &&
                      current_username == history_username &&
                      current_url == history_url &&
                      current_notes == history_notes &&
                      current_password == history_password;

    log::debug!("  Field comparison:");
    log::debug!("    Title: current={:?}, history={:?} ({})", current_title, history_title, current_title == history_title);
    log::debug!("    UserName: current={:?}, history={:?} ({})", current_username, history_username, current_username == history_username);
    log::debug!("    URL: current={:?}, history={:?} ({})", current_url, history_url, current_url == history_url);
    log::debug!("    Notes: current={:?}, history={:?} ({})", current_notes, history_notes, current_notes == history_notes);
    log::debug!("    Password: current={:?}, history={:?} ({})", current_password, history_password, current_password == history_password);
    log::debug!("  All fields match: {}", fields_match);

    if fields_match && history_time > current_time {
        log::debug!("  History has same fields but newer timestamp - using history time as correct modification time");
        Some(history_time)
    } else {
        log::debug!("  Using current LastModificationTime as modification time");
        Some(current_time)
    }
}

pub fn parse_modified_timestamp(entry: &Entry) -> Option<SystemTime> {
    // First try to get the timestamp from the times field
    if let Some(mod_time) = entry.times.times.get("LastModificationTime") {
        // Convert NaiveDateTime to SystemTime
        // KeePass stores times as local time, but we'll assume they're close enough to UTC for comparison
        // Convert to UTC assuming the stored time is in UTC
        let datetime_utc = DateTime::<Utc>::from_naive_utc_and_offset(*mod_time, Utc);
        Some(datetime_utc.into())
    } else {
        // Fallback to fields (for backward compatibility or if times field is not populated)
        let possible_fields = ["LastModificationTime", "Modified", "Times.LastModificationTime"];

        for field_name in &possible_fields {
            if let Some(value) = entry.fields.get(*field_name) {
                // Convert Value to string
                let value_str: &str = match value {
                    keepass::db::Value::Unprotected(s) => s,
                    keepass::db::Value::Protected(p) => {
                        std::str::from_utf8(p.unsecure()).unwrap_or("")
                    },
                    keepass::db::Value::Bytes(_) => continue, // Skip binary fields
                };

                // Try parsing as Unix timestamp first
                if let Ok(timestamp) = value_str.parse::<i64>() {
                    if timestamp > 0 {
                        return Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64));
                    }
                }

                // Try parsing as ISO 8601 datetime string
                if let Ok(dt) = DateTime::parse_from_rfc3339(value_str) {
                    return Some(dt.with_timezone(&Utc).into());
                }
                if let Ok(dt) = DateTime::parse_from_rfc2822(value_str) {
                    return Some(dt.with_timezone(&Utc).into());
                }
            }
        }

        None
    }
}

pub fn format_timestamp(timestamp: SystemTime) -> String {
    let datetime = DateTime::<Utc>::try_from(timestamp).unwrap();
    datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}