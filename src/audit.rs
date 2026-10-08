//! Atlassian's audit logs.
//!
//! Bitbucket's (`atlassian-bitbucket-audit.log`, up to Bitbucket 7), fields
//! between ` | `: the client's address (every proxy's, comma-separated),
//! the event, the user, the time (milliseconds since 1970, UTC), the
//! object (`PROJECT/myproject`), its details (JSON), the request id and
//! the session; `-` for none:
//!
//! ```text
//! 63.246.22.199,172.16.1.187 | RepositoryCreatedEvent | jsmith | 1400681373433 | PROJECT/myproject | {"id":2,"name":"my-repo",…} | @8KJQAGx969x543x0 | tmpqqw
//! ```
//!
//! The audit log file of Jira, Confluence and Bitbucket Data Center
//! (`<home>/log/audit/*.audit.log`), one JSON object per line, as
//! Atlassian documents it:
//!
//! ```text
//! {"affectedObjects":[{"id":"10100","name":"jsmith","type":"USER"}],"auditType":{"action":"User created",
//!  "area":"USER_MANAGEMENT","category":"Users and groups","level":"BASE"},"author":{"id":"10000","name":"admin",
//!  "type":"user"},"changedValues":[{"key":"Email","from":"","to":"jsmith@example.com"}],
//!  "extraAttributes":[{"name":"Directory","value":"Jira Internal Directory"}],"method":"Browser",
//!  "source":"192.0.2.10","system":"https://jira.example.com","timestamp":{"epochSecond":1696320045,"nano":317000000}}
//! ```
//!
//! Each line is an event: when (UTC), what (`auditType.action`), by whom
//! (`author.name`), from where (`source`), to what (`affectedObjects`);
//! the rest by name (`area`, `category`, `audit_level`, `method`,
//! `system`, `node`, `author_id`, `author_type`, `changed`, `attributes`).

use common::json::{self, Json};
use common::time::{Precision, Ts, TICKS_PER_SECOND};

use crate::{value, Entries, Entry};

/// Bitbucket's fields.
const BITBUCKET_FIELDS: usize = 8;

/// Read an audit log, one entry per line.
pub(crate) fn read(text: &str, parse: fn(&str) -> Result<Entry, String>) -> Entries {
    let mut log = Entries::default();
    for (index, line) in (1..).zip(text.lines()) {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        match parse(line) {
            Ok(mut entry) => {
                entry.line = index;
                log.entries.push(entry);
            }
            Err(why) => log.problems.push(format!("line {index}: {why}")),
        }
    }
    log
}

/// Whether a line looks like a Bitbucket audit log line.
#[must_use]
pub fn is_bitbucket(line: &str) -> bool {
    let fields = bitbucket_fields(line);
    fields.len() == BITBUCKET_FIELDS
        && !fields[1].is_empty()
        && fields[1]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !fields[3].is_empty()
        && fields[3].bytes().all(|b| b.is_ascii_digit())
}

/// A line's fields: the first five and last two split at ` | `, the
/// details (which may hold ` | `) between them.
fn bitbucket_fields(line: &str) -> Vec<&str> {
    let mut head: Vec<&str> = line.splitn(6, " | ").collect();
    let Some(tail) = head.pop().filter(|_| head.len() == 5) else {
        return Vec::new();
    };
    let mut end = tail.rsplitn(3, " | ");
    let (Some(session), Some(request), Some(details)) = (end.next(), end.next(), end.next()) else {
        return Vec::new();
    };
    head.extend([details, request, session]);
    head.into_iter().map(str::trim).collect()
}

/// One Bitbucket audit line.
///
/// # Errors
/// Why the line isn't one.
pub fn parse_bitbucket(line: &str) -> Result<Entry, String> {
    let fields = bitbucket_fields(line);
    let [client, event, user, millis, object, details, request_id, session] = fields[..] else {
        return Err(format!("{} fields, not {BITBUCKET_FIELDS}", fields.len()));
    };
    let millis: i64 = millis
        .parse()
        .map_err(|_| format!("a time {millis:?} not read"))?;
    let mut entry = Entry {
        time: Some(Ts::from_unix_millis(millis)),
        client: value(client),
        action: value(event),
        user: value(user),
        object: value(object),
        ..Entry::default()
    };
    for (name, text) in [
        ("details", details),
        ("request_id", request_id),
        ("session", session),
    ] {
        if let Some(text) = value(text) {
            entry.extra.push((name, text));
        }
    }
    Ok(entry)
}

/// Whether a line looks like an audit log file's.
#[must_use]
pub fn is_audit(line: &str) -> bool {
    line.trim_start().starts_with('{') && line.contains("\"auditType\"")
}

/// One audit log file line.
///
/// # Errors
/// Why the line isn't one.
pub fn parse_audit(line: &str) -> Result<Entry, String> {
    let event = json::parse(line).map_err(|why| why.to_string())?;
    let audit_type = event.get("auditType").ok_or("no auditType")?;
    let author = event.get("author");
    let field = |json: Option<&Json>, name: &str| json.and_then(|j| j.get(name)).and_then(text);
    let mut entry = Entry {
        time: event.get("timestamp").and_then(time),
        action: field(Some(audit_type), "action")
            .or_else(|| field(Some(audit_type), "actionI18nKey")),
        user: field(author, "name"),
        client: field(Some(&event), "source"),
        object: event
            .get("affectedObjects")
            .and_then(Json::as_array)
            .and_then(|objects| joined(objects, object)),
        ..Entry::default()
    };
    let values = [
        ("area", field(Some(audit_type), "area")),
        ("category", field(Some(audit_type), "category")),
        ("audit_level", field(Some(audit_type), "level")),
        ("method", field(Some(&event), "method")),
        ("system", field(Some(&event), "system")),
        ("node", field(Some(&event), "node")),
        ("author_id", field(author, "id")),
        ("author_type", field(author, "type")),
        (
            "changed",
            event
                .get("changedValues")
                .and_then(Json::as_array)
                .and_then(|values| joined(values, change)),
        ),
        (
            "attributes",
            event
                .get("extraAttributes")
                .and_then(Json::as_array)
                .and_then(|values| joined(values, attribute)),
        ),
    ];
    for (name, text) in values {
        if let Some(text) = text {
            entry.extra.push((name, text));
        }
    }
    Ok(entry)
}

/// `{"epochSecond": …, "nano": …}`, milliseconds since 1970, or ISO 8601.
fn time(json: &Json) -> Option<Ts> {
    match json {
        Json::Object(_) => {
            let seconds = json.get("epochSecond")?.as_i64()?;
            let nanos = json.get("nano").and_then(Json::as_i64).unwrap_or(0);
            if !(0..1_000_000_000).contains(&nanos) {
                return None;
            }
            let ticks = seconds
                .checked_mul(TICKS_PER_SECOND)?
                .checked_add(nanos / 100)?;
            let precision = if nanos % 1_000_000 == 0 {
                Precision::Millisecond
            } else {
                Precision::Tick
            };
            Some(Ts::from_ticks(ticks, precision))
        }
        Json::Int(millis) => Some(Ts::from_unix_millis(*millis)),
        Json::String(text) => crate::time::iso8601(text),
        _ => None,
    }
}

/// Each element as text, joined by `; `; `None` when none is.
fn joined(values: &[Json], each: fn(&Json) -> Option<String>) -> Option<String> {
    let texts: Vec<String> = values.iter().filter_map(each).collect();
    (!texts.is_empty()).then(|| texts.join("; "))
}

/// An affected object: `name (TYPE)`, or its id when it has no name.
fn object(json: &Json) -> Option<String> {
    let name = json
        .get("name")
        .and_then(text)
        .or_else(|| json.get("id").and_then(text))?;
    Some(match json.get("type").and_then(text) {
        Some(kind) => format!("{name} ({kind})"),
        None => name,
    })
}

/// A changed value: `key: from -> to`.
fn change(json: &Json) -> Option<String> {
    let key = json
        .get("key")
        .and_then(text)
        .or_else(|| json.get("i18nKey").and_then(text))?;
    let side = |name: &str| json.get(name).and_then(text).unwrap_or_default();
    Some(format!("{key}: {} -> {}", side("from"), side("to")))
}

/// An extra attribute: `name: value`.
fn attribute(json: &Json) -> Option<String> {
    let name = json
        .get("name")
        .and_then(text)
        .or_else(|| json.get("nameI18nKey").and_then(text))?;
    Some(format!(
        "{name}: {}",
        json.get("value").and_then(text).unwrap_or_default()
    ))
}

/// A scalar as text, empty meaning none.
fn text(json: &Json) -> Option<String> {
    let text = match json {
        Json::String(s) => s.clone(),
        Json::Int(n) => n.to_string(),
        Json::UInt(n) => n.to_string(),
        Json::Float(n) => n.to_string(),
        Json::Bool(b) => b.to_string(),
        _ => return None,
    };
    Some(text).filter(|t| !t.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitbucket_details_holding_the_separator() {
        let line = "10.1.1.100 | RepositoryCreatedEvent | jsmith | 1400681373433 | PROJECT/p | {\"name\":\"a | b\"} | @8KJQ | tmpqqw";
        assert!(is_bitbucket(line));
        let entry = parse_bitbucket(line).unwrap();
        assert_eq!(entry.get("details"), Some("{\"name\":\"a | b\"}"));
        assert_eq!(entry.get("session"), Some("tmpqqw"));
        assert!(parse_bitbucket("a | b | c").is_err());
        assert!(parse_bitbucket("a | b | c | x | e | f | g | h").is_err());
        assert!(!is_bitbucket("a | b | c | 12 | e | f | g"));
    }

    #[test]
    fn audit_times_and_values() {
        let entry = parse_audit(r#"{"auditType":{"actionI18nKey":"jira.auditing.user.created"},"timestamp":{"epochSecond":1696320045,"nano":317000000},"affectedObjects":[{"id":"10100"},{"name":"x","type":"GROUP"},{}],"changedValues":[{"key":"Email","to":"a@example.com"}]}"#).unwrap();
        assert_eq!(
            entry.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2023-10-03T08:00:45.3170000Z")
        );
        assert_eq!(entry.action.as_deref(), Some("jira.auditing.user.created"));
        assert_eq!(entry.object.as_deref(), Some("10100; x (GROUP)"));
        assert_eq!(entry.get("changed"), Some("Email:  -> a@example.com"));
        assert_eq!(
            time(&Json::String("2023-10-03T08:00:45Z".into()))
                .and_then(|t| t.to_iso8601())
                .as_deref(),
            Some("2023-10-03T08:00:45.0000000Z")
        );
        assert_eq!(
            time(&Json::object([
                ("epochSecond", Json::Int(i64::MAX)),
                ("nano", Json::Int(0))
            ])),
            None
        );
        assert!(parse_audit("{}").is_err());
        assert!(parse_audit("not json").is_err());
    }
}
