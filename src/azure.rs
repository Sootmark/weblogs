//! Azure Application Gateway's access log (`ApplicationGatewayAccessLog`),
//! as diagnostic settings write it: JSON, one record per request, in a
//! storage account's `PT1H.json` (`{"records": […]}`), as JSON lines, or
//! as an array:
//!
//! ```text
//! {"timeStamp": "2021-10-14T22:17:11+00:00", "resourceId": "/SUBSCRIPTIONS/…/APPLICATIONGATEWAYS/…",
//!  "listenerName": "HTTP-Listener", "ruleName": "…", "backendPoolName": "…", "backendSettingName": "…",
//!  "operationName": "ApplicationGatewayAccess", "category": "ApplicationGatewayAccessLog",
//!  "properties": {"instanceId": "appgw_2", "clientIP": "185.42.129.24", "clientPort": 45057,
//!   "httpMethod": "GET", "originalRequestUriWithArgs": "/", "requestUri": "/", "requestQuery": "",
//!   "userAgent": "…", "httpStatus": 200, "httpVersion": "HTTP/1.1", "receivedBytes": 184,
//!   "sentBytes": 466, "timeTaken": 0.034, "WAFMode": "Detection", "transactionId": "…",
//!   "sslEnabled": "on", "serverRouted": "52.239.221.65:443", "serverStatus": "200",
//!   "originalHost": "20.110.30.194", "host": "20.110.30.194", …}}
//! ```
//!
//! Each record is a request: the client, method, URI (the original, with
//! its query; v1 gateways write only `requestUri`), protocol, status,
//! bytes sent, user agent, host (the original `Host`), how long it took;
//! the rest by name (`instance_id`, `server_routed`, `waf_mode`, …). The
//! time (`timeStamp`, v1's `time`) is UTC. Records of the gateway's other
//! logs (firewall, performance) are counted in `problems`.

use common::json::{self, Json};

use crate::{time, value, Log, Request};

/// The operation of an access record.
const ACCESS: &str = "ApplicationGatewayAccess";

/// The properties kept by name, and their names here.
const PROPERTIES: [(&str, &str); 20] = [
    ("instanceId", "instance_id"),
    ("clientPort", "client_port"),
    ("requestUri", "request_uri"),
    ("requestQuery", "request_query"),
    ("host", "request_host"),
    ("receivedBytes", "received_bytes"),
    ("clientResponseTime", "client_response_time"),
    ("timeTaken", "time_taken"),
    ("WAFEvaluationTime", "waf_evaluation_time"),
    ("WAFMode", "waf_mode"),
    ("transactionId", "transaction_id"),
    ("sslEnabled", "ssl_enabled"),
    ("sslCipher", "ssl_cipher"),
    ("sslProtocol", "ssl_protocol"),
    ("sslClientVerify", "ssl_client_verify"),
    (
        "sslClientCertificateFingerprint",
        "ssl_client_certificate_fingerprint",
    ),
    (
        "sslClientCertificateIssuerName",
        "ssl_client_certificate_issuer_name",
    ),
    ("serverRouted", "server_routed"),
    ("serverStatus", "server_status"),
    ("serverResponseLatency", "server_response_latency"),
];

/// The record's own values kept by name.
const RECORD: [(&str, &str); 5] = [
    ("resourceId", "resource_id"),
    ("listenerName", "listener_name"),
    ("ruleName", "rule_name"),
    ("backendPoolName", "backend_pool_name"),
    ("backendSettingName", "backend_setting_name"),
];

/// Whether `head` starts like an Application Gateway access log.
#[must_use]
pub fn is_access(head: &str) -> bool {
    let head = head.trim_start_matches('\u{feff}').trim_start();
    (head.starts_with('{') || head.starts_with('[')) && head.contains(&format!("\"{ACCESS}\""))
}

/// Read a log: its records, each its position (a line for JSON lines, an
/// element otherwise).
#[must_use]
pub fn read(text: &str) -> Log {
    let mut log = Log::default();
    let text = text.trim_start_matches('\u{feff}');
    let records = match json::parse(text) {
        Ok(document) => (1..).zip(records(document)).collect(),
        Err(_) => lines(text, &mut log),
    };
    let mut others = 0usize;
    for (position, record) in records {
        if record.get("operationName").and_then(Json::as_str) != Some(ACCESS) {
            others += 1;
            continue;
        }
        match parse(&record) {
            Ok(mut request) => {
                request.line = position;
                log.requests.push(request);
            }
            Err(why) => log.problems.push(format!("record {position}: {why}")),
        }
    }
    if others > 0 {
        log.problems
            .push(format!("{others} records of no access log"));
    }
    log
}

/// A document's records: those under `records`, an array's elements, or
/// the document itself.
fn records(document: Json) -> Vec<Json> {
    if let Some(records) = document.get("records").and_then(Json::as_array) {
        return records.to_vec();
    }
    match document {
        Json::Array(records) => records,
        record => vec![record],
    }
}

/// JSON lines: each line's records, with the line's number.
fn lines(text: &str, log: &mut Log) -> Vec<(usize, Json)> {
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match json::parse(line) {
            Ok(document) => found.extend(records(document).into_iter().map(|r| (index + 1, r))),
            Err(why) => log.problems.push(format!("line {}: {why}", index + 1)),
        }
    }
    found
}

/// One access record.
fn parse(record: &Json) -> Result<Request, String> {
    let properties = record.get("properties").ok_or("no properties")?;
    let property = |name: &str| properties.get(name).and_then(text);
    let stamp = record
        .get("timeStamp")
        .or_else(|| record.get("time"))
        .and_then(Json::as_str)
        .ok_or("no time")?;
    let mut request = Request {
        time: Some(time::iso8601(stamp).ok_or_else(|| format!("a time {stamp:?} not read"))?),
        client: property("clientIP"),
        method: property("httpMethod"),
        uri: property("originalRequestUriWithArgs").or_else(|| property("requestUri")),
        protocol: property("httpVersion"),
        status: property("httpStatus").and_then(|s| s.parse().ok()),
        bytes: property("sentBytes").and_then(|b| b.parse().ok()),
        user_agent: property("userAgent"),
        host: property("originalHost").or_else(|| property("host")),
        duration_ms: properties.get("timeTaken").and_then(milliseconds),
        ..Request::default()
    };
    for (json_name, name) in RECORD {
        if let Some(text) = record.get(json_name).and_then(text) {
            request.extra.push((name, text));
        }
    }
    for (json_name, name) in PROPERTIES {
        if let Some(text) = property(json_name) {
            request.extra.push((name, text));
        }
    }
    Ok(request)
}

/// A scalar as text, empty and `-` meaning none.
fn text(json: &Json) -> Option<String> {
    let text = match json {
        Json::String(s) => s.clone(),
        Json::Int(n) => n.to_string(),
        Json::UInt(n) => n.to_string(),
        Json::Float(n) => n.to_string(),
        Json::Bool(b) => b.to_string(),
        _ => return None,
    };
    value(&text)
}

/// Seconds (`0.034`, or as text) in whole milliseconds, rounded.
fn milliseconds(json: &Json) -> Option<u64> {
    let seconds: f64 = match json {
        Json::Float(n) => *n,
        Json::Int(n) => *n as f64,
        Json::String(s) => s.trim().parse().ok()?,
        _ => return None,
    };
    let millis = (seconds * 1000.0).round();
    (millis.is_finite() && (0.0..=u64::MAX as f64).contains(&millis)).then_some(millis as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn containers_and_versions() {
        let v1 = r#"{"records": [{"time": "2017-04-26T19:27:38Z", "operationName": "ApplicationGatewayAccess", "properties": {"clientIP": "191.96.249.97", "httpMethod": "GET", "requestUri": "/phpmyadmin/scripts/setup.php", "httpStatus": 404, "sentBytes": "553", "timeTaken": 205, "host": "www.contoso.com"}}, {"operationName": "ApplicationGatewayFirewall", "properties": {}}]}"#;
        let log = read(v1);
        assert_eq!(log.problems, ["1 records of no access log"]);
        let request = &log.requests[0];
        assert_eq!(
            (
                request.uri.as_deref(),
                request.status,
                request.bytes,
                request.duration_ms,
                request.host.as_deref()
            ),
            (
                Some("/phpmyadmin/scripts/setup.php"),
                Some(404),
                Some(553),
                Some(205_000),
                Some("www.contoso.com")
            )
        );
        assert_eq!(
            request.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2017-04-26T19:27:38.0000000Z")
        );
        let lines = "{\"timeStamp\": \"2021-10-14T22:17:11+00:00\", \"operationName\": \"ApplicationGatewayAccess\", \"properties\": {\"timeTaken\": 0.034}}\nnot json\n";
        let log = read(lines);
        assert_eq!(
            (log.requests[0].line, log.requests[0].duration_ms),
            (1, Some(34))
        );
        assert_eq!(log.problems.len(), 1);
        assert!(is_access(lines));
        assert!(!is_access(
            "{\"operationName\": \"ApplicationGatewayFirewall\"}"
        ));
    }
}
