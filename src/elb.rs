//! AWS Elastic Load Balancing access logs, as delivered to S3, one
//! connection or request per line, values separated by spaces, some
//! quoted:
//!
//! ```text
//! classic:     time elb client:port backend:port request_processing_time backend_processing_time response_processing_time elb_status_code backend_status_code received_bytes sent_bytes "request" "user_agent" ssl_cipher ssl_protocol
//! application: type time elb client:port target:port … "request" "user_agent" ssl_cipher ssl_protocol target_group_arn "trace_id" "domain_name" "chosen_cert_arn" matched_rule_priority request_creation_time "actions_executed" "redirect_url" "error_reason" "target:port_list" "target_status_code_list" "classification" "classification_reason" …
//! network:     type version time elb listener client:port destination:port connection_time tls_handshake_time received_bytes sent_bytes incoming_tls_alert chosen_cert_arn chosen_cert_serial tls_cipher tls_protocol_version tls_named_group domain_name alpn_fe_protocol alpn_be_protocol alpn_client_preference_list tls_connection_creation_time
//! ```
//!
//! Told apart by where the time is. Classic and application load balancers
//! write UTC (`2020-01-11T16:55:20.356586Z`); network load balancers write
//! no zone (`2022-04-01T08:51:42`), kept local. The load balancer's status
//! and the bytes sent to the client are the request's; an application load
//! balancer's `request_creation_time` is when the request came in. Every
//! other value is kept by AWS's name, `-` meaning none.

use crate::{request_line, time, value, Request};

/// Which load balancer wrote a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Balancer {
    Classic,
    Application,
    Network,
}

/// Each balancer's values, in order, by AWS's names.
const CLASSIC: [&str; 15] = [
    "time",
    "elb",
    "client:port",
    "backend:port",
    "request_processing_time",
    "backend_processing_time",
    "response_processing_time",
    "elb_status_code",
    "backend_status_code",
    "received_bytes",
    "sent_bytes",
    "request",
    "user_agent",
    "ssl_cipher",
    "ssl_protocol",
];
const APPLICATION: [&str; 33] = [
    "type",
    "time",
    "elb",
    "client:port",
    "target:port",
    "request_processing_time",
    "target_processing_time",
    "response_processing_time",
    "elb_status_code",
    "target_status_code",
    "received_bytes",
    "sent_bytes",
    "request",
    "user_agent",
    "ssl_cipher",
    "ssl_protocol",
    "target_group_arn",
    "trace_id",
    "domain_name",
    "chosen_cert_arn",
    "matched_rule_priority",
    "request_creation_time",
    "actions_executed",
    "redirect_url",
    "error_reason",
    "target:port_list",
    "target_status_code_list",
    "classification",
    "classification_reason",
    "conn_trace_id",
    "transformed_host",
    "transformed_uri",
    "request_transform_status",
];
const NETWORK: [&str; 22] = [
    "type",
    "version",
    "time",
    "elb",
    "listener",
    "client:port",
    "destination:port",
    "connection_time",
    "tls_handshake_time",
    "received_bytes",
    "sent_bytes",
    "incoming_tls_alert",
    "chosen_cert_arn",
    "chosen_cert_serial",
    "tls_cipher",
    "tls_protocol_version",
    "tls_named_group",
    "domain_name",
    "alpn_fe_protocol",
    "alpn_be_protocol",
    "alpn_client_preference_list",
    "tls_connection_creation_time",
];

/// The fewest values each writes.
const CLASSIC_FEWEST: usize = 15;
const APPLICATION_FEWEST: usize = 29;
const NETWORK_FEWEST: usize = 21;

/// Whether a line looks like an ELB access log line.
#[must_use]
pub fn is_access(line: &str) -> bool {
    balancer(&values(line)).is_some()
}

/// One line.
///
/// # Errors
/// Why the line isn't one.
pub fn parse(line: &str) -> Result<Request, String> {
    let values = values(line);
    let names: &[&'static str] = match balancer(&values).ok_or("not an ELB access log line")? {
        Balancer::Classic => &CLASSIC,
        Balancer::Application => &APPLICATION,
        Balancer::Network => &NETWORK,
    };
    let mut request = Request::default();
    for (name, text) in names.iter().zip(&values) {
        let text = text.as_str();
        match *name {
            "time" => request.time = time::iso8601(text),
            "request_creation_time" | "tls_connection_creation_time" => {
                request.started = time::iso8601(text);
            }
            "client:port" => {
                let (address, port) = address_and_port(text);
                request.client = value(address);
                push(&mut request, "client_port", port);
            }
            "backend:port" => endpoint(&mut request, text, ("backend", "backend_port")),
            "target:port" => endpoint(&mut request, text, ("target", "target_port")),
            "destination:port" => {
                endpoint(&mut request, text, ("destination", "destination_port"));
            }
            "elb_status_code" => request.status = text.parse().ok(),
            "sent_bytes" => request.bytes = text.parse().ok(),
            "request" => request_line(text, &mut request),
            "user_agent" => request.user_agent = value(text),
            name => push(&mut request, name, text),
        }
    }
    if request.time.is_none() {
        return Err("a time not read".to_owned());
    }
    Ok(request)
}

/// An `address:port` kept under the names given.
fn endpoint(request: &mut Request, text: &str, names: (&'static str, &'static str)) {
    let (address, port) = address_and_port(text);
    push(request, names.0, address);
    push(request, names.1, port);
}

/// Keep `text` under `name`, unless none.
fn push(request: &mut Request, name: &'static str, text: &str) {
    if let Some(text) = value(text) {
        request.extra.push((name, text));
    }
}

/// Which balancer wrote these values: where its time is, and how many.
fn balancer(values: &[String]) -> Option<Balancer> {
    let is_time = |at: usize| values.get(at).is_some_and(|v| time::iso8601(v).is_some());
    if is_time(0) && values.len() >= CLASSIC_FEWEST {
        Some(Balancer::Classic)
    } else if is_time(1) && values.len() >= APPLICATION_FEWEST {
        Some(Balancer::Application)
    } else if is_time(2) && values.len() >= NETWORK_FEWEST {
        Some(Balancer::Network)
    } else {
        None
    }
}

/// A line's values: split at spaces, a quoted value (`"GET / HTTP/1.1"`)
/// whole and unquoted.
fn values(line: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut chars = line.trim().chars().peekable();
    while let Some(&c) = chars.peek() {
        if c == ' ' {
            chars.next();
            continue;
        }
        let mut text = String::new();
        if c == '"' {
            chars.next();
            for c in chars.by_ref() {
                if c == '"' {
                    break;
                }
                text.push(c);
            }
        } else {
            while let Some(c) = chars.next_if(|c| *c != ' ') {
                text.push(c);
            }
        }
        values.push(text);
    }
    values
}

/// `192.168.1.10:44325` (or `-`) as the address and port.
fn address_and_port(text: &str) -> (&str, &str) {
    text.rsplit_once(':').unwrap_or((text, ""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_balancers() {
        let classic = parse(r#"2021-05-13T23:39:45.945958Z my-loadbalancer 192.168.131.39:2817 10.0.0.1:80 0.001069 0.000028 0.000041 - - 82 305 "- - - " "-" - -"#).unwrap();
        assert_eq!(
            (
                classic.client.as_deref(),
                classic.status,
                classic.uri.as_deref(),
                classic.get("backend_port")
            ),
            (Some("192.168.131.39"), None, Some("- - -"), Some("80"))
        );
        let network = parse(r#"tls 2.0 2022-04-01T08:51:42 net/nlb/c6e7 g3d4 72.21.218.154:51341 172.100.100.185:443 5 2 98 246 - arn:cert - ECDHE-RSA-AES128-SHA tlsv12 - nlb.example h2 h2 "h2""#).unwrap();
        assert_eq!(
            network.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2022-04-01T08:51:42.0000000")
        );
        assert_eq!(
            (
                network.get("listener"),
                network.get("destination"),
                network.bytes,
                network.get("alpn_client_preference_list")
            ),
            (Some("g3d4"), Some("172.100.100.185"), Some(246), Some("h2"))
        );
        assert!(parse("2021-05-13T23:39:45.945958Z too few").is_err());
        assert!(!is_access(
            r#"1.2.3.4 - - [25/Apr/2021:06:15:33 +0000] "GET / HTTP/1.1" 200 1"#
        ));
    }
}
