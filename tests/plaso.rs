//! plaso's access logs (Apache-2.0, `tests/fixtures/plaso/`,
//! gzip-compressed): every request plaso reads, read the same
//! (`tests/oracle/plaso.tsv` and `cloud.tsv`, written from plaso's own
//! output, see `tests/oracle/README`), and the lines read beyond plaso's,
//! counted.

use std::io::Read;

use weblogs::{Kind, Request};

fn gunzip(compressed: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed)
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// Every fixture's name, kind and requests.
fn fixtures() -> Vec<(String, Kind, weblogs::Log)> {
    let folder = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/plaso");
    let mut names: Vec<String> = std::fs::read_dir(folder)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".gz").map(str::to_owned))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let data = gunzip(&std::fs::read(format!("{folder}/{name}.gz")).unwrap());
            let kind =
                weblogs::detect(&name, &data).unwrap_or_else(|| panic!("{name}: not detected"));
            let log = weblogs::read(kind, &data);
            (name, kind, log)
        })
        .collect()
}

fn text<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(String::new, |v| v.to_string())
}

/// A request as the oracle's fields.
fn line(name: &str, kind: Kind, r: &Request) -> String {
    let micros = text(r.time.and_then(|t| t.ticks()).map(|t| t / 10));
    let get = |key: &str| r.get(key).unwrap_or_default().to_owned();
    let fields = match kind {
        Kind::Access => vec![
            text(r.client.as_ref()),
            text(r.user.as_ref()),
            r.request(),
            text(r.status),
            text(r.bytes),
            text(r.referer.as_ref()),
            text(r.user_agent.as_ref()),
            text(r.host.as_ref()),
            text(r.port),
        ],
        Kind::Atlassian => vec![
            text(r.client.as_ref()),
            text(r.user.as_ref()),
            text(r.method.as_ref()),
            text(r.uri.as_ref()),
            text(r.protocol.as_ref()),
            text(r.status),
            text(r.bytes),
            text(r.referer.as_ref()),
            text(r.user_agent.as_ref()),
            text(r.duration_ms),
            get("thread"),
            get("forwarded_for"),
        ],
        Kind::Elb | Kind::AzureGateway => unreachable!("compared by cloud_line"),
        Kind::Bitbucket => vec![
            text(r.client.as_ref()),
            text(r.user.as_ref()),
            text(r.method.as_ref()),
            text(r.uri.as_ref()),
            text(r.protocol.as_ref()),
            text(r.user_agent.as_ref()),
            text(r.status),
            get("bytes_read"),
            text(r.bytes),
            text(r.duration_ms),
            get("protocol"),
            get("request_id"),
            get("labels"),
            get("session"),
            get("repository"),
            get("mesh_execution_id"),
        ],
    };
    [vec![name.to_owned(), micros], fields].concat().join("\t")
}

#[test]
fn every_request_as_plaso_reads_it() {
    let mut got: Vec<String> = Vec::new();
    for (name, kind, log) in fixtures() {
        if !matches!(kind, Kind::Elb | Kind::AzureGateway) {
            got.extend(log.requests.iter().map(|r| line(&name, kind, r)));
        }
    }
    let oracle = include_str!("oracle/plaso.tsv");
    let expected: Vec<&str> = oracle.lines().collect();
    let missing: Vec<&&str> = expected
        .iter()
        .filter(|e| !got.iter().any(|g| g == **e))
        .collect();
    assert!(
        missing.is_empty(),
        "read differently or not at all:\n{missing:#?}\n\ngot:\n{got:#?}"
    );
    let beyond: Vec<&String> = got
        .iter()
        .filter(|g| !expected.contains(&g.as_str()))
        .collect();
    // The Googlebot line, its user agent cut short: plaso's grammar
    // rejects it.
    assert_eq!(beyond.len(), 1, "{beyond:#?}");
    assert!(beyond[0].contains("Googlebot"));
}

#[test]
fn every_line_is_read() {
    for (name, _, log) in fixtures() {
        assert_eq!(log.problems, Vec::<String>::new(), "{name}");
    }
}

/// AWS's names, after this crate's, and plaso's.
const ELB: [(&str, &str); 30] = [
    ("type", "request_type"),
    ("elb", "resource_identifier"),
    ("client_port", "source_port"),
    ("backend", "destination_ip_address"),
    ("target", "destination_ip_address"),
    ("destination", "destination_ip_address"),
    ("backend_port", "destination_port"),
    ("target_port", "destination_port"),
    ("destination_port", "destination_port"),
    ("request_processing_time", "request_processing_duration"),
    ("backend_processing_time", "destination_processing_duration"),
    ("target_processing_time", "destination_processing_duration"),
    ("response_processing_time", "response_processing_duration"),
    ("backend_status_code", "destination_status_code"),
    ("target_status_code", "destination_status_code"),
    ("target_group_arn", "destination_group_arn"),
    ("trace_id", "trace_identifier"),
    ("target_status_code_list", "destination_status_code_list"),
    ("connection_time", "connection_duration"),
    ("tls_handshake_time", "handshake_duration"),
    ("alpn_fe_protocol", "alpn_front_end_protocol"),
    ("alpn_be_protocol", "alpn_back_end_protocol"),
    ("ssl_cipher", "ssl_cipher"),
    ("ssl_protocol", "ssl_protocol"),
    ("received_bytes", "received_bytes"),
    ("domain_name", "domain_name"),
    ("chosen_cert_arn", "chosen_cert_arn"),
    ("matched_rule_priority", "matched_rule_priority"),
    ("actions_executed", "actions_executed"),
    ("version", "version"),
];

/// Azure's names here, and plaso's.
const AZURE: [(&str, &str); 16] = [
    ("client_port", "client_port"),
    ("client_response_time", "client_response_time"),
    ("instance_id", "instance_identifier"),
    ("received_bytes", "received_bytes"),
    ("request_host", "request_host"),
    ("request_uri", "request_uri"),
    ("server_response_latency", "server_response_latency"),
    ("server_routed", "server_routed"),
    ("server_status", "server_status"),
    ("ssl_cipher", "ssl_cipher"),
    ("ssl_client_verify", "ssl_client_verify"),
    ("ssl_enabled", "ssl_enabled"),
    ("ssl_protocol", "ssl_protocol"),
    ("time_taken", "time_taken"),
    ("transaction_id", "transaction_identifier"),
    ("waf_evaluation_time", "waf_evaluation_time"),
];

/// A request's values under plaso's names, sorted, as `name=value`.
fn cloud_values(kind: Kind, r: &Request) -> Vec<String> {
    let mut values: Vec<(&str, String)> = Vec::new();
    if kind == Kind::Elb {
        for (ours, plaso) in ELB {
            if let Some(value) = r.get(ours) {
                values.push((plaso, value.to_owned()));
            }
        }
        // AWS's names not renamed by plaso.
        for name in [
            "redirect_url",
            "error_reason",
            "classification",
            "classification_reason",
            "listener",
            "incoming_tls_alert",
            "chosen_cert_serial",
            "tls_cipher",
            "tls_protocol_version",
            "tls_named_group",
            "alpn_client_preference_list",
        ] {
            if let Some(value) = r.get(name) {
                values.push((name, value.to_owned()));
            }
        }
        if let Some(targets) = r.get("target:port_list") {
            values.push((
                "destination_list",
                targets.split(' ').collect::<Vec<_>>().join(", "),
            ));
        }
        values.extend([
            ("elb_status_code", text(r.status)),
            ("request", r.request()),
            ("sent_bytes", text(r.bytes)),
            ("source_ip_address", text(r.client.as_ref())),
            ("user_agent", text(r.user_agent.as_ref())),
        ]);
    } else {
        for (ours, plaso) in AZURE {
            if let Some(value) = r.get(ours) {
                values.push((plaso, value.to_owned()));
            }
        }
        values.extend([
            ("client_ip", text(r.client.as_ref())),
            ("http_method", text(r.method.as_ref())),
            ("http_status", text(r.status)),
            ("http_version", text(r.protocol.as_ref())),
            ("original_request_host", text(r.host.as_ref())),
            ("original_request_uri", text(r.uri.as_ref())),
            ("sent_bytes", text(r.bytes)),
            ("user_agent", text(r.user_agent.as_ref())),
            ("waf_mode", r.get("waf_mode").unwrap_or_default().to_owned()),
        ]);
    }
    let mut values: Vec<String> = values
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    values.sort();
    values
}

/// A request's events as `cloud.tsv`'s lines: its time, and when it came
/// in if logged apart.
fn cloud_lines(name: &str, kind: Kind, r: &Request) -> Vec<String> {
    let (parser, sent, received) = match kind {
        Kind::Elb => (
            "text/aws_elb_access",
            "Response Sent Time",
            "Request Received Time",
        ),
        _ => (
            "jsonl/azure_application_gateway_access_log",
            "Recorded Time",
            "",
        ),
    };
    let values = cloud_values(kind, r);
    [(r.time, sent), (r.started, received)]
        .into_iter()
        .filter_map(|(time, desc)| {
            let time = time?.to_iso8601()?;
            let time = time.trim_end_matches('Z');
            Some(
                [
                    vec![
                        name.to_owned(),
                        time.to_owned(),
                        desc.to_owned(),
                        parser.to_owned(),
                    ],
                    values.clone(),
                ]
                .concat()
                .join("\t"),
            )
        })
        .collect()
}

/// AWS ELB and Azure Application Gateway: every event plaso reads, read the
/// same, but where plaso keeps what AWS writes for none: `-` (an ALPN
/// protocol) and `-1` bytes (a connection closed before the request was
/// read); and where it keeps the spaces around a request line nobody sent
/// (`"- - - "`).
#[test]
fn every_elb_and_gateway_request_as_plaso_reads_it() {
    let mut got: Vec<String> = Vec::new();
    for (name, kind, log) in fixtures() {
        if matches!(kind, Kind::Elb | Kind::AzureGateway) {
            got.extend(
                log.requests
                    .iter()
                    .flat_map(|r| cloud_lines(&name, kind, r)),
            );
        }
    }
    got.sort();
    let oracle = include_str!("oracle/cloud.tsv");
    let none = [
        "\talpn_back_end_protocol=-",
        "\talpn_front_end_protocol=-",
        "\tsent_bytes=-1",
    ];
    let mut expected: Vec<String> = oracle
        .lines()
        .map(|line| {
            let mut line = line.replace("request=- - - \t", "request=- - -\t");
            for value in none {
                line = line.replace(value, "");
            }
            line
        })
        .collect();
    expected.sort();
    assert_eq!(
        oracle
            .lines()
            .filter(|l| none.iter().any(|v| l.contains(v)))
            .count(),
        2
    );
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
    assert_eq!(got.len(), expected.len());
}
