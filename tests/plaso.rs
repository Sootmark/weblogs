//! plaso's access logs (Apache-2.0, `tests/fixtures/plaso/`,
//! gzip-compressed): every request plaso reads, read the same
//! (`tests/oracle/plaso.tsv`, written from plaso's own output, see
//! `tests/oracle/README`), and the lines read beyond plaso's, counted.

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
        got.extend(log.requests.iter().map(|r| line(&name, kind, r)));
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
