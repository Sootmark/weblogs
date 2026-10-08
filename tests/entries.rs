//! Atlassian's application and audit logs.
//!
//! plaso's (Apache-2.0, `tests/fixtures/plaso/atlassian/`, gzip-compressed):
//! every event plaso 20260720 reads, read the same (`tests/oracle/atlassian.tsv`,
//! written by `tests/oracle/plaso.py` from plaso's output, see
//! `tests/oracle/README`). Jira's and Confluence's samples are in the same
//! layout, and plaso reads both with the first of its two identical
//! plugins, `text/atlassian_confluence`.
//!
//! The synthetic ones (`tests/fixtures/synthetic/`, made by its `gen.py`):
//! Jira's own layout, Confluence's request values and stack traces,
//! Bitbucket's quoted HTTP action, and the audit log file of Jira,
//! Confluence and Bitbucket Data Center. Unverified: plaso reads none of
//! these, and they are written from Atlassian's documentation, not copied
//! from a real log.

use std::io::Read;

use weblogs::{Entry, EntryKind};

fn gunzip(compressed: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed)
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn fixture(path: &str) -> Vec<u8> {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    if common::gzip::is_gzip(&data) {
        gunzip(&data)
    } else {
        data
    }
}

/// A fixture detected and read.
fn read(path: &str) -> (EntryKind, weblogs::Entries) {
    let data = fixture(path);
    let kind =
        weblogs::detect_entries(path, &data).unwrap_or_else(|| panic!("{path}: not detected"));
    assert_eq!(weblogs::detect(path, &data), None, "{path}: an access log?");
    (kind, weblogs::read_entries(kind, &data))
}

fn some(name: &'static str, value: Option<&String>) -> Option<(&'static str, String)> {
    value.map(|v| (name, v.clone()))
}

/// An entry as the oracle's line: file, time, its name, parser, and
/// plaso's values, sorted.
fn line(file: &str, kind: EntryKind, e: &Entry) -> String {
    let get = |name: &'static str| e.get(name).map(|v| (name, v.to_owned()));
    let (desc, parser, values) = match kind {
        EntryKind::BitbucketAudit => (
            "Recorded Time",
            "text/bitbucket_audit",
            vec![
                get("details").map(|(_, v)| ("details", v)),
                some("entity", e.object.as_ref()),
                some("event_name", e.action.as_ref()),
                some("remote_address", e.client.as_ref()),
                get("request_id").map(|(_, v)| ("request_identifier", v)),
                get("session").map(|(_, v)| ("session_identifier", v)),
                some("username", e.user.as_ref()),
            ],
        ),
        EntryKind::Application if e.method.is_some() => (
            "Content Modification Time",
            "text/atlassian_confluence",
            vec![
                some("level", e.level.as_ref()),
                some("logger_class", e.logger.as_ref()),
                some("logger_method", e.method.as_ref()),
                some("message_body", e.message.as_ref()),
                some("thread", e.thread.as_ref()),
            ],
        ),
        EntryKind::Application => (
            "Content Modification Time",
            "text/atlassian_bitbucket",
            vec![
                some("ip_address", e.client.as_ref()),
                some("level", e.level.as_ref()),
                some("logger_class", e.logger.as_ref()),
                some("message_body", e.message.as_ref()),
                some("request_action", e.action.as_ref()),
                get("request_id").map(|(_, v)| ("request_identifier", v)),
                get("session").map(|(_, v)| ("session_identifier", v)),
                some("thread", e.thread.as_ref()),
                some("username", e.user.as_ref()),
            ],
        ),
        EntryKind::Audit => unreachable!("plaso reads no audit log file"),
    };
    let time = e.time.and_then(|t| t.to_iso8601()).unwrap();
    let mut values: Vec<String> = values
        .into_iter()
        .flatten()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    values.sort();
    [
        vec![
            file.to_owned(),
            time.trim_end_matches('Z').to_owned(),
            desc.to_owned(),
            parser.to_owned(),
        ],
        values,
    ]
    .concat()
    .join("\t")
}

#[test]
fn every_entry_as_plaso_reads_it() {
    let mut got = Vec::new();
    for file in [
        "atlassian-bitbucket-audit.log",
        "atlassian-bitbucket.log",
        "atlassian-confluence.log",
        "atlassian-jira.log",
    ] {
        let (kind, log) = read(&format!("plaso/atlassian/{file}.gz"));
        assert!(log.problems.is_empty(), "{file}: {:?}", log.problems);
        got.extend(log.entries.iter().map(|e| line(file, kind, e)));
    }
    got.sort();
    let expected: Vec<&str> = include_str!("oracle/atlassian.tsv").lines().collect();
    assert_eq!(got, expected);
}

#[test]
fn beyond_plaso() {
    let (_, log) = read("plaso/atlassian/atlassian-bitbucket.log.gz");
    // `!!!` before the logger: plaso drops it.
    let warned = log.entries.iter().find(|e| e.get("context").is_some());
    assert_eq!(warned.and_then(|e| e.get("context")), Some("!!!"));
    let (_, log) = read("plaso/atlassian/atlassian-bitbucket-audit.log.gz");
    assert_eq!(
        log.entries[0].time.and_then(|t| t.to_iso8601()).as_deref(),
        Some("2014-05-21T14:09:21.9060000Z")
    );
}

/// Unverified: Jira's own layout.
#[test]
fn synthetic_jira() {
    let (kind, log) = read("synthetic/atlassian-jira.log");
    assert_eq!(kind, EntryKind::Application);
    assert!(log.problems.is_empty(), "{:?}", log.problems);
    assert_eq!(log.entries.len(), 3);
    let login = &log.entries[0];
    assert_eq!(
        login.time.and_then(|t| t.to_iso8601()).as_deref(),
        Some("2023-10-03T08:00:45.3170000Z")
    );
    assert_eq!(
        (
            login.user.as_deref(),
            login.client.as_deref(),
            login.get("url")
        ),
        (Some("admin"), Some("192.0.2.10"), Some("/login.jsp"))
    );
    assert_eq!(
        login.thread.as_deref(),
        Some("http-nio-8080-exec-1 url: /login.jsp; user: admin")
    );
    let background = &log.entries[1];
    assert_eq!(
        (
            background.thread.as_deref(),
            background.user.as_deref(),
            background.client.as_ref()
        ),
        (Some("Caesium-1-4"), Some("ServiceRunner"), None)
    );
    let error = &log.entries[2];
    assert_eq!(
        error.time.and_then(|t| t.to_iso8601()).as_deref(),
        Some("2023-10-03T08:02:10.5000000Z")
    );
    assert_eq!(error.client.as_deref(), Some("198.51.100.7,192.0.2.1"));
    assert_eq!(
        (error.get("request_id"), error.get("session")),
        (Some("482x9x2"), Some("9zz8yy7"))
    );
    assert_eq!(error.message.as_deref().map(|m| m.lines().count()), Some(3));
}

/// Unverified: Confluence's request values, a stack trace, Bitbucket's
/// quoted HTTP action.
#[test]
fn synthetic_confluence_and_bitbucket() {
    let (_, log) = read("synthetic/atlassian-confluence.log");
    assert!(log.problems.is_empty(), "{:?}", log.problems);
    let removed = &log.entries[0];
    assert_eq!(
        (
            removed.user.as_deref(),
            removed.action.as_deref(),
            removed.get("url"),
            removed.get("trace_id"),
            removed.get("referer")
        ),
        (
            Some("jsmith"),
            Some("removepage"),
            Some("/pages/removepage.action"),
            Some("5e2a9c1b7d3f4a60"),
            Some("https://wiki.example.com/display/OPS")
        )
    );
    assert_eq!(log.entries[1].method.as_deref(), Some("lambda$doBackup$0"));
    assert!(log.entries[1]
        .message
        .as_deref()
        .unwrap()
        .ends_with("\tat com.example.Backup.write(Backup.java:7)"));
    let (_, log) = read("synthetic/atlassian-bitbucket.log");
    let clone = &log.entries[0];
    assert_eq!(
        (
            clone.user.as_deref(),
            clone.client.as_deref(),
            clone.action.as_deref()
        ),
        (
            Some("john.smith"),
            Some("192.0.2.44"),
            Some("GET /scm/ops/runbooks.git/info/refs HTTP/1.1")
        )
    );
    assert_eq!(clone.message.as_deref(), Some("Clone of ops/runbooks"));
}

/// Unverified: the audit log file.
#[test]
fn synthetic_audit_file() {
    let (kind, log) = read("synthetic/synthetic.audit.log");
    assert_eq!(kind, EntryKind::Audit);
    assert!(log.problems.is_empty(), "{:?}", log.problems);
    let summary: Vec<String> = log
        .entries
        .iter()
        .map(|e| {
            [&e.action, &e.user, &e.client, &e.object]
                .map(|v| v.as_deref().unwrap_or_default())
                .join(" | ")
        })
        .collect();
    assert_eq!(
        summary,
        [
            "User created | admin | 192.0.2.10 | jsmith (USER)",
            "Page removed | jsmith | 198.51.100.7 | Runbook (Page); Operations (Space)",
            "Repository permission granted | john.smith | 192.0.2.44 | ops/runbooks (REPOSITORY)",
        ]
    );
    let created = &log.entries[0];
    assert_eq!(
        created.time.and_then(|t| t.to_iso8601()).as_deref(),
        Some("2023-10-03T08:00:45.3170000Z")
    );
    assert_eq!(
        created.get("changed"),
        Some("Email:  -> jsmith@example.com")
    );
    assert_eq!(
        created.get("attributes"),
        Some("Directory: Jira Internal Directory")
    );
    assert_eq!(created.get("area"), Some("USER_MANAGEMENT"));
    assert_eq!(created.get("system"), Some("https://jira.example.com"));
    assert_eq!(created.get("node"), None);
}
