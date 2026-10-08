//! Atlassian's access logs.
//!
//! Jira and Confluence (Tomcat's valve, `access_log.<date>` and
//! `conf_access_log.<date>`):
//!
//! ```text
//! [time] user thread client method path protocol status 350ms bytes referer user agent…
//! [time] forwarded-for user thread client method …          (Confluence 7.11, Jira 9.4 and later)
//! ```
//!
//! Bitbucket (`atlassian-bitbucket-access.log`), fields between ` | `:
//! client, protocol, request id (`i@…` as it came in, `o@…` as it went
//! out), user, time (local), action, `"referer" "agent"`, status, bytes
//! read, bytes written, labels, duration, session; gRPC lines add a mesh
//! execution id after the request id and two counters before the labels.

use crate::{request_line, time, value, Request};

/// Whether a line looks like a Jira or Confluence access log line.
#[must_use]
pub fn is_access(line: &str) -> bool {
    line.strip_prefix('[')
        .and_then(|rest| rest.split_once("] "))
        .is_some_and(|(stamp, rest)| time::clf(stamp).is_some() && method_at(rest).is_some())
}

/// Where the method is among the words after the time: 3 (user, thread,
/// client) or 4 (forwarded-for first).
fn method_at(rest: &str) -> Option<usize> {
    let words: Vec<&str> = rest.split(' ').take(6).collect();
    [3, 4].into_iter().find(|&at| {
        words
            .get(at)
            .is_some_and(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_uppercase()))
            && words
                .get(at - 2)
                .is_some_and(|w| w.contains("exec") || w.contains('-'))
    })
}

/// One Jira or Confluence line.
///
/// # Errors
/// Why the line isn't one.
pub fn parse_access(line: &str) -> Result<Request, String> {
    let (stamp, rest) = line
        .strip_prefix('[')
        .and_then(|rest| rest.split_once("] "))
        .ok_or("no [time]")?;
    let mut request = Request {
        time: Some(time::clf(stamp).ok_or_else(|| format!("a time {stamp:?} not read"))?),
        ..Request::default()
    };
    let at = method_at(rest).ok_or("no method where one is expected")?;
    let mut words = rest.splitn(at + 8, ' ');
    let mut next = || words.next().unwrap_or_default();
    if at == 4 {
        if let Some(forwarded) = value(next()) {
            request.extra.push(("forwarded_for", forwarded));
        }
    }
    request.user = value(next());
    if let Some(thread) = value(next()) {
        request.extra.push(("thread", thread));
    }
    request.client = value(next());
    let line = [next(), next(), next()].join(" ");
    request_line(&line, &mut request);
    request.status = next().parse().ok();
    request.duration_ms = next().strip_suffix("ms").and_then(|d| d.parse().ok());
    request.bytes = next().parse().ok();
    request.referer = value(next());
    request.user_agent = value(next());
    Ok(request)
}

/// Whether a line looks like a Bitbucket access log line.
#[must_use]
pub fn is_bitbucket(line: &str) -> bool {
    let fields: Vec<&str> = line.split(" | ").collect();
    fields.len() >= 12
        && fields
            .get(1)
            .is_some_and(|p| ["http", "https", "ssh", "grpc"].contains(&p.trim()))
        && fields[3..6].iter().any(|f| time::log4j(f).is_some())
}

/// One Bitbucket line.
///
/// # Errors
/// Why the line isn't one.
pub fn parse_bitbucket(line: &str) -> Result<Request, String> {
    let fields: Vec<&str> = line
        .trim_end_matches(" |")
        .split(" | ")
        .map(str::trim)
        .collect();
    let get = |at: usize| fields.get(at).copied().unwrap_or_default();
    // gRPC lines add a mesh execution id after the request id, and two
    // counters before the labels (no duration).
    let mesh = get(3).starts_with('@');
    let after = usize::from(mesh);
    let at = |index: usize| get(index + after);
    let time_text = at(4);
    let mut request = Request {
        client: value(get(0)),
        user: value(at(3)),
        time: Some(time::log4j(time_text).ok_or_else(|| format!("a time {time_text:?} not read"))?),
        ..Request::default()
    };
    request.extra.push(("protocol", get(1).to_owned()));
    if let Some(id) = value(get(2)) {
        request.extra.push(("request_id", id));
    }
    if mesh {
        request.extra.push(("mesh_execution_id", get(3).to_owned()));
    }
    action(at(5).trim_matches('"'), &mut request);
    let mut agent = at(6).split("\" \"");
    request.referer = agent.next().and_then(|r| value(r.trim_start_matches('"')));
    request.user_agent = agent.next().and_then(|a| value(a.trim_end_matches('"')));
    request.status = at(7).parse().ok();
    if let Some(read) = value(at(8)) {
        request.extra.push(("bytes_read", read));
    }
    request.bytes = at(9).parse().ok();
    let (labels, session) = if mesh {
        (at(12), at(13))
    } else {
        request.duration_ms = at(11).parse().ok();
        (at(10), at(12))
    };
    if let Some(labels) = value(labels) {
        request.extra.push(("labels", labels));
    }
    if let Some(session) = value(session) {
        request.extra.push(("session", session));
    }
    Ok(request)
}

/// The action: an HTTP request line, `SSH - <command> '<repository>'`, or
/// a gRPC method.
fn action(text: &str, request: &mut Request) {
    if let Some(ssh) = text.strip_prefix("SSH - ") {
        request.method = Some("SSH".to_owned());
        let (command, repository) = ssh.split_once(' ').unwrap_or((ssh, ""));
        request.uri = value(command);
        if let Some(repository) = value(repository.trim_matches('\'')) {
            request.extra.push(("repository", repository));
        }
    } else {
        request_line(text, request);
    }
}
