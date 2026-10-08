//! Apache and nginx access logs in the NCSA formats:
//!
//! ```text
//! common:         client ident user [time] "request" status bytes
//! combined:       … "referer" "user agent"
//! vhost_combined: host:port client ident user [time] "request" …
//! ```
//!
//! A request line may hold quotes of its own (exploits often do): it ends
//! at the first quote followed by a status. The referer and user agent are
//! split where a quote, a space and a quote meet; a value cut short (a
//! truncated user agent) is read to the line's end.

use crate::{request_line, time, value, Request};

/// Whether a line looks like an NCSA access log line.
#[must_use]
pub fn is_access(line: &str) -> bool {
    let Some((before, after)) = line.split_once(" [") else {
        return false;
    };
    let fields = before.split_whitespace().count();
    (3..=4).contains(&fields)
        && after
            .split_once(']')
            .is_some_and(|(stamp, rest)| time::clf(stamp).is_some() && rest.starts_with(" \""))
}

/// One line.
///
/// # Errors
/// Why the line isn't one.
pub fn parse(line: &str) -> Result<Request, String> {
    let (before, after) = line.split_once(" [").ok_or("no [time]")?;
    let fields: Vec<&str> = before.split_whitespace().collect();
    let mut request = Request::default();
    let (client, user) = match fields[..] {
        [host, client, _, user] => {
            let (name, port) = host.rsplit_once(':').unwrap_or((host, ""));
            request.host = value(name);
            request.port = port.parse().ok();
            (client, user)
        }
        [client, _, user] => (client, user),
        _ => return Err(format!("{} fields before the time", fields.len())),
    };
    request.client = value(client);
    request.user = value(user);
    let (stamp, rest) = after.split_once(']').ok_or("no ] after the time")?;
    request.time = Some(time::clf(stamp).ok_or_else(|| format!("a time {stamp:?} not read"))?);
    let rest = rest.strip_prefix(" \"").ok_or("no quoted request")?;
    let (line, tail) = split_request(rest).ok_or("no status after the request")?;
    request_line(line, &mut request);
    let mut tail = tail.trim_start().splitn(3, ' ');
    let status = tail.next().unwrap_or_default();
    request.status = status.parse().ok();
    request.bytes = tail.next().and_then(|b| b.parse().ok());
    let mut quoted = quoted_values(tail.next().unwrap_or_default());
    request.referer = quoted.next().and_then(value);
    request.user_agent = quoted.next().and_then(value);
    Ok(request)
}

/// The request line (inside its quotes) and what follows its closing
/// quote: the first quote followed by a status (three digits or `-`).
fn split_request(rest: &str) -> Option<(&str, &str)> {
    let mut from = 0;
    while let Some(found) = rest[from..].find("\" ") {
        let at = from + found;
        let next = rest[at + 2..].split(' ').next().unwrap_or_default();
        if next == "-" || (next.len() == 3 && next.bytes().all(|b| b.is_ascii_digit())) {
            return Some((&rest[..at], &rest[at + 1..]));
        }
        from = at + 1;
    }
    None
}

/// The quoted values of `text` (`"a" "b"`), split where a quote, a space
/// and a quote meet, so a value may hold quotes; one cut short runs to the
/// end.
fn quoted_values(text: &str) -> impl Iterator<Item = &str> {
    let text = text.trim();
    let body = text
        .strip_prefix('"')
        .map(|t| t.strip_suffix('"').unwrap_or(t));
    body.into_iter().flat_map(|body| body.split("\" \""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_inside_values() {
        let request = parse(r#"1.2.3.4 - - [25/Apr/2021:06:15:33 +0000] "GET /a?t=<script>alert("x")</script> HTTP/1.0" 404 1164 "-" "Mozilla "quoted" 5""#).unwrap();
        assert_eq!(
            request.uri.as_deref(),
            Some(r#"/a?t=<script>alert("x")</script>"#)
        );
        assert_eq!(request.status, Some(404));
        assert_eq!(request.referer, None);
        assert_eq!(request.user_agent.as_deref(), Some(r#"Mozilla "quoted" 5"#));
    }

    #[test]
    fn nginx_bad_requests_and_cut_agents() {
        let request = parse(r#"5.6.7.8 - - [25/Apr/2021:06:15:33 +0000] "\x16\x03\x01" 400 157 "-" "Googlebot (+http://"#).unwrap();
        assert_eq!(
            (request.method.as_deref(), request.uri.as_deref()),
            (None, Some(r"\x16\x03\x01"))
        );
        assert_eq!(request.user_agent.as_deref(), Some("Googlebot (+http://"));
        assert!(parse("hello").is_err());
        assert!(parse(r#"a b c [25/Apr/2021:06:15:33 +0000] "GET / HTTP/1.1""#).is_err());
    }
}
