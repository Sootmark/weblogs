//! Web server access logs, for forensics: what web shells, exploitation
//! and data theft leave behind, one request per line.
//!
//! - [`access`]: Apache and nginx in the NCSA formats (common, combined,
//!   and combined with the virtual host first).
//! - [`atlassian`]: Jira and Confluence access logs, and Bitbucket's
//!   `atlassian-bitbucket-access.log`.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let data = std::fs::read("/var/log/apache2/access.log")?;
//! if let Some(kind) = weblogs::detect("access.log", &data) {
//!     for request in weblogs::read(kind, &data).requests {
//!         println!("{:?} {:?} {} {:?}", request.time, request.client, request.request(), request.status);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Text is read as UTF-8, invalid bytes replaced. Lines that can't be read
//! go to `problems`, never a panic.

pub mod access;
pub mod atlassian;
mod time;

use common::time::Ts;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A kind of access log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Apache or nginx, NCSA common or combined, the virtual host first or
    /// not.
    Access,
    /// Jira or Confluence (`[time] user thread address method …`).
    Atlassian,
    /// Bitbucket (`address | protocol | id | user | time | …`).
    Bitbucket,
}

/// A request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    /// Its line, from 1.
    pub line: usize,
    /// When it was logged: UTC when the log gives its offset (Apache,
    /// nginx, Jira, Confluence), local otherwise (Bitbucket).
    pub time: Option<Ts>,
    /// The client's address (Bitbucket: every proxy's, comma-separated).
    pub client: Option<String>,
    /// The authenticated user.
    pub user: Option<String>,
    /// The method (`GET`, `POST`, Bitbucket's `SSH`).
    pub method: Option<String>,
    /// The path and query, as sent (or what the request line holds when it
    /// isn't `method path protocol`).
    pub uri: Option<String>,
    /// The protocol (`HTTP/1.1`).
    pub protocol: Option<String>,
    /// The response's status.
    pub status: Option<u16>,
    /// The bytes sent.
    pub bytes: Option<u64>,
    /// The `Referer` header.
    pub referer: Option<String>,
    /// The `User-Agent` header.
    pub user_agent: Option<String>,
    /// The virtual host (Apache's `vhost_combined`).
    pub host: Option<String>,
    /// The virtual host's port.
    pub port: Option<u16>,
    /// How long it took, in milliseconds.
    pub duration_ms: Option<u64>,
    /// The format's other values, by name (`thread`, `forwarded_for`,
    /// `request_id`, `session`, `labels`, `bytes_read`, …).
    pub extra: Vec<(&'static str, String)>,
}

impl Request {
    /// The request line: method, path and protocol, as far as known.
    #[must_use]
    pub fn request(&self) -> String {
        [&self.method, &self.uri, &self.protocol]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// An extra value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.extra
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A log's requests and what couldn't be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Log {
    /// The requests, in order.
    pub requests: Vec<Request>,
    /// The lines that couldn't be read, with why.
    pub problems: Vec<String>,
}

/// Which access log `head` starts like, if any: its first complete lines
/// (up to five) all of one format.
#[must_use]
pub fn detect(_name: &str, head: &[u8]) -> Option<Kind> {
    let text = String::from_utf8_lossy(head);
    let mut lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    // The last line may be cut where the head ends.
    if lines.len() > 1 && !text.ends_with('\n') {
        lines.pop();
    }
    lines.truncate(5);
    let all = |test: fn(&str) -> bool| !lines.is_empty() && lines.iter().all(|l| test(l));
    if all(atlassian::is_bitbucket) {
        Some(Kind::Bitbucket)
    } else if all(atlassian::is_access) {
        Some(Kind::Atlassian)
    } else if all(access::is_access) {
        Some(Kind::Access)
    } else {
        None
    }
}

/// Read a log of `kind`.
#[must_use]
pub fn read(kind: Kind, data: &[u8]) -> Log {
    let text = String::from_utf8_lossy(data);
    let parse: fn(&str) -> Result<Request, String> = match kind {
        Kind::Access => access::parse,
        Kind::Atlassian => atlassian::parse_access,
        Kind::Bitbucket => atlassian::parse_bitbucket,
    };
    let mut log = Log::default();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match parse(line.trim_end_matches('\r')) {
            Ok(mut request) => {
                request.line = index + 1;
                log.requests.push(request);
            }
            Err(why) => log.problems.push(format!("line {}: {why}", index + 1)),
        }
    }
    log
}

/// `-` and empty mean none.
fn value(text: &str) -> Option<String> {
    Some(text.trim())
        .filter(|t| !t.is_empty() && *t != "-")
        .map(str::to_owned)
}

/// A request line (`GET /x HTTP/1.1`) into method, path and protocol; one
/// that isn't three parts is kept whole as the path.
fn request_line(line: &str, request: &mut Request) {
    let line = line.trim();
    let parts: Option<(&str, &str, &str)> = line.split_once(' ').and_then(|(method, rest)| {
        let (uri, protocol) = rest.rsplit_once(' ')?;
        let is_method = !method.is_empty() && method.bytes().all(|b| b.is_ascii_uppercase());
        (is_method && protocol.starts_with("HTTP/")).then_some((method, uri, protocol))
    });
    match parts {
        Some((method, uri, protocol)) => {
            request.method = Some(method.to_owned());
            request.uri = Some(uri.to_owned());
            request.protocol = Some(protocol.to_owned());
        }
        None => request.uri = value(line),
    }
}
