//! Web server access logs, for forensics: what web shells, exploitation
//! and data theft leave behind, one request per line.
//!
//! - [`access`]: Apache and nginx in the NCSA formats (common, combined,
//!   and combined with the virtual host first).
//! - [`atlassian`]: Jira and Confluence access logs, and Bitbucket's
//!   `atlassian-bitbucket-access.log`.
//! - [`elb`]: AWS Elastic Load Balancing access logs (classic, application
//!   and network load balancers).
//! - [`azure`]: Azure Application Gateway's access log (diagnostic
//!   settings' JSON).
//!
//! And Atlassian's other logs, read into entries rather than requests
//! ([`detect_entries`], [`read_entries`]):
//!
//! - [`application`]: Jira's, Confluence's and Bitbucket's application
//!   logs (`atlassian-jira.log`, `atlassian-confluence.log`,
//!   `atlassian-bitbucket.log`).
//! - [`audit`]: Bitbucket's audit log (`atlassian-bitbucket-audit.log`)
//!   and the audit log file Jira, Confluence and Bitbucket Data Center
//!   write (`log/audit/*.audit.log`, JSON lines).
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
//! Text is read as UTF-8, invalid bytes replaced. Lines (or records) that
//! can't be read go to `problems`, never a panic.

pub mod access;
pub mod application;
pub mod atlassian;
pub mod audit;
pub mod azure;
pub mod elb;
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
    /// AWS Elastic Load Balancing (classic, application, network).
    Elb,
    /// Azure Application Gateway's access log (JSON records).
    AzureGateway,
}

/// A request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    /// Its line, from 1 (a JSON document's record: its position).
    pub line: usize,
    /// When it was logged: UTC when the log gives its offset (Apache,
    /// nginx, Jira, Confluence, ELB's classic and application load
    /// balancers, Azure), local otherwise (Bitbucket, ELB's network load
    /// balancers).
    pub time: Option<Ts>,
    /// When the request came in, when the log says so apart from `time`
    /// (an application load balancer's `request_creation_time`, a network
    /// load balancer's `tls_connection_creation_time`).
    pub started: Option<Ts>,
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
    /// `request_id`, `session`, `labels`, `bytes_read`, ELB's and Azure's
    /// by theirs, …).
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
/// (up to five) all of one format, or Azure's JSON.
#[must_use]
pub fn detect(_name: &str, head: &[u8]) -> Option<Kind> {
    let text = String::from_utf8_lossy(head);
    if azure::is_access(&text) {
        return Some(Kind::AzureGateway);
    }
    let mut lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    // The last line may be cut where the head ends.
    if lines.len() > 1 && !text.ends_with('\n') {
        lines.pop();
    }
    lines.truncate(5);
    let all = |test: fn(&str) -> bool| !lines.is_empty() && lines.iter().all(|l| test(l));
    if all(atlassian::is_bitbucket) {
        Some(Kind::Bitbucket)
    } else if all(elb::is_access) {
        Some(Kind::Elb)
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
        Kind::Elb => elb::parse,
        Kind::AzureGateway => return azure::read(&text),
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

/// A kind of Atlassian log of entries (not requests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// Jira, Confluence or Bitbucket's application log
    /// (`time level [thread] …`).
    Application,
    /// Bitbucket's audit log (`address | event | user | milliseconds | …`).
    BitbucketAudit,
    /// The audit log file of Jira, Confluence and Bitbucket Data Center
    /// (JSON lines).
    Audit,
}

/// An entry of an application or audit log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// Its line, from 1 (an application entry's first).
    pub line: usize,
    /// When it was logged: local for application logs without an offset,
    /// UTC otherwise (Jira's with `+0000`, audit logs').
    pub time: Option<Ts>,
    /// The level (`INFO`, `WARN`, …).
    pub level: Option<String>,
    /// The thread (`http-nio-8080-exec-1`).
    pub thread: Option<String>,
    /// The logger, a Java class (`c.a.b.m.r.DefaultRepositoryManager`).
    pub logger: Option<String>,
    /// The method that logged it (Confluence's: `startCluster`).
    pub method: Option<String>,
    /// The user: the one acting, or an audit event's author.
    pub user: Option<String>,
    /// The client's address (Bitbucket: every proxy's, comma-separated).
    pub client: Option<String>,
    /// What was done: an audit event (`RepositoryCreatedEvent`, `User
    /// created`), Bitbucket's request action (`TransactionService/Transact`).
    pub action: Option<String>,
    /// What an audit event was done to (`PROJECT/myproject`, `admin (USER)`).
    pub object: Option<String>,
    /// The message; an application entry's continuation lines (a stack
    /// trace) after a newline.
    pub message: Option<String>,
    /// The format's other values, by name (`request_id`, `session`, `url`,
    /// `details`, `area`, `changed`, …).
    pub extra: Vec<(&'static str, String)>,
}

impl Entry {
    /// An extra value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.extra
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A log's entries and what couldn't be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entries {
    /// The entries, in order.
    pub entries: Vec<Entry>,
    /// The lines that couldn't be read, with why.
    pub problems: Vec<String>,
}

/// Which Atlassian application or audit log `head` starts like, if any:
/// its first complete line.
#[must_use]
pub fn detect_entries(_name: &str, head: &[u8]) -> Option<EntryKind> {
    let text = String::from_utf8_lossy(head);
    let text = text.trim_start_matches('\u{feff}');
    let first = text.lines().find(|l| !l.trim().is_empty())?;
    if audit::is_audit(first) {
        Some(EntryKind::Audit)
    } else if audit::is_bitbucket(first) {
        Some(EntryKind::BitbucketAudit)
    } else if application::is_application(first) {
        Some(EntryKind::Application)
    } else {
        None
    }
}

/// Read a log of entries of `kind`.
#[must_use]
pub fn read_entries(kind: EntryKind, data: &[u8]) -> Entries {
    let text = String::from_utf8_lossy(data);
    let text = text.trim_start_matches('\u{feff}');
    match kind {
        EntryKind::Application => application::read(text),
        EntryKind::BitbucketAudit => audit::read(text, audit::parse_bitbucket),
        EntryKind::Audit => audit::read(text, audit::parse_audit),
    }
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
