//! Jira's, Confluence's and Bitbucket's application logs
//! (`atlassian-jira.log`, `atlassian-confluence.log`,
//! `atlassian-bitbucket.log`), Log4j lines in three layouts:
//!
//! ```text
//! 2022-07-12 01:08:59,489 INFO [Catalina-utility-1] [confluence.cluster.hazelcast.HazelcastClusterManager] startCluster Starting the cluster.
//! 2022-04-12 05:39:57,408 INFO [tx:thread-2] admin 2CM38K4Fx339x113x2 @5XDWX5x339x568x0 10.229.31.195 "TransactionService/Transact" c.a.b.m.r.DefaultRepositoryManager Repository … created
//! 2020-06-03 10:43:10,664+0000 http-nio-8080-exec-23 ERROR charlie 643x2264x1 1ia9vad 10.10.10.10 /secure/Dashboard.jspa [c.a.j.util.index.DefaultIndexManager] message
//! ```
//!
//! Confluence's (and plaso's Jira sample's): time, level, thread and
//! logger in brackets, the method, the message; Confluence may end the
//! message with its request's values (` -- url: … | traceId: … |
//! userName: …`). Bitbucket's: time, level, thread in brackets, then its
//! request's values (user, request id, session, address, action in
//! quotes; none for a background thread), the logger and the message.
//! Jira's: time with its offset, thread (a request thread's name adds
//! `url: …; user: …`), level, the request's user, id, session, address
//! and path (blank for a background thread), the logger in brackets and
//! the message.
//!
//! A line that doesn't start with a time continues the entry before it
//! (a stack trace): it is added to the message after a newline.

use crate::{time, value, Entries, Entry};

const LEVELS: [&str; 6] = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"];

/// Whether a line starts an application log entry.
#[must_use]
pub fn is_application(line: &str) -> bool {
    parse(line).is_some_and(|entry| entry.is_ok())
}

/// Read an application log.
pub(crate) fn read(text: &str) -> Entries {
    let mut log = Entries::default();
    for (index, line) in (1..).zip(text.lines()) {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        match parse(line) {
            Some(Ok(mut entry)) => {
                entry.line = index;
                log.entries.push(entry);
            }
            Some(Err(why)) => log.problems.push(format!("line {index}: {why}")),
            None => match log.entries.last_mut() {
                Some(entry) => continue_message(entry, line),
                None => log
                    .problems
                    .push(format!("line {index}: no time, and no entry before it")),
            },
        }
    }
    log
}

/// A continuation line added to an entry's message.
fn continue_message(entry: &mut Entry, line: &str) {
    match &mut entry.message {
        Some(message) => {
            message.push('\n');
            message.push_str(line);
        }
        None => entry.message = Some(line.to_owned()),
    }
}

/// One line: `None` when it doesn't start with a time (a continuation),
/// an error when what follows the time isn't one of the layouts.
fn parse(line: &str) -> Option<Result<Entry, String>> {
    let mut words = line.splitn(3, ' ');
    let stamp = [words.next()?, words.next()?].join(" ");
    let time = time::log4j(&stamp)?;
    let rest = words.next().unwrap_or_default().trim_start();
    let entry = Entry {
        time: Some(time),
        ..Entry::default()
    };
    Some(match rest.split_once(' ') {
        Some((level, after)) if LEVELS.contains(&level) => bracketed(entry, level, after),
        _ => jira(entry, rest),
    })
}

/// After the level, Confluence's `[thread] [logger] method message` or
/// Bitbucket's `[thread] context logger message`.
fn bracketed(mut entry: Entry, level: &str, rest: &str) -> Result<Entry, String> {
    entry.level = Some(level.to_owned());
    let (thread, rest) = rest
        .trim_start()
        .strip_prefix('[')
        .and_then(|r| r.split_once(']'))
        .ok_or("no [thread] after the level")?;
    thread_values(&mut entry, thread);
    match rest.strip_prefix(" [") {
        Some(rest) => confluence(entry, rest),
        None => bitbucket(entry, rest),
    }
}

/// After `[thread] [`: `logger] method message`.
fn confluence(mut entry: Entry, rest: &str) -> Result<Entry, String> {
    let (logger, rest) = rest.split_once(']').ok_or("no ] after the logger")?;
    entry.logger = text(logger);
    let rest = rest.trim_start();
    let (method, message) = rest.split_once(' ').unwrap_or((rest, ""));
    entry.method = text(method);
    entry.message = text(message);
    if let Some((_, suffix)) = message.rsplit_once(" -- ") {
        request_values(&mut entry, suffix);
    }
    Ok(entry)
}

/// The values Confluence ends a message with (` -- url: /x | traceId: … |
/// userName: admin`), those known taken.
fn request_values(entry: &mut Entry, suffix: &str) {
    for pair in suffix.split(" | ") {
        let Some((key, raw)) = pair.split_once(": ") else {
            continue;
        };
        let found = value(raw);
        match key.trim() {
            "userName" if entry.user.is_none() => entry.user = found,
            "action" if entry.action.is_none() => entry.action = found,
            "url" => push(entry, "url", found),
            "referer" => push(entry, "referer", found),
            "traceId" => push(entry, "trace_id", found),
            _ => {}
        }
    }
}

/// After `[thread]`: the request's values, then the logger and message.
fn bitbucket(mut entry: Entry, rest: &str) -> Result<Entry, String> {
    let mut rest = rest.trim_start();
    let mut context = Context::default();
    loop {
        let (token, after) = next_token(rest).ok_or("no logger")?;
        if token.starts_with('"') {
            context.add(token);
        } else if is_class(token) && !(context.is_empty() && next_is_request_id(after)) {
            entry.logger = Some(token.to_owned());
            entry.message = text(after);
            break;
        } else {
            context.add(token);
        }
        rest = after;
    }
    context.into_entry(&mut entry);
    Ok(entry)
}

/// Whether the next word is a request id: then a dotted word before it is
/// a user (`john.smith`), not the logger.
fn next_is_request_id(rest: &str) -> bool {
    next_token(rest).is_some_and(|(token, _)| is_request_id(token))
}

/// Jira's: `thread LEVEL user id session address path [logger] message`.
fn jira(mut entry: Entry, rest: &str) -> Result<Entry, String> {
    let (thread, level, after) = LEVELS
        .iter()
        .filter_map(|level| {
            let at = rest.find(&format!(" {level} "))?;
            Some((&rest[..at], *level, &rest[at + level.len() + 2..]))
        })
        .min_by_key(|(thread, _, _)| thread.len())
        .ok_or("no level after the time")?;
    entry.level = Some(level.to_owned());
    thread_values(&mut entry, thread);
    let (context, rest) = after.split_once('[').ok_or("no [logger] after the level")?;
    let (logger, message) = rest.split_once(']').ok_or("no ] after the logger")?;
    let mut values = Context::default();
    let mut words = context;
    while let Some((token, after)) = next_token(words) {
        values.add(token);
        words = after;
    }
    values.into_entry(&mut entry);
    entry.logger = text(logger);
    entry.message = text(message);
    Ok(entry)
}

/// A thread's name, and the values Jira adds to a request thread's
/// (`http-nio-8080-exec-7 url: /secure/Dashboard.jspa; user: admin`).
fn thread_values(entry: &mut Entry, thread: &str) {
    entry.thread = text(thread);
    let Some((_, values)) = thread.split_once(" url: ") else {
        return;
    };
    let (url, user) = match values.split_once("; user: ") {
        Some((url, user)) => (url, Some(user)),
        None => (values, None),
    };
    push(entry, "url", value(url));
    entry.user = user.and_then(value);
}

/// A request's values before the logger, told apart by their shape.
#[derive(Default)]
struct Context {
    user: Option<String>,
    request_id: Option<String>,
    session: Option<String>,
    client: Option<String>,
    action: Option<String>,
    url: Option<String>,
    /// What isn't any of these (Bitbucket's `!!!`).
    other: Vec<String>,
    /// Words seen.
    seen: usize,
}

impl Context {
    fn is_empty(&self) -> bool {
        self.seen == 0
    }

    fn add(&mut self, token: &str) {
        let first = self.seen == 0;
        let after_request_id = self.request_id.is_some() && self.session.is_none();
        self.seen += 1;
        if let Some(action) = token.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
            self.action = value(action);
        } else if is_request_id(token) && self.request_id.is_none() {
            self.request_id = value(token);
        } else if token.starts_with(['@', '*']) && self.session.is_none() {
            self.session = value(token);
        } else if token.starts_with('/') && self.url.is_none() {
            self.url = value(token);
        } else if is_address(token) && self.client.is_none() {
            self.client = value(token);
        } else if after_request_id {
            self.session = value(token);
        } else if first && is_user(token) {
            self.user = value(token);
        } else {
            self.other.push(token.to_owned());
        }
    }

    fn into_entry(self, entry: &mut Entry) {
        if self.user.is_some() {
            entry.user = self.user;
        }
        entry.client = self.client;
        entry.action = self.action;
        push(entry, "request_id", self.request_id);
        push(entry, "session", self.session);
        if entry.get("url").is_none() {
            push(entry, "url", self.url);
        }
        if !self.other.is_empty() {
            push(entry, "context", Some(self.other.join(" ")));
        }
    }
}

/// Text trimmed, empty meaning none (`-` kept: a message may be one).
fn text(text: &str) -> Option<String> {
    Some(text.trim())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
}

fn push(entry: &mut Entry, name: &'static str, text: Option<String>) {
    if let Some(text) = text {
        entry.extra.push((name, text));
    }
}

/// The next word, or a quoted string whole, and what follows it.
fn next_token(text: &str) -> Option<(&str, &str)> {
    let text = text.trim_start();
    if text.is_empty() {
        return None;
    }
    let end = match text.strip_prefix('"') {
        Some(quoted) => quoted.find('"').map_or(text.len(), |at| at + 2),
        None => text.find(' ').unwrap_or(text.len()),
    };
    Some((&text[..end], &text[end..]))
}

/// A Java class name, maybe abbreviated: dotted words, each starting with a
/// letter (`c.a.b.m.r.DefaultRepositoryManager`, `org.hibernate.SQL`).
fn is_class(token: &str) -> bool {
    let mut parts = token.split('.');
    let valid = |part: &str| {
        part.chars().next().is_some_and(char::is_alphabetic)
            && part
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
    };
    parts.clone().count() >= 2 && parts.all(valid)
}

/// A request id: Jira's `643x2264x1`, Bitbucket's `2CM38K4Fx339x113x2`.
fn is_request_id(token: &str) -> bool {
    let parts: Vec<&str> = token.split('x').collect();
    let digits = |part: &&str| part.bytes().all(|b| b.is_ascii_digit());
    parts.len() >= 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric()))
        && parts[parts.len() - 2..].iter().all(digits)
}

/// An IPv4 or IPv6 address, or several comma-separated.
fn is_address(token: &str) -> bool {
    token.split(',').all(|address| {
        let v4 = address.split('.').count() == 4
            && address
                .split('.')
                .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()));
        let v6 = address.matches(':').count() >= 2
            && address.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
        v4 || v6
    })
}

/// A user name: a letter first, then letters, digits, `.`, `_`, `-`, `/`,
/// `@` (plaso's, with `@`).
fn is_user(token: &str) -> bool {
    token.chars().next().is_some_and(char::is_alphabetic)
        && token
            .chars()
            .all(|c| c.is_alphanumeric() || "._-/@".contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(line: &str) -> Entry {
        parse(line).unwrap().unwrap()
    }

    #[test]
    fn jira_request_and_background_lines() {
        let line = entry("2020-06-03 10:43:10,664+0000 http-nio-8080-exec-23 url: /secure/admin/IndexReIndex.jspa; user: charlie ERROR charlie 643x2264x1 1ia9vad 10.10.10.10,172.31.2.2 /secure/admin/IndexReIndex.jspa [c.a.j.util.index.DefaultIndexManager] Re-index failed");
        assert_eq!(
            line.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2020-06-03T10:43:10.6640000Z")
        );
        assert_eq!(line.level.as_deref(), Some("ERROR"));
        assert_eq!(line.user.as_deref(), Some("charlie"));
        assert_eq!(line.client.as_deref(), Some("10.10.10.10,172.31.2.2"));
        assert_eq!(line.get("request_id"), Some("643x2264x1"));
        assert_eq!(line.get("session"), Some("1ia9vad"));
        assert_eq!(line.get("url"), Some("/secure/admin/IndexReIndex.jspa"));
        assert_eq!(
            line.logger.as_deref(),
            Some("c.a.j.util.index.DefaultIndexManager")
        );
        assert_eq!(line.message.as_deref(), Some("Re-index failed"));
        let line = entry("2020-06-03 10:44:00,001+0000 Caesium-1-4 INFO ServiceRunner     [c.a.jira.service.ServiceRunner] Mail queue run");
        assert_eq!(line.thread.as_deref(), Some("Caesium-1-4"));
        assert_eq!(line.user.as_deref(), Some("ServiceRunner"));
        assert_eq!(line.get("request_id"), None);
    }

    #[test]
    fn bitbucket_users_with_dots_and_odd_context() {
        let line = entry("2022-04-12 05:39:57,408 INFO [http-nio-7990-exec-3] john.smith 1A2B3Cx339x113x2 @5XDWX5x339x568x0 10.0.0.9 \"GET /scm/p/r.git/info/refs HTTP/1.1\" c.a.b.i.s.g.GitSmartHttpHandler Fetch");
        assert_eq!(line.user.as_deref(), Some("john.smith"));
        assert_eq!(
            line.action.as_deref(),
            Some("GET /scm/p/r.git/info/refs HTTP/1.1")
        );
        assert_eq!(
            line.logger.as_deref(),
            Some("c.a.b.i.s.g.GitSmartHttpHandler")
        );
        let line = entry("2022-06-24 08:01:19,381 WARN [git:gc:thread-1] !!! c.a.s.i.r.DefaultRepositorySizeCache Size calculation failed");
        assert_eq!(line.get("context"), Some("!!!"));
        assert_eq!(line.user, None);
    }

    #[test]
    fn confluence_request_values_and_stack_traces() {
        let log = read("2022-07-12 01:40:00,000 ERROR [http-nio-8090-exec-5] [atlassian.confluence.servlet.ConfluenceServletDispatcher] sendError Could not find action -- referer: http://wiki/ | url: /pages/x.action | traceId: 3f1b | userName: jdoe\njava.lang.RuntimeException: boom\n\tat com.example.X.run(X.java:1)\n");
        assert!(log.problems.is_empty());
        let line = &log.entries[0];
        assert_eq!(line.user.as_deref(), Some("jdoe"));
        assert_eq!(line.get("url"), Some("/pages/x.action"));
        assert_eq!(line.get("trace_id"), Some("3f1b"));
        assert!(line.message.as_deref().unwrap().ends_with(
            "userName: jdoe\njava.lang.RuntimeException: boom\n\tat com.example.X.run(X.java:1)"
        ));
        let log = read("\tat orphan\n2022-07-12 01:40:00,000 NOPE x\n");
        assert_eq!(log.problems.len(), 2);
    }
}
