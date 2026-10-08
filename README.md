# weblogs

Web server access logs, for forensics: what web shells, exploitation and data theft leave behind, one request per line, read into the client, user, time, request, status, bytes, referer and user agent; and Atlassian's application and audit logs, read into entries. One dependency, its sibling `sootmark-common` (JSON, times).

```toml
[dependencies]
sootmark-weblogs = "0.3"
```

```rust
let data = std::fs::read("/var/log/apache2/access.log")?;
if let Some(kind) = weblogs::detect("access.log", &data) {
    for request in weblogs::read(kind, &data).requests {
        println!("{:?} {:?} {} {:?}", request.time, request.client, request.request(), request.status);
    }
}

let data = std::fs::read("atlassian-bitbucket-audit.log")?;
if let Some(kind) = weblogs::detect_entries("atlassian-bitbucket-audit.log", &data) {
    for entry in weblogs::read_entries(kind, &data).entries {
        println!("{:?} {:?} {:?} {:?} {:?}", entry.time, entry.user, entry.client, entry.action, entry.object);
    }
}
```

## What you get

- `detect(name, head)`: the format, from the first lines' shape.
- Apache and nginx (`access`): the NCSA common and combined formats, the virtual host and port first or not (`vhost_combined`). A request line may hold quotes of its own, as exploits' often do; a line nginx couldn't read as HTTP (`"\x16\x03…"`) keeps its bytes as the path; a user agent cut short is kept.
- Jira and Confluence (`atlassian`): their Tomcat access logs, with the user, thread, duration and, from Confluence 7.11 and Jira 9.4, the forwarded-for address.
- Bitbucket (`atlassian`): `atlassian-bitbucket-access.log`: HTTP, SSH (command and repository) and gRPC lines, with the request id (`i@` in, `o@` out), bytes read and written, labels (`push`, access tokens), duration and session.
- AWS Elastic Load Balancing (`elb`): classic, application and network load balancers' access logs, told apart by shape: client and port, the target (backend, destination) and its port, the load balancer's status and the target's, bytes in and out, the request, user agent, TLS cipher and protocol, and the application load balancer's trace id, SNI domain, rule, actions, redirect, error reason and when the request came in (`started`); every value by AWS's name.
- Azure Application Gateway (`azure`): the access log as diagnostic settings write it (a storage account's `PT1H.json`, JSON lines or an array; v1 and v2 gateways): client and port, method, original URI with its query, protocol, status, bytes, user agent, original host, time taken, instance, backend server and its status, TLS, WAF mode, transaction id. Records of the gateway's other logs are counted in `problems`.
- `detect_entries(name, head)` and `read_entries(kind, data)`: Atlassian's logs of entries rather than requests, each `Entry` with its time, level, thread, logger, method, user, client address, action, affected object, message and the rest by name:
  - Application logs (`application`): `atlassian-confluence.log` (`time level [thread] [logger] method message`, and the request's referer, URL, trace id, user and action Confluence may end a message with), `atlassian-bitbucket.log` (`time level [thread]`, then the request's user, request id, session, address and quoted action, the logger, the message) and `atlassian-jira.log` (Jira's layout: the time with its offset, the thread, with a request's URL and user, the level, the request's user, id, session, address and path, the logger in brackets; and plaso's Jira sample, in Confluence's layout). Request values are told apart by their shape (a request id `643x2264x1`, a session `@…`, an address, a path), so blank ones on background threads are simply absent; what is none of them is kept (`context`). A line that doesn't start with a time continues the entry before it (a stack trace), added to its message after a newline.
  - Bitbucket's audit log (`audit`, `atlassian-bitbucket-audit.log`): client addresses (every proxy's), event, user, time (milliseconds, UTC), object (`PROJECT/myproject`), details (JSON, kept as written, even holding ` | `), request id and session.
  - The audit log file of Jira, Confluence and Bitbucket Data Center (`audit`, `log/audit/*.audit.log`, JSON lines): time (`epochSecond` and `nano`, milliseconds, or ISO 8601; UTC), action (`auditType.action`), author, source address, affected objects (`name (TYPE)`), area, category, coverage level, method, system, node, author id and type, changed values (`key: from -> to`) and extra attributes.
- Times in UTC where the log gives its offset; Bitbucket's and network load balancers' are local, their zone not recorded, as are Confluence's and Bitbucket's application logs' (Jira's carry their offset). Lines that can't be read go to `problems`, never a panic.

Not yet: Application Gateway's firewall and performance logs, Log Analytics' `AzureDiagnostics` exports, Gateway Load Balancer logs; Atlassian's other logs (`atlassian-jira-security.log`, Confluence's `atlassian-synchrony.log`), and the audit log as Jira's and Confluence's database or REST API export it.

## How it's checked

- plaso's test logs (Apache-2.0, `tests/fixtures/plaso/`, see `NOTICE`): every one of the 44 requests plaso reads from them with its own parsers, read the same (`tests/oracle/`); beyond plaso, a Googlebot line whose user agent was cut short, which plaso's grammar rejects. And every one of the 28 events plaso reads from its AWS ELB and Azure Application Gateway samples (16 load balancer lines, application load balancers' with two times; 2 gateway records), read the same, but where plaso keeps AWS's marks for none (`-`, `-1` bytes) and the spaces of an empty request line.
- Atlassian application and audit logs: plaso's `atlassian-confluence.log`, `atlassian-jira.log`, `atlassian-bitbucket.log` and `atlassian-bitbucket-audit.log` (commit `91b6849`, `tests/fixtures/plaso/atlassian/`), against plaso 20260720's `text/atlassian_confluence`, `text/atlassian_jira`, `text/atlassian_bitbucket` and `text/bitbucket_audit` (`tests/oracle/atlassian.tsv`, commands in `tests/oracle/README`): all 22 events identical (4 Confluence, 7 Jira, 6 Bitbucket, 5 audit): time, level, thread, logger, method, message, user, address, request id, session, action, event, entity, details. Differences: plaso's Jira and Confluence plugins are the same grammar, so plaso reads Jira's sample with the first, `text/atlassian_confluence`; with all four plugins enabled plaso reads Jira's and Confluence's samples with `text/atlassian_bitbucket`, the logger's closing bracket and the method left in the message (`] startCluster Starting the cluster.`), which this crate doesn't (the oracle runs the Bitbucket and the Jira and Confluence plugins apart). Beyond plaso: Bitbucket's unclassified context (`!!!`), kept; continuation lines, which plaso drops; a dotted user name, which plaso's grammar would take for the logger; Jira's own layout, Confluence's request values and the audit log file, on synthetic logs (`tests/fixtures/synthetic/`, made by `gen.py` from Atlassian's documented layouts; unverified, plaso reads none of them).
- Property tests: arbitrary text and lines cut anywhere give requests, entries, problems or nothing, never a panic.

## Licence

MIT or Apache-2.0, at your option.
