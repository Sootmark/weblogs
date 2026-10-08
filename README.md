# weblogs

Web server access logs, for forensics: what web shells, exploitation and data theft leave behind, one request per line, read into the client, user, time, request, status, bytes, referer and user agent. One dependency, its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-weblogs = "0.1"
```

```rust
let data = std::fs::read("/var/log/apache2/access.log")?;
if let Some(kind) = weblogs::detect("access.log", &data) {
    for request in weblogs::read(kind, &data).requests {
        println!("{:?} {:?} {} {:?}", request.time, request.client, request.request(), request.status);
    }
}
```

## What you get

- `detect(name, head)`: the format, from the first lines' shape.
- Apache and nginx (`access`): the NCSA common and combined formats, the virtual host and port first or not (`vhost_combined`). A request line may hold quotes of its own, as exploits' often do; a line nginx couldn't read as HTTP (`"\x16\x03…"`) keeps its bytes as the path; a user agent cut short is kept.
- Jira and Confluence (`atlassian`): their Tomcat access logs, with the user, thread, duration and, from Confluence 7.11 and Jira 9.4, the forwarded-for address.
- Bitbucket (`atlassian`): `atlassian-bitbucket-access.log`: HTTP, SSH (command and repository) and gRPC lines, with the request id (`i@` in, `o@` out), bytes read and written, labels (`push`, access tokens), duration and session.
- Times in UTC where the log gives its offset; Bitbucket's are local, their zone not recorded. Lines that can't be read go to `problems`, never a panic.

## How it's checked

- plaso's test logs (Apache-2.0, `tests/fixtures/plaso/`, see `NOTICE`): every one of the 44 requests plaso reads from them with its own parsers, read the same (`tests/oracle/`); beyond plaso, a Googlebot line whose user agent was cut short, which plaso's grammar rejects.
- Property tests: arbitrary text and lines cut anywhere give requests, problems or nothing, never a panic.

## Licence

MIT or Apache-2.0, at your option.
