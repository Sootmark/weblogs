# weblogs

Web server access logs, for forensics: what web shells, exploitation and data theft leave behind, one request per line, read into the client, user, time, request, status, bytes, referer and user agent. One dependency, its sibling `sootmark-common` (JSON, times).

```toml
[dependencies]
sootmark-weblogs = "0.2"
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
- AWS Elastic Load Balancing (`elb`): classic, application and network load balancers' access logs, told apart by shape: client and port, the target (backend, destination) and its port, the load balancer's status and the target's, bytes in and out, the request, user agent, TLS cipher and protocol, and the application load balancer's trace id, SNI domain, rule, actions, redirect, error reason and when the request came in (`started`); every value by AWS's name.
- Azure Application Gateway (`azure`): the access log as diagnostic settings write it (a storage account's `PT1H.json`, JSON lines or an array; v1 and v2 gateways): client and port, method, original URI with its query, protocol, status, bytes, user agent, original host, time taken, instance, backend server and its status, TLS, WAF mode, transaction id. Records of the gateway's other logs are counted in `problems`.
- Times in UTC where the log gives its offset; Bitbucket's and network load balancers' are local, their zone not recorded. Lines that can't be read go to `problems`, never a panic.

Not yet: Application Gateway's firewall and performance logs, Log Analytics' `AzureDiagnostics` exports, Gateway Load Balancer logs.

## How it's checked

- plaso's test logs (Apache-2.0, `tests/fixtures/plaso/`, see `NOTICE`): every one of the 44 requests plaso reads from them with its own parsers, read the same (`tests/oracle/`); beyond plaso, a Googlebot line whose user agent was cut short, which plaso's grammar rejects. And every one of the 28 events plaso reads from its AWS ELB and Azure Application Gateway samples (16 load balancer lines, application load balancers' with two times; 2 gateway records), read the same, but where plaso keeps AWS's marks for none (`-`, `-1` bytes) and the spaces of an empty request line.
- Property tests: arbitrary text and lines cut anywhere give requests, problems or nothing, never a panic.

## Licence

MIT or Apache-2.0, at your option.
