//! Any input gives requests, problems or nothing, never a panic.

use proptest::prelude::*;
use weblogs::{EntryKind, Kind};

const ENTRY_KINDS: [EntryKind; 3] = [
    EntryKind::Application,
    EntryKind::BitbucketAudit,
    EntryKind::Audit,
];

const KINDS: [Kind; 5] = [
    Kind::Access,
    Kind::Atlassian,
    Kind::Bitbucket,
    Kind::Elb,
    Kind::AzureGateway,
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_text(text in "[ -~\t\n|\\[\\]{}\"/:@,.-]{0,600}") {
        for kind in KINDS {
            let _ = weblogs::read(kind, text.as_bytes());
        }
        let _ = weblogs::detect("access.log", text.as_bytes());
        for kind in ENTRY_KINDS {
            let _ = weblogs::read_entries(kind, text.as_bytes());
        }
        let _ = weblogs::detect_entries("atlassian-jira.log", text.as_bytes());
    }

    /// Application and audit lines cut anywhere, and after an entry's time
    /// anything.
    #[test]
    fn entry_lines_cut_anywhere(cut in 0usize..700, tail in "[ -~\t\\[\\]\"|]{0,200}") {
        let lines = [
            (EntryKind::Application, "2022-07-12 01:38:50,696 WARN [support-zip] [troubleshooting.SupportHealthCheckProcess] lambda$x$0 Health check -- url: /x | userName: a | traceId: 1"),
            (EntryKind::Application, r#"2022-04-12 05:39:57,408 INFO [tx:thread-2] john.smith 2CM38K4Fx339x113x2 @5XDWX5x339x568x0,4SJOMSOBx339x40x2 10.229.31.195 "TransactionService/Transact" c.a.b.m.r.DefaultRepositoryManager Repository created"#),
            (EntryKind::Application, "2020-06-03 10:43:10,664+0000 http-nio-8080-exec-23 url: /a; user: c ERROR c 643x2264x1 1ia9vad 10.10.10.10,::1 /a [c.a.j.X] message"),
            (EntryKind::BitbucketAudit, r#"63.246.22.199,172.16.1.187 | RepositoryCreatedEvent | jsmith | 1400681373433 | PROJECT/myproject | {"id":2,"a":"b | c"} | @8KJQAGx969x543x0 | tmpqqw"#),
            (EntryKind::Audit, r#"{"affectedObjects":[{"id":"1","name":"a","type":"USER"}],"auditType":{"action":"User created","level":"BASE"},"author":{"id":"2","name":"admin"},"changedValues":[{"key":"k","from":1,"to":2.5}],"extraAttributes":[{"name":"n","value":true}],"source":"192.0.2.1","timestamp":{"epochSecond":-99999999999999,"nano":999999999}}"#),
        ];
        for (kind, line) in lines {
            let cut_line = &line.as_bytes()[..cut.min(line.len())];
            let _ = weblogs::read_entries(kind, cut_line);
            let _ = weblogs::detect_entries("x", cut_line);
            let mut joined = cut_line.to_vec();
            joined.extend_from_slice(tail.as_bytes());
            joined.extend_from_slice(b"\n\tat continuation\n");
            joined.extend_from_slice(line.as_bytes());
            let _ = weblogs::read_entries(kind, &joined);
        }
    }

    #[test]
    fn lines_cut_anywhere(cut in 0usize..700) {
        let lines = [
            r#"plaso.log2timeline.net:443 10.1.1.2 - bob [13/Jan/2018:19:31:17 +0000] "GET /evil.php?c="x" HTTP/1.1" 200 1063 "-" "Mozilla/5.0""#,
            "[03/Oct/2022:09:00:30 +0100] 10.0.0.6 - http-nio-8080-exec-2 192.168.1.11 GET /login.jsp HTTP/1.1 200 125ms 8712 http://localhost/ curl/7.85.0",
            r#"10.229.31.65 | grpc | o@1GGG0Q5Kx420x106x2 | @5XDWX5x420x2768x0 | admin | 2022-04-12 07:09:18,086 | "HostingService/HttpBackend" | - | 0 | 2 | 141583 | 18951 | 3826461940 | - | 508028 |"#,
            r#"h2 2020-01-11T16:55:32.115600Z app/web/jf29 192.168.1.10:55753 192.168.1.123:32869 0.010 0.004 0.000 302 302 32 596 "GET https://www.example.com:443/b.png HTTP/2.0" "Mozilla/5.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:tg "Root=1-x" "www.example.com" "arn:cert" 2 2020-01-11T16:55:32.101000Z "waf,forward" "-" "-" "192.168.1.123:32869" "302" "-" "-""#,
            r#"{"records": [{"timeStamp": "2021-10-14T22:17:11+00:00", "operationName": "ApplicationGatewayAccess", "properties": {"clientIP": "185.42.129.24", "httpStatus": 200, "timeTaken": 1e300, "sentBytes": -5}}]}"#,
        ];
        for (line, kind) in lines.iter().zip(KINDS) {
            let _ = weblogs::read(kind, &line.as_bytes()[..cut.min(line.len())]);
        }
    }

    #[test]
    fn deep_nesting(depth in 0usize..400) {
        let text = format!(
            "{{\"operationName\":\"ApplicationGatewayAccess\",\"properties\":{}{}}}",
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let _ = weblogs::read(Kind::AzureGateway, text.as_bytes());
        let audit = format!(
            "{{\"auditType\":{{}},\"affectedObjects\":{}{}}}",
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let _ = weblogs::read_entries(EntryKind::Audit, audit.as_bytes());
    }
}
