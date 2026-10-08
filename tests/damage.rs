//! Any input gives requests, problems or nothing, never a panic.

use proptest::prelude::*;
use weblogs::Kind;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_text(text in "[ -~\t\n|\\[\\]\"/:@,.-]{0,600}") {
        for kind in [Kind::Access, Kind::Atlassian, Kind::Bitbucket] {
            let _ = weblogs::read(kind, text.as_bytes());
        }
        let _ = weblogs::detect("access.log", text.as_bytes());
    }

    #[test]
    fn lines_cut_anywhere(cut in 0usize..400) {
        let lines = [
            r#"plaso.log2timeline.net:443 10.1.1.2 - bob [13/Jan/2018:19:31:17 +0000] "GET /evil.php?c="x" HTTP/1.1" 200 1063 "-" "Mozilla/5.0""#,
            "[03/Oct/2022:09:00:30 +0100] 10.0.0.6 - http-nio-8080-exec-2 192.168.1.11 GET /login.jsp HTTP/1.1 200 125ms 8712 http://localhost/ curl/7.85.0",
            r#"10.229.31.65 | grpc | o@1GGG0Q5Kx420x106x2 | @5XDWX5x420x2768x0 | admin | 2022-04-12 07:09:18,086 | "HostingService/HttpBackend" | - | 0 | 2 | 141583 | 18951 | 3826461940 | - | 508028 |"#,
        ];
        for (line, kind) in lines.iter().zip([Kind::Access, Kind::Atlassian, Kind::Bitbucket]) {
            let _ = weblogs::read(kind, &line.as_bytes()[..cut.min(line.len())]);
        }
    }
}
