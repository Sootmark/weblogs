"""Writes the synthetic Atlassian logs beside this script. Unverified:
plaso has no sample of these layouts (its Jira sample is in Confluence's
layout, and it reads no audit log file), and no real log was copied. The
layouts are Atlassian's as its documentation and support articles show
them:

- atlassian-jira.log: Jira's Log4j layout, the time with its offset, the
  thread (a request thread's name with `url: …; user: …`), the level, the
  request's user, id, session, address and path (blank on a background
  thread), the logger in brackets, the message; a stack trace after one.
- atlassian-confluence.log: Confluence's layout with the request's values
  Confluence ends a message with (` -- referer: … | url: … | traceId: … |
  userName: … | action: …`), and a stack trace.
- atlassian-bitbucket.log: Bitbucket's layout with a user name holding a
  dot and an HTTP action in quotes.
- synthetic.audit.log: the audit log file of Jira, Confluence and
  Bitbucket Data Center (log/audit/*.audit.log), one JSON object per line.

Synthetic values only: documentation addresses (RFC 5737) and domains
(RFC 2606).

  python3 -I tests/fixtures/synthetic/gen.py
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

JIRA = """\
2023-10-03 08:00:45,317+0000 http-nio-8080-exec-1 url: /login.jsp; user: admin INFO admin 480x1x1 1ab2c3d 192.0.2.10 /login.jsp [c.a.jira.login.LoginLoggers] login : 'admin' tried to login successfully
2023-10-03 08:01:00,000+0000 Caesium-1-4 INFO ServiceRunner     [c.a.jira.service.DefaultServiceManager] Running service Backup
2023-10-03 10:02:10,500+0200 http-nio-8080-exec-7 url: /rest/api/2/user; user: jsmith ERROR jsmith 482x9x2 9zz8yy7 198.51.100.7,192.0.2.1 /rest/api/2/user [c.a.j.rest.exception.ExceptionInterceptor] Returning internal server error in response
java.lang.IllegalStateException: no such user
\tat com.example.Users.find(Users.java:42)
"""

CONFLUENCE = """\
2023-10-03 08:03:00,123 WARN [http-nio-8090-exec-5] [atlassian.confluence.pages.DefaultPageManager] removePage Page 'Runbook' removed -- referer: https://wiki.example.com/display/OPS | url: /pages/removepage.action | traceId: 5e2a9c1b7d3f4a60 | userName: jsmith | action: removepage
2023-10-03 08:04:00,000 ERROR [Caesium-1-2] [confluence.impl.backup.DefaultBackupManager] lambda$doBackup$0 Backup failed
java.io.IOException: disk full
\tat com.example.Backup.write(Backup.java:7)
"""

BITBUCKET = """\
2023-10-03 08:05:00,001 INFO [http-nio-7990-exec-9] john.smith 1A2B3Cx485x77x3 @9QW3ERx485x12x0 192.0.2.44 "GET /scm/ops/runbooks.git/info/refs HTTP/1.1" c.a.b.i.s.g.p.h.HttpReceivePackHook Clone of ops/runbooks
"""

AUDIT = [
    {
        "affectedObjects": [{"id": "10100", "name": "jsmith", "type": "USER"}],
        "area": "USER_MANAGEMENT",
        "auditType": {
            "action": "User created",
            "actionI18nKey": "jira.auditing.user.created",
            "area": "USER_MANAGEMENT",
            "category": "Users and groups",
            "categoryI18nKey": "jira.auditing.category.usermanagement",
            "level": "BASE",
        },
        "author": {"id": "10000", "name": "admin", "type": "user"},
        "changedValues": [
            {"i18nKey": "common.words.email", "key": "Email", "from": "", "to": "jsmith@example.com"}
        ],
        "extraAttributes": [{"name": "Directory", "nameI18nKey": "x", "value": "Jira Internal Directory"}],
        "method": "Browser",
        "node": None,
        "source": "192.0.2.10",
        "system": "https://jira.example.com",
        "timestamp": {"epochSecond": 1696320045, "nano": 317000000},
        "version": "1.0",
    },
    {
        "affectedObjects": [
            {"id": "65551", "name": "Runbook", "type": "Page"},
            {"id": "98305", "name": "Operations", "type": "Space"},
        ],
        "auditType": {
            "action": "Page removed",
            "area": "CONTENT",
            "category": "Pages",
            "level": "BASE",
        },
        "author": {"id": "8a7f808a", "name": "jsmith", "type": "user"},
        "changedValues": [],
        "extraAttributes": [],
        "method": "Browser",
        "source": "198.51.100.7",
        "system": "https://wiki.example.com",
        "timestamp": {"epochSecond": 1696320180, "nano": 123000000},
        "version": "1.0",
    },
    {
        "affectedObjects": [{"id": "7", "name": "ops/runbooks", "type": "REPOSITORY"}],
        "auditType": {
            "action": "Repository permission granted",
            "area": "PERMISSIONS",
            "category": "Permissions",
            "level": "BASE",
        },
        "author": {"id": "2", "name": "john.smith", "type": "NORMAL"},
        "changedValues": [{"key": "Permission", "from": "", "to": "REPO_ADMIN"}],
        "extraAttributes": [{"name": "Target", "value": "mallory"}],
        "method": "Browser",
        "source": "192.0.2.44",
        "system": "https://git.example.com",
        "timestamp": {"epochSecond": 1696320301, "nano": 0},
        "version": "1.0",
    },
]


def write(name, text):
    with open(os.path.join(HERE, name), "w", encoding="utf-8", newline="\n") as out:
        out.write(text)


write("atlassian-jira.log", JIRA)
write("atlassian-confluence.log", CONFLUENCE)
write("atlassian-bitbucket.log", BITBUCKET)
write(
    "synthetic.audit.log",
    "".join(json.dumps(event, separators=(",", ":")) + "\n" for event in AUDIT),
)
