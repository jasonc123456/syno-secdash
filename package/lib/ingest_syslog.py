"""Parse sshd / ftpd / DSM web sign-in lines from syslog files (auth.log, messages)."""
import re

from common import event_hash, norm_ip, parse_ts

_IP = r"(?P<ip>[0-9a-fA-F:.]+)"
PATTERNS = [
    ("fail", "SSH", re.compile(
        r"sshd\[\d+\]: Failed \S+ for (?:invalid user )?(?P<user>\S*) from " + _IP)),
    ("success", "SSH", re.compile(
        r"sshd\[\d+\]: Accepted \S+ for (?P<user>\S+) from " + _IP)),
    ("fail", "SSH", re.compile(
        r"sshd\[\d+\]: (?:error: )?maximum authentication attempts exceeded for "
        r"(?:invalid user )?(?P<user>\S*) from " + _IP)),
    # DSM web sign-in with a username that doesn't exist. These never reach the
    # connection log; failures for real accounts do, and are read from there.
    ("fail", "DSM", re.compile(
        r"pam_unix\(webui:auth\): authentication failure;.*? rhost=" + _IP +
        r"(?:\s+user=(?P<user>\S*))?")),
    ("fail", "FTP", re.compile(
        r"ftpd\[\d+\]: .*?(?:FAIL|failed) (?:LOGIN|login)[^\[]*\[(?P<ip>[^\]]+)\].*?(?:user|as) "
        r"\"?(?P<user>[^\s\",]*)")),
]


def parse_line(line, now=None):
    for result, service, rx in PATTERNS:
        m = rx.search(line)
        if not m:
            continue
        ip = norm_ip(m.group("ip").rstrip(".,"))
        if ip is None:
            return None
        ts, _ = parse_ts(line, now=now)
        if ts is None:
            # "<prio>" prefix or hostname-first formats: try after the first space
            ts, _ = parse_ts(line.split(" ", 1)[-1], now=now)
        if ts is None:
            return None
        return {
            "ts": ts, "ip": ip, "user": m.groupdict().get("user") or None, "service": service,
            "result": result, "source": "syslog",
            "hash": event_hash("syslog", line.rstrip("\n")),
        }
    return None


def read(path, now=None):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if "sshd" not in line and "ftpd" not in line and "pam_unix(webui" not in line:
                continue
            ev = parse_line(line, now=now)
            if ev:
                yield ev
