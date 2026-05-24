"""
parser.py
---------
Parses log files into a normalised list of LogEntry dicts.

Supported formats (auto-detected):
  - Linux auth.log  (SSH, sudo, su, PAM)
  - Apache / Nginx  access.log
  - Generic syslog  (fallback)

Each LogEntry:
{
    "timestamp":  datetime | None,
    "raw":        str,           # original line
    "source_ip":  str | None,
    "user":       str | None,
    "action":     str | None,    # e.g. "ssh_failed", "sudo", "http_get"
    "status":     str | None,    # e.g. "FAILED", "SUCCESS", HTTP status code
    "extra":      dict           # format-specific fields
}
"""

import re
from datetime import datetime
from typing import Optional


# ── Regex patterns ─────────────────────────────────────────────────────────────

# Auth.log: SSH failed
_SSH_FAIL = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*"
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
# Auth.log: SSH accepted
_SSH_OK = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*"
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
# Auth.log: sudo
_SUDO = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*"
    r"sudo:.*?(?P<user>\S+) :.*COMMAND=(?P<cmd>.+)"
)
# Auth.log: su
_SU = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*"
    r"su\[.*\]: (?P<status>Successful|FAILED) su for (?P<user>\S+)"
)
# Auth.log: new user / groupadd
_USERADD = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*"
    r"(?:useradd|groupadd)\[.*?\]:.*(?:new user|new group):.*name=(?P<user>\S+)"
)
# Auth.log: invalid user (enumeration)
_INVALID_USER = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*"
    r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
# Apache/Nginx combined access log
_HTTP = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - (?P<user>\S+) '
    r'\[(?P<dt>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)
# Generic syslog timestamp
_SYSLOG_TS = re.compile(r'^(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})')

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _syslog_ts(month: str, day: str, time_str: str) -> Optional[datetime]:
    try:
        now = datetime.now()
        h, m, s = map(int, time_str.split(":"))
        return datetime(now.year, MONTHS.get(month, 1), int(day), h, m, s)
    except Exception:
        return None


def _http_ts(dt_str: str) -> Optional[datetime]:
    # e.g. "01/Jan/2024:10:22:33 +0000"
    try:
        return datetime.strptime(dt_str[:20], "%d/%b/%Y:%H:%M:%S")
    except Exception:
        return None


def _make_entry(timestamp, raw, source_ip=None, user=None,
                action=None, status=None, extra=None) -> dict:
    return {
        "timestamp": timestamp,
        "raw":       raw,
        "source_ip": source_ip,
        "user":      user,
        "action":    action,
        "status":    status,
        "extra":     extra or {},
    }


# ── Per-line parsers ───────────────────────────────────────────────────────────

def _parse_auth_line(line: str) -> Optional[dict]:
    m = _SSH_FAIL.search(line)
    if m:
        return _make_entry(
            _syslog_ts(m["month"], m["day"], m["time"]), line,
            source_ip=m["ip"], user=m["user"],
            action="ssh_failed", status="FAILED",
        )
    m = _SSH_OK.search(line)
    if m:
        return _make_entry(
            _syslog_ts(m["month"], m["day"], m["time"]), line,
            source_ip=m["ip"], user=m["user"],
            action="ssh_success", status="SUCCESS",
        )
    m = _SUDO.search(line)
    if m:
        return _make_entry(
            _syslog_ts(m["month"], m["day"], m["time"]), line,
            user=m["user"], action="sudo",
            status="EXECUTED", extra={"command": m["cmd"].strip()},
        )
    m = _SU.search(line)
    if m:
        status = "SUCCESS" if "Successful" in m["status"] else "FAILED"
        return _make_entry(
            _syslog_ts(m["month"], m["day"], m["time"]), line,
            user=m["user"], action="su", status=status,
        )
    m = _USERADD.search(line)
    if m:
        return _make_entry(
            _syslog_ts(m["month"], m["day"], m["time"]), line,
            user=m["user"], action="user_created", status="INFO",
        )
    m = _INVALID_USER.search(line)
    if m:
        return _make_entry(
            _syslog_ts(m["month"], m["day"], m["time"]), line,
            source_ip=m["ip"], user=m["user"],
            action="invalid_user", status="FAILED",
        )
    # Generic syslog fallback
    m = _SYSLOG_TS.match(line)
    if m:
        return _make_entry(
            _syslog_ts(m.group(1), m.group(2), m.group(3)), line,
            action="syslog", status="INFO",
        )
    return None


def _parse_http_line(line: str) -> Optional[dict]:
    m = _HTTP.match(line)
    if not m:
        return None
    method = m["method"]
    status = m["status"]
    path   = m["path"]
    action = f"http_{method.lower()}"
    return _make_entry(
        _http_ts(m["dt"]), line,
        source_ip=m["ip"],
        user=m["user"] if m["user"] != "-" else None,
        action=action, status=status,
        extra={"method": method, "path": path, "size": m["size"]},
    )


# ── Format detection ───────────────────────────────────────────────────────────

def _detect_format(lines: list[str]) -> str:
    sample = "\n".join(lines[:40])
    if re.search(r'Failed password|Accepted password|sudo:|Invalid user', sample):
        return "auth"
    if re.search(r'"\w+ /\S+ HTTP', sample):
        return "http"
    return "syslog"


# ── Public API ─────────────────────────────────────────────────────────────────

def parse_log_file(filepath: str) -> tuple[list[dict], str]:
    """
    Parse a log file and return (entries, detected_format).
    Skips lines that don't match any known pattern.
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    fmt = _detect_format(lines)
    entries = []

    for line in lines:
        line = line.rstrip()
        if not line:
            continue
        if fmt == "auth":
            entry = _parse_auth_line(line)
        elif fmt == "http":
            entry = _parse_http_line(line)
        else:
            entry = _parse_auth_line(line) or _make_entry(None, line, action="syslog", status="INFO")

        if entry:
            entries.append(entry)

    return entries, fmt