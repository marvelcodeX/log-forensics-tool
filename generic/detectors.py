"""
detectors.py
------------
Detection engines. Each returns a list of Finding dicts.

Finding:
{
    "id":          str,        # unique finding ID
    "type":        str,        # BRUTE_FORCE | PRIVESC | PORT_SCAN | ODD_HOURS | GEO_ANOMALY | HTTP_ATTACK
    "severity":    str,        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    "timestamp":   datetime,
    "source_ip":   str | None,
    "user":        str | None,
    "title":       str,
    "description": str,
    "raw_lines":   list[str],  # supporting log lines
    "extra":       dict,
}
"""

import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional


# ── Finding factory ────────────────────────────────────────────────────────────

def _finding(ftype, severity, timestamp, title, description,
             source_ip=None, user=None, raw_lines=None, extra=None) -> dict:
    return {
        "id":          uuid.uuid4().hex[:8],
        "type":        ftype,
        "severity":    severity,
        "timestamp":   timestamp,
        "source_ip":   source_ip,
        "user":        user,
        "title":       title,
        "description": description,
        "raw_lines":   raw_lines or [],
        "extra":       extra or {},
    }


# ── 1. Brute Force Detection ───────────────────────────────────────────────────

BRUTE_THRESHOLD      = 5    # failures within window = brute force
BRUTE_WINDOW_SECS    = 60
SPRAY_THRESHOLD      = 3    # same IP trying ≥N different users
LOCKOUT_SUCCESS_GAP  = 300  # success within 5 min after failures = likely compromise

def detect_brute_force(entries: list[dict]) -> list[dict]:
    findings = []
    fails_by_ip   = defaultdict(list)   # ip → [entries]
    users_by_ip   = defaultdict(set)    # ip → {users tried}
    success_by_ip = defaultdict(list)

    for e in entries:
        if e["action"] in ("ssh_failed", "invalid_user") and e["source_ip"]:
            fails_by_ip[e["source_ip"]].append(e)
            users_by_ip[e["source_ip"]].add(e["user"])
        if e["action"] == "ssh_success" and e["source_ip"]:
            success_by_ip[e["source_ip"]].append(e)

    for ip, fails in fails_by_ip.items():
        # Sort by time
        timed = [f for f in fails if f["timestamp"]]
        timed.sort(key=lambda x: x["timestamp"])

        # Sliding window
        for i, start in enumerate(timed):
            window = [
                f for f in timed[i:]
                if f["timestamp"] and
                   (f["timestamp"] - start["timestamp"]).total_seconds() <= BRUTE_WINDOW_SECS
            ]
            if len(window) >= BRUTE_THRESHOLD:
                users = list({f["user"] for f in window if f["user"]})
                findings.append(_finding(
                    "BRUTE_FORCE", "CRITICAL", start["timestamp"],
                    f"Brute Force from {ip}",
                    f"{len(window)} failed SSH attempts in {BRUTE_WINDOW_SECS}s "
                    f"targeting user(s): {', '.join(users) or 'unknown'}",
                    source_ip=ip,
                    user=users[0] if users else None,
                    raw_lines=[f["raw"] for f in window[:10]],
                    extra={"attempt_count": len(window), "users_targeted": users},
                ))
                break  # one finding per IP

        # Password spray: one IP, many users
        if len(users_by_ip[ip]) >= SPRAY_THRESHOLD:
            users = list(users_by_ip[ip])
            ts = timed[0]["timestamp"] if timed else None
            findings.append(_finding(
                "BRUTE_FORCE", "HIGH", ts,
                f"Password Spray from {ip}",
                f"Single IP tried {len(users)} different usernames: {', '.join(users[:8])}",
                source_ip=ip,
                raw_lines=[f["raw"] for f in fails[:10]],
                extra={"users_sprayed": users},
            ))

        # Brute force succeeded: failures followed by success
        if ip in success_by_ip and timed:
            last_fail_ts = timed[-1]["timestamp"]
            for succ in success_by_ip[ip]:
                if succ["timestamp"] and last_fail_ts:
                    gap = (succ["timestamp"] - last_fail_ts).total_seconds()
                    if 0 < gap <= LOCKOUT_SUCCESS_GAP:
                        findings.append(_finding(
                            "BRUTE_FORCE", "CRITICAL", succ["timestamp"],
                            f"Brute Force Succeeded — {ip}",
                            f"SSH login succeeded {int(gap)}s after repeated failures "
                            f"for user '{succ['user']}'.",
                            source_ip=ip, user=succ["user"],
                            raw_lines=[succ["raw"]],
                            extra={"gap_seconds": int(gap)},
                        ))

    return findings


# ── 2. Privilege Escalation Detection ─────────────────────────────────────────

SENSITIVE_CMDS = ["/bin/bash", "/bin/sh", "chmod", "chown", "passwd",
                  "visudo", "sudoers", "/etc/shadow", "id", "whoami",
                  "nc ", "netcat", "python", "perl", "ruby", "wget", "curl"]

def detect_privesc(entries: list[dict]) -> list[dict]:
    findings = []

    for e in entries:
        if e["action"] == "sudo":
            cmd = e["extra"].get("command", "")
            for s in SENSITIVE_CMDS:
                if s in cmd:
                    findings.append(_finding(
                        "PRIVESC", "HIGH", e["timestamp"],
                        f"Suspicious sudo by '{e['user']}'",
                        f"User '{e['user']}' ran a sensitive command via sudo: {cmd}",
                        user=e["user"],
                        raw_lines=[e["raw"]],
                        extra={"command": cmd},
                    ))
                    break

        if e["action"] == "su" and e["status"] == "FAILED":
            findings.append(_finding(
                "PRIVESC", "MEDIUM", e["timestamp"],
                f"Failed su attempt by '{e['user']}'",
                f"User '{e['user']}' attempted to switch user and failed.",
                user=e["user"],
                raw_lines=[e["raw"]],
            ))

        if e["action"] == "user_created":
            findings.append(_finding(
                "PRIVESC", "HIGH", e["timestamp"],
                f"New account created: '{e['user']}'",
                f"A new user account '{e['user']}' was created — "
                "potential persistence mechanism.",
                user=e["user"],
                raw_lines=[e["raw"]],
            ))

    return findings


# ── 3. Port Scan Detection (from HTTP logs) ────────────────────────────────────

SCAN_STATUS_CODES   = {"400", "404", "403", "405"}
SCAN_PATH_THRESHOLD = 20   # unique 404 paths from same IP in short window
SCAN_WINDOW_SECS    = 120

def detect_port_scan(entries: list[dict]) -> list[dict]:
    findings = []
    http_by_ip = defaultdict(list)

    for e in entries:
        if e["action"] and e["action"].startswith("http_") and e["source_ip"]:
            if e["status"] in SCAN_STATUS_CODES:
                http_by_ip[e["source_ip"]].append(e)

    for ip, errors in http_by_ip.items():
        timed = [e for e in errors if e["timestamp"]]
        timed.sort(key=lambda x: x["timestamp"])

        for i, start in enumerate(timed):
            window = [
                e for e in timed[i:]
                if (e["timestamp"] - start["timestamp"]).total_seconds() <= SCAN_WINDOW_SECS
            ]
            paths = {e["extra"].get("path", "") for e in window}
            if len(paths) >= SCAN_PATH_THRESHOLD:
                findings.append(_finding(
                    "PORT_SCAN", "HIGH", start["timestamp"],
                    f"Web Directory Scan from {ip}",
                    f"{ip} probed {len(paths)} unique paths in {SCAN_WINDOW_SECS}s "
                    f"— likely automated scanner.",
                    source_ip=ip,
                    raw_lines=[e["raw"] for e in window[:10]],
                    extra={"paths_probed": len(paths), "sample_paths": list(paths)[:10]},
                ))
                break

    return findings


# ── 4. Odd-Hours Login Detection ───────────────────────────────────────────────

ODD_HOURS = set(range(0, 6))   # midnight–6am

def detect_odd_hours(entries: list[dict]) -> list[dict]:
    findings = []
    for e in entries:
        if e["action"] == "ssh_success" and e["timestamp"]:
            hour = e["timestamp"].hour
            if hour in ODD_HOURS:
                findings.append(_finding(
                    "ODD_HOURS", "MEDIUM", e["timestamp"],
                    f"Off-hours login by '{e['user']}'",
                    f"Successful SSH login at {e['timestamp'].strftime('%H:%M')} "
                    f"(hour {hour}) from {e['source_ip'] or 'unknown IP'}.",
                    source_ip=e["source_ip"], user=e["user"],
                    raw_lines=[e["raw"]],
                    extra={"hour": hour},
                ))
    return findings


# ── 5. HTTP Attack Pattern Detection ──────────────────────────────────────────

_SQLI_PATTERNS  = ["'", "OR 1=1", "UNION SELECT", "--", "xp_", "SLEEP(", "BENCHMARK("]
_XSS_PATTERNS   = ["<script", "javascript:", "onerror=", "onload=", "alert("]
_TRAVERSAL      = ["../", "..%2f", "%2e%2e", "etc/passwd", "etc/shadow", "win.ini"]
_SHELLS         = ["cmd.exe", "/bin/sh", "whoami", "passthru", "eval(", "system(", "exec("]

def _check_patterns(path: str, patterns: list[str]) -> Optional[str]:
    path_lower = path.lower()
    for p in patterns:
        if p.lower() in path_lower:
            return p
    return None

def detect_http_attacks(entries: list[dict]) -> list[dict]:
    findings = []
    for e in entries:
        if not (e["action"] and e["action"].startswith("http_")):
            continue
        path = e["extra"].get("path", "")

        hit = _check_patterns(path, _SQLI_PATTERNS)
        if hit:
            findings.append(_finding(
                "HTTP_ATTACK", "CRITICAL", e["timestamp"],
                "SQL Injection Attempt",
                f"Possible SQLi in request from {e['source_ip']}: {path[:120]}",
                source_ip=e["source_ip"], raw_lines=[e["raw"]],
                extra={"path": path, "pattern": hit},
            ))
            continue

        hit = _check_patterns(path, _XSS_PATTERNS)
        if hit:
            findings.append(_finding(
                "HTTP_ATTACK", "HIGH", e["timestamp"],
                "XSS Attempt",
                f"Possible XSS in request from {e['source_ip']}: {path[:120]}",
                source_ip=e["source_ip"], raw_lines=[e["raw"]],
                extra={"path": path, "pattern": hit},
            ))
            continue

        hit = _check_patterns(path, _TRAVERSAL)
        if hit:
            findings.append(_finding(
                "HTTP_ATTACK", "CRITICAL", e["timestamp"],
                "Path Traversal Attempt",
                f"Directory traversal from {e['source_ip']}: {path[:120]}",
                source_ip=e["source_ip"], raw_lines=[e["raw"]],
                extra={"path": path, "pattern": hit},
            ))
            continue

        hit = _check_patterns(path, _SHELLS)
        if hit:
            findings.append(_finding(
                "HTTP_ATTACK", "CRITICAL", e["timestamp"],
                "Remote Code Execution Attempt",
                f"Possible RCE pattern from {e['source_ip']}: {path[:120]}",
                source_ip=e["source_ip"], raw_lines=[e["raw"]],
                extra={"path": path, "pattern": hit},
            ))

    return findings


# ── Master runner ──────────────────────────────────────────────────────────────

def run_all_detectors(entries: list[dict], log_format: str) -> list[dict]:
    """
    Run all applicable detectors and return a merged, time-sorted finding list.
    """
    findings = []
    findings += detect_brute_force(entries)
    findings += detect_privesc(entries)
    findings += detect_odd_hours(entries)

    if log_format == "http":
        findings += detect_port_scan(entries)
        findings += detect_http_attacks(entries)

    # Sort by timestamp (None timestamps go to end)
    findings.sort(key=lambda f: f["timestamp"] or datetime.max)
    return findings