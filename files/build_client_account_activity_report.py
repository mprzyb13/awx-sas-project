#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

REPORT_TYPE = "client_account_activity"
COLLECTOR_VERSION = "2.0.0"

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
FAILED_RE = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
SESSION_OPEN_RE = re.compile(r"pam_unix\((?P<svc>sshd|login):session\): session opened for user (?P<user>[^\s(]+)")
SUDO_RE = re.compile(r"sudo: (?P<user>[^ :]+) : TTY=(?P<tty>[^ ;]+)")
WHO_RE = re.compile(r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<date>\d{4}-\d{2}-\d{2}|[A-Z][a-z]{2}\s+\d{1,2})\s+(?P<time>\d{2}:\d{2})(?:\s+\((?P<src>[^)]+)\))?")
W_SESSION_RE = re.compile(r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<src>\S+)\s+(?P<login>\d{2}:\d{2})")
PASSWD_STATUS_RE = re.compile(r"^(?P<user>\S+)\s+(?P<code>[A-Z]{1,3})\b")


@dataclass
class Event:
    ts: datetime
    kind: str
    source_type: str
    ip: str | None
    line: str


# -------- basic helpers --------

def json_load(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_isoish(ts: str) -> datetime | None:
    ts = ts.strip()
    if not ts:
        return None
    normalized = ts.replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", normalized):
        normalized = normalized[:-5] + normalized[-5:-2] + ":" + normalized[-2:]
    try:
        return ensure_utc(datetime.fromisoformat(normalized))
    except Exception:
        return None


def parse_syslog_prefix(line: str, collected_at: datetime) -> tuple[datetime | None, str]:
    line = line.rstrip()
    if not line:
        return None, line
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T[^ ]+)\s+(.*)$", line)
    if m:
        return parse_isoish(m.group(1)), m.group(2)

    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(.*)$", line)
    if m:
        month = MONTHS.get(m.group(1))
        if month:
            day = int(m.group(2))
            hh, mm, ss = map(int, m.group(3).split(":"))
            dt = datetime(collected_at.year, month, day, hh, mm, ss, tzinfo=timezone.utc)
            # guard against Dec->Jan around year boundaries
            if dt - collected_at > timedelta(days=30):
                dt = dt.replace(year=dt.year - 1)
            elif collected_at - dt > timedelta(days=335):
                dt = dt.replace(year=dt.year + 1)
            return dt, m.group(4)

    return None, line


def dt_text(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return ensure_utc(dt).replace(tzinfo=None).isoformat(timespec="seconds")


def is_interactive_shell(shell: str | None) -> bool:
    shell = (shell or "").strip().lower()
    if not shell:
        return False
    bad = ["nologin", "/bin/false", "/sbin/halt", "/sbin/shutdown", "/bin/sync"]
    return not any(token in shell for token in bad)


def ipv4_or_empty(value: str | None) -> str:
    value = (value or "").strip()
    if IPV4_RE.fullmatch(value):
        return value
    return ""


def first_non_loopback_ipv4(*values: str) -> str:
    for value in values:
        if not value:
            continue
        for match in IPV4_RE.findall(value):
            if match != "127.0.0.1":
                return match
    return ""


# -------- parsers --------

def parse_passwd_rows(rows: Iterable[str]) -> dict[str, dict[str, Any]]:
    users: dict[str, dict[str, Any]] = {}
    for row in rows:
        parts = row.split(":")
        if len(parts) < 7:
            continue
        user = parts[0]
        if user in users:
            continue  # prefer first occurrence (usually local over alt mapping)
        users[user] = {
            "user_name": user,
            "uid_number": _to_int(parts[2]),
            "gid_number": _to_int(parts[3]),
            "gecos": parts[4] or None,
            "home_dir": parts[5] or None,
            "login_shell": parts[6] or None,
            "shell_is_interactive_flag": is_interactive_shell(parts[6]),
        }
    return users


def parse_shadow_rows(rows: Iterable[str]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        parts = row.split(":")
        if len(parts) < 2:
            continue
        user = parts[0]
        result[user] = {
            "password_hash": parts[1],
            "shadow_last_change_days": _to_int(parts[2]) if len(parts) > 2 else None,
            "shadow_min_days": _to_int(parts[3]) if len(parts) > 3 else None,
            "shadow_max_days": _to_int(parts[4]) if len(parts) > 4 else None,
            "shadow_warn_days": _to_int(parts[5]) if len(parts) > 5 else None,
            "shadow_inactive_days": _to_int(parts[6]) if len(parts) > 6 else None,
            "shadow_expire_days": _to_int(parts[7]) if len(parts) > 7 else None,
        }
    return result


def parse_passwd_status(results: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for rec in results or []:
        user = rec.get("item")
        stdout = (rec.get("stdout") or "").strip()
        if not user:
            continue
        m = PASSWD_STATUS_RE.match(stdout)
        code = None
        if m and m.group("user") == user:
            code = m.group("code")
        out[user] = {"passwd_status_code": code, "raw": stdout or None, "rc": rec.get("rc")}
    return out


def parse_chage(results: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for rec in results or []:
        user = rec.get("item")
        if not user:
            continue
        parsed: dict[str, Any] = {}
        for line in rec.get("stdout_lines") or []:
            if ":" not in line:
                continue
            key, value = [x.strip() for x in line.split(":", 1)]
            parsed[key] = value
        out[user] = parsed
    return out


def parse_authorized_keys(lines: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in lines or []:
        parts = line.split("|")
        if len(parts) >= 3:
            out[parts[0]] = _to_int(parts[2]) or 0
    return out


def parse_faillock(results: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for rec in results or []:
        user = rec.get("item")
        lines = rec.get("stdout_lines") or []
        count = sum(1 for line in lines if line.strip() and not line.lower().startswith("when") and not line.lower().startswith("user"))
        out[user] = {"faillock_count": count, "faillock_locked_flag": count > 0}
    return out


def parse_events(raw: dict[str, Any], collected_at: datetime) -> dict[str, list[Event]]:
    events: dict[str, list[Event]] = defaultdict(list)

    def add(user: str, ts: datetime | None, kind: str, source_type: str, ip: str | None, line: str) -> None:
        if not user or ts is None:
            return
        events[user].append(Event(ensure_utc(ts), kind, source_type, ip, line))

    # First pass over raw auth/journal logs where timestamps are explicit.
    for field in ["journal_auth", "authlog"]:
        for line in raw.get(field, []) or []:
            ts, remainder = parse_syslog_prefix(line, collected_at)
            if ts is None:
                continue

            m = ACCEPTED_RE.search(remainder)
            if m:
                add(m.group("user"), ts, "success_login", "SSH", m.group("ip"), line)

            m = SESSION_OPEN_RE.search(remainder)
            if m:
                source_type = "SSH" if m.group("svc") == "sshd" else "CONSOLE"
                add(m.group("user"), ts, "success_login", source_type, None, line)

            m = FAILED_RE.search(remainder)
            if m:
                add(m.group("user"), ts, "failed_login", "SSH", m.group("ip"), line)

    # Normalized auth/journal evidence created by collector v2.
    for field in ["authlog_normalized", "journal_normalized"]:
        for line in raw.get(field, []) or []:
            if not isinstance(line, str) or "|" not in line:
                continue
            prefix, rest = line.split("|", 1)
            ts, remainder = parse_syslog_prefix(rest, collected_at)
            if ts is None:
                continue
            source_type = "SSH" if prefix.strip().upper().startswith("SSH") else "CONSOLE"

            m = SESSION_OPEN_RE.search(remainder)
            if m:
                add(m.group("user"), ts, "success_login", source_type, None, line)
                continue
            m = ACCEPTED_RE.search(remainder)
            if m:
                add(m.group("user"), ts, "success_login", source_type, m.group("ip"), line)
                continue
            m = FAILED_RE.search(remainder)
            if m:
                add(m.group("user"), ts, "failed_login", source_type, m.group("ip"), line)
                continue
            m = re.search(r"user (?P<user>[^\s(]+)", remainder)
            if m:
                add(m.group("user"), ts, "session_activity", source_type, None, line)

    # last/lastb normalized evidence if available.
    for field, kind in [("last_normalized", "success_login"), ("lastb_normalized", "failed_login")]:
        for line in raw.get(field, []) or []:
            if not isinstance(line, str):
                continue
            parts = line.split("|", 4)
            if len(parts) < 5:
                continue
            source_type, user, _term, src, rawline = parts
            ts = _parse_last_timestamp(rawline, collected_at)
            add(user, ts, kind, source_type.strip().upper(), ipv4_or_empty(src) or None, rawline)

    # who / w live session hints (best effort)
    for line in raw.get("who", []) or []:
        m = WHO_RE.match(line.strip())
        if not m:
            continue
        user = m.group("user")
        source_type = "SSH" if m.group("tty").startswith("pts/") else "CONSOLE"
        ts = _parse_who_datetime(m.group("date"), m.group("time"), collected_at)
        add(user, ts, "live_session", source_type, ipv4_or_empty(m.group("src") or "") or None, line)

    for line in raw.get("w", []) or [][2:]:
        m = W_SESSION_RE.match(line.strip())
        if not m:
            continue
        user = m.group("user")
        source_type = "SSH" if m.group("tty").startswith("pts/") else "CONSOLE"
        ts = _today_at(m.group("login"), collected_at)
        src = m.group("src") if IPV4_RE.fullmatch(m.group("src") or "") else None
        add(user, ts, "live_session", source_type, src, line)

    for user in list(events):
        events[user].sort(key=lambda e: e.ts)
    return events


def _parse_last_timestamp(rawline: str, collected_at: datetime) -> datetime | None:
    # Example: user pts/0 192.168.0.1 Fri Mar 27 22:31:50 2026 - Fri Mar ...
    m = re.search(r"([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})", rawline)
    if m:
        try:
            return ensure_utc(datetime.strptime(m.group(1), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc))
        except Exception:
            return None
    return None


def _parse_who_datetime(date_text: str, time_text: str, collected_at: datetime) -> datetime | None:
    if re.match(r"\d{4}-\d{2}-\d{2}$", date_text):
        return parse_isoish(f"{date_text}T{time_text}:00+00:00")
    m = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})$", date_text)
    if m:
        month = MONTHS.get(m.group(1))
        if month:
            dt = datetime(collected_at.year, month, int(m.group(2)), int(time_text[:2]), int(time_text[3:]), 0, tzinfo=timezone.utc)
            if dt > collected_at + timedelta(days=1):
                dt = dt.replace(year=dt.year - 1)
            return dt
    return None


def _today_at(hhmm: str, collected_at: datetime) -> datetime | None:
    if not re.match(r"\d{2}:\d{2}$", hhmm):
        return None
    dt = collected_at.replace(hour=int(hhmm[:2]), minute=int(hhmm[3:]), second=0, microsecond=0)
    if dt > collected_at + timedelta(hours=1):
        dt -= timedelta(days=1)
    return dt


# -------- row builder --------

def build_host_row(raw: dict[str, Any]) -> dict[str, Any]:
    collected_at = parse_isoish(raw.get("host_time_text") or "") or datetime.now(timezone.utc)
    users = parse_passwd_rows(raw.get("passwd") or [])
    shadow = parse_shadow_rows(raw.get("shadow") or [])
    passwd_status = parse_passwd_status(raw.get("passwd_status") or [])
    chage = parse_chage(raw.get("chage") or [])
    authkeys = parse_authorized_keys(raw.get("authorized_keys") or [])
    faillock = parse_faillock(raw.get("faillock") or [])
    events = parse_events(raw, collected_at)

    user_rows = []
    source_files = [
        "/etc/passwd",
        "/etc/shadow",
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/audit/audit.log",
    ]

    for user_name, base in sorted(users.items()):
        s = shadow.get(user_name, {})
        ps = passwd_status.get(user_name, {})
        ch = chage.get(user_name, {})
        fl = faillock.get(user_name, {"faillock_count": 0, "faillock_locked_flag": False})
        ev = events.get(user_name, [])

        success = [e for e in ev if e.kind in {"success_login", "live_session"}]
        failed = [e for e in ev if e.kind == "failed_login"]

        last_success = success[-1] if success else None
        last_failed = failed[-1] if failed else None

        ips30 = {e.ip for e in success if e.ip and e.ts >= collected_at - timedelta(days=30)}
        ips90 = {e.ip for e in success if e.ip and e.ts >= collected_at - timedelta(days=90)}

        password_hash = s.get("password_hash")
        password_hash_present = bool(password_hash and password_hash not in {"x", "*", "!*", "!!", "!", ""} and (password_hash.startswith("$") or password_hash.startswith("y$")))
        passwd_status_code = ps.get("passwd_status_code")
        password_locked = passwd_status_code in {"L", "LK"} or (password_hash or "").startswith("!") or password_hash in {"*", "!*"}
        must_change = passwd_status_code in {"NP"}

        user_obj = {
            **base,
            "passwd_status_code": passwd_status_code,
            "password_hash_present_flag": password_hash_present,
            "password_locked_flag": password_locked,
            "account_locked_flag": False,
            "account_disabled_flag": False,
            "must_change_password_flag": must_change,
            "password_last_change_date": _normalize_chage_date(ch.get("Last password change")),
            "password_min_days": _to_int_or_none(ch.get("Minimum number of days between password change")) or s.get("shadow_min_days"),
            "password_max_days": _to_int_or_none(ch.get("Maximum number of days between password change")) or s.get("shadow_max_days"),
            "password_warn_days": _to_int_or_none(ch.get("Number of days of warning before password expires")) or s.get("shadow_warn_days"),
            "password_inactive_days": _to_int_or_none(ch.get("Password inactive")) or s.get("shadow_inactive_days"),
            "account_expire_date": _normalize_chage_date(ch.get("Account expires")),
            "faillock_count": fl.get("faillock_count", 0),
            "faillock_locked_flag": fl.get("faillock_locked_flag", False),
            "ssh_authorized_keys_count": authkeys.get(user_name, 0),
            "successful_login_count_7d": sum(1 for e in success if e.ts >= collected_at - timedelta(days=7)),
            "successful_login_count_30d": sum(1 for e in success if e.ts >= collected_at - timedelta(days=30)),
            "successful_login_count_90d": sum(1 for e in success if e.ts >= collected_at - timedelta(days=90)),
            "last_success_login_at_utc": dt_text(last_success.ts) if last_success else None,
            "last_success_login_ip": last_success.ip if last_success else None,
            "failed_login_count_7d": sum(1 for e in failed if e.ts >= collected_at - timedelta(days=7)),
            "failed_login_count_30d": sum(1 for e in failed if e.ts >= collected_at - timedelta(days=30)),
            "failed_login_count_90d": sum(1 for e in failed if e.ts >= collected_at - timedelta(days=90)),
            "last_failed_login_at_utc": dt_text(last_failed.ts) if last_failed else None,
            "last_failed_login_ip": last_failed.ip if last_failed else None,
            "distinct_source_ip_count_30d": len(ips30),
            "distinct_source_ip_count_90d": len(ips90),
            "account_created_source": None,
            "account_created_at_best_effort_utc": None,
            "account_disabled_source": None,
            "account_disabled_at_best_effort_utc": None,
            "source_confidence_code": _source_confidence(success, failed, passwd_status_code),
            "source_files_json": source_files,
            "raw_payload_json": {
                "passwd_status": ps.get("raw"),
                "platform_family_detected": (raw.get("platform_family_detected") or "").strip() or None,
                "auth_log_hint": (raw.get("auth_log_hint") or "").strip() or None,
                "ssh_service_hint": (raw.get("ssh_service_hint") or "").strip() or None,
            },
            "events": [
                {
                    "timestamp_utc": dt_text(e.ts),
                    "event_kind": e.kind,
                    "source_type": e.source_type,
                    "source_ip": e.ip,
                    "raw_line": e.line,
                }
                for e in ev[-50:]
            ],
        }
        user_rows.append(user_obj)

    summary = {
        "account_count": len(user_rows),
        "successful_login_count_30d": sum(u["successful_login_count_30d"] for u in user_rows),
        "failed_login_count_30d": sum(u["failed_login_count_30d"] for u in user_rows),
        "locked_account_count": sum(1 for u in user_rows if u["password_locked_flag"]),
        "disabled_account_count": sum(1 for u in user_rows if u["account_disabled_flag"]),
    }

    details = {
        "report_type": REPORT_TYPE,
        "collector_version": COLLECTOR_VERSION,
        "source_window_days": raw.get("window_days"),
        "summary": summary,
        "users": user_rows,
    }

    row = {
        "hostname": raw.get("hostname") or "",
        "group": raw.get("host_group_csv") or "",
        "ip_address": ipv4_or_empty(raw.get("ip_address") or ""),
        "os_distro": raw.get("os_distro") or "",
        "os_version": raw.get("os_version") or "",
        "hw_arch": raw.get("hw_arch") or "",
        "time": raw.get("host_time_text") or dt_text(collected_at) or "",
        "changed": str(bool(raw.get("changed", False))).lower(),
        "unreachable": str(bool(raw.get("unreachable", False))).lower(),
        "failed": str(bool(raw.get("failed", False))).lower(),
        "details": json.dumps(details, ensure_ascii=False, separators=(",", ":")),
    }
    return row


def _source_confidence(success: list[Event], failed: list[Event], passwd_status_code: str | None) -> str:
    if success or failed:
        return "HIGH"
    if passwd_status_code:
        return "MEDIUM"
    return "LOW"


def _normalize_chage_date(value: str | None) -> str | None:
    value = (value or "").strip()
    if not value or value.lower() == "never":
        return None
    for fmt in ["%b %d, %Y", "%Y-%m-%d"]:
        try:
            return datetime.strptime(value, fmt).date().isoformat()
        except Exception:
            pass
    return value


def _to_int(text: str | None) -> int | None:
    try:
        if text is None or text == "":
            return None
        return int(text)
    except Exception:
        return None


def _to_int_or_none(text: str | None) -> int | None:
    text = (text or "").strip()
    if not text or text.lower() == "never":
        return None
    m = re.search(r"-?\d+", text)
    return int(m.group(0)) if m else None


# -------- cli --------

def build_rows(input_dir: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(input_dir.glob("*_account_activity_raw.json")):
        raw = json_load(path)
        rows.append(build_host_row(raw))
    return rows


def write_csv(rows: list[dict[str, Any]], output_file: Path) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["hostname", "group", "ip_address", "os_distro", "os_version", "hw_arch", "time", "changed", "unreachable", "failed", "details"]
    with output_file.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output-file", required=True)
    args = parser.parse_args()

    rows = build_rows(Path(args.input_dir))
    write_csv(rows, Path(args.output_file))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
