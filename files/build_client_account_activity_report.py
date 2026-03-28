#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

CSV_HEADER = [
    "hostname",
    "group",
    "ip_address",
    "os_distro",
    "os_version",
    "hw_arch",
    "time",
    "changed",
    "unreachable",
    "failed",
    "details",
]

INTERACTIVE_SHELL_MARKERS = ("/sh", "/bash", "/zsh", "/ksh", "/csh", "/fish")
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}
PASSWD_STATUS_MAP = {
    "P": (False, False),
    "PS": (False, False),
    "NP": (False, False),
    "L": (True, True),
    "LK": (True, True),
}


def parse_bool(v: Any) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def iso_or_none(dt: Optional[datetime]) -> Optional[str]:
    return dt.strftime("%Y-%m-%dT%H:%M:%S") if dt else None


def date_or_none(dt: Optional[datetime]) -> Optional[str]:
    return dt.strftime("%Y-%m-%d") if dt else None


def epoch_days_to_date(text: str) -> Optional[datetime]:
    if not text or not str(text).isdigit():
        return None
    return datetime(1970, 1, 1) + timedelta(days=int(text))


def normalize_result_map(results: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for item in results or []:
        cmd = str(item.get("cmd") or "")
        parts = cmd.split()
        user = parts[-1] if parts else None
        if user:
            out[user] = item
    return out


def parse_passwd(lines: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for line in lines or []:
        parts = str(line).rstrip("\n").split(":")
        if len(parts) < 7:
            continue
        user, _, uid, gid, gecos, home, shell = parts[:7]
        out[user] = {
            "user_name": user,
            "uid_number": int(uid) if uid.isdigit() else None,
            "gid_number": int(gid) if gid.isdigit() else None,
            "gecos": gecos or None,
            "home_dir": home or None,
            "login_shell": shell or None,
            "shell_is_interactive_flag": bool(shell and any(shell.endswith(m) for m in INTERACTIVE_SHELL_MARKERS)),
        }
    return out


def parse_shadow(lines: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for line in lines or []:
        parts = str(line).rstrip("\n").split(":")
        if len(parts) < 9:
            continue
        user, pwd, lastchg, mindays, maxdays, warn, inactive, expire, _ = parts[:9]
        out[user] = {
            "password_hash_present_flag": bool(pwd and pwd not in {"!", "*", "!!", "x"}),
            "password_locked_flag": pwd.startswith("!") or pwd.startswith("*"),
            "password_last_change_date": date_or_none(epoch_days_to_date(lastchg)),
            "password_min_days": int(mindays) if str(mindays).isdigit() else None,
            "password_max_days": int(maxdays) if str(maxdays).isdigit() else None,
            "password_warn_days": int(warn) if str(warn).isdigit() else None,
            "password_inactive_days": int(inactive) if str(inactive).isdigit() else None,
            "account_expire_date": date_or_none(epoch_days_to_date(expire)),
        }
        if out[user]["password_last_change_date"] and out[user]["password_max_days"] is not None:
            base = datetime.strptime(out[user]["password_last_change_date"], "%Y-%m-%d")
            out[user]["password_expire_date"] = date_or_none(base + timedelta(days=out[user]["password_max_days"]))
        else:
            out[user]["password_expire_date"] = None
    return out


def parse_passwd_status(results: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for user, item in results.items():
        stdout = str(item.get("stdout") or "").strip()
        if not stdout:
            continue
        parts = stdout.split()
        if len(parts) < 2:
            continue
        status = parts[1].upper()
        password_locked_flag, account_locked_flag = PASSWD_STATUS_MAP.get(status, (False, False))
        out[user] = {
            "passwd_status_code": status,
            "password_locked_flag": password_locked_flag,
            "account_locked_flag": account_locked_flag,
            "passwd_status_raw": stdout,
        }
    return out


def parse_chage(results: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for user, item in results.items():
        stdout = str(item.get("stdout") or "")
        if not stdout:
            continue
        data: Dict[str, Any] = {}
        for line in stdout.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            key = k.strip().lower()
            val = v.strip()
            if key == "last password change":
                data["password_last_change_text"] = val
            elif key == "password expires":
                data["password_expires_text"] = val
            elif key == "password inactive":
                data["password_inactive_text"] = val
            elif key == "account expires":
                data["account_expires_text"] = val
            elif key == "minimum number of days between password change":
                data["password_min_days"] = int(val) if val.isdigit() else data.get("password_min_days")
            elif key == "maximum number of days between password change":
                data["password_max_days"] = int(val) if val.isdigit() else data.get("password_max_days")
            elif key == "number of days of warning before password expires":
                data["password_warn_days"] = int(val) if val.isdigit() else data.get("password_warn_days")
        out[user] = data
    return out


def parse_lastlog(results: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for user, item in results.items():
        lines = [ln for ln in str(item.get("stdout") or "").splitlines() if ln.strip()]
        if len(lines) < 2:
            continue
        line = lines[1].strip()
        if "**Never logged in**" in line:
            out[user] = {
                "last_login_at_utc": None,
                "last_login_source_ip": None,
                "last_login_tty": None,
                "never_logged_in_flag": True,
            }
            continue
        # user pts/0 192.168.1.10 Sat Mar 28 09:55:10 +0000 2026
        m = re.match(r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<src>\S+)\s+(?P<dt>.+)$", line)
        if not m:
            continue
        dt = parse_generic_date(m.group("dt"))
        out[user] = {
            "last_login_at_utc": iso_or_none(dt),
            "last_login_source_ip": m.group("src") if m.group("src") not in {"**Never", "in**"} else None,
            "last_login_tty": m.group("tty"),
            "never_logged_in_flag": False,
        }
    return out


def parse_generic_date(text: str) -> Optional[datetime]:
    text = str(text).strip()
    fmts = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%a %b %d %H:%M:%S %z %Y",
        "%a %b %d %H:%M:%S %Y",
        "%b %d %H:%M:%S %Y",
    ]
    for fmt in fmts:
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo:
                return dt.replace(tzinfo=None)
            return dt
        except ValueError:
            continue
    return None


def parse_last_lines(lines: Iterable[str], success: bool) -> Dict[str, Dict[str, Any]]:
    if success:
        counts: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "successful_login_count_7d": 0,
            "successful_login_count_30d": 0,
            "successful_login_count_90d": 0,
            "distinct_ips_30d": set(),
            "distinct_ips_90d": set(),
            "last_success_login_at_utc": None,
            "last_success_login_ip": None,
        })
    else:
        counts = defaultdict(lambda: {
            "failed_login_count_7d": 0,
            "failed_login_count_30d": 0,
            "failed_login_count_90d": 0,
            "distinct_ips_30d": set(),
            "distinct_ips_90d": set(),
            "last_failed_login_at_utc": None,
            "last_failed_login_ip": None,
        })
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    line_re = re.compile(r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<src>\S+)\s+(?P<dt1>[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\d{4})")
    for line in lines or []:
        text = str(line).strip()
        if not text or text.startswith(("wtmp begins", "btmp begins", "reboot", "shutdown")):
            continue
        m = line_re.match(text)
        if not m:
            continue
        user = m.group("user")
        src = None if m.group("src") in {"0.0.0.0", ":0", "(none)"} else m.group("src")
        dt = parse_generic_date(m.group("dt1"))
        if not dt:
            continue
        age_days = (now - dt).days
        bucket = counts[user]
        if success:
            if bucket["last_success_login_at_utc"] is None or dt > datetime.strptime(bucket["last_success_login_at_utc"], "%Y-%m-%dT%H:%M:%S"):
                bucket["last_success_login_at_utc"] = iso_or_none(dt)
                bucket["last_success_login_ip"] = src
            if age_days <= 7:
                bucket["successful_login_count_7d"] += 1
            if age_days <= 30:
                bucket["successful_login_count_30d"] += 1
                if src:
                    bucket["distinct_ips_30d"].add(src)
            if age_days <= 90:
                bucket["successful_login_count_90d"] += 1
                if src:
                    bucket["distinct_ips_90d"].add(src)
        else:
            if bucket["last_failed_login_at_utc"] is None or dt > datetime.strptime(bucket["last_failed_login_at_utc"], "%Y-%m-%dT%H:%M:%S"):
                bucket["last_failed_login_at_utc"] = iso_or_none(dt)
                bucket["last_failed_login_ip"] = src
            if age_days <= 7:
                bucket["failed_login_count_7d"] += 1
            if age_days <= 30:
                bucket["failed_login_count_30d"] += 1
                if src:
                    bucket["distinct_ips_30d"].add(src)
            if age_days <= 90:
                bucket["failed_login_count_90d"] += 1
                if src:
                    bucket["distinct_ips_90d"].add(src)
    out = {}
    for user, bucket in counts.items():
        bucket["distinct_source_ip_count_30d"] = len(bucket.pop("distinct_ips_30d"))
        bucket["distinct_source_ip_count_90d"] = len(bucket.pop("distinct_ips_90d"))
        out[user] = dict(bucket)
    return out


def parse_faillock(results: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for user, item in results.items():
        stdout = str(item.get("stdout") or "")
        lines = [ln for ln in stdout.splitlines() if ln.strip()]
        out[user] = {
            "faillock_count": max(0, len(lines) - 1) if lines else 0,
            "faillock_locked_flag": bool(lines and len(lines) > 1),
        }
    return out


def parse_authorized_keys(lines: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for line in lines or []:
        parts = str(line).split("|")
        if len(parts) != 3:
            continue
        user, path, count = parts
        out[user] = {
            "ssh_authorized_keys_count": int(count) if count.isdigit() else 0,
            "ssh_authorized_keys_path": path,
        }
    return out


def collect_events(user: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    regexes = [
        (payload.get("authlog") or [], re.compile(r"^(?P<ts>\w{3}\s+\d+\s+\d+:\d+:\d+).*Accepted .* for (?P<user>\S+) from (?P<ip>\S+) .*ssh2"), "LOGIN_SUCCESS", "SUCCESS", "AUTHLOG"),
        (payload.get("authlog") or [], re.compile(r"^(?P<ts>\w{3}\s+\d+\s+\d+:\d+:\d+).*Failed .* for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) .*ssh2"), "LOGIN_FAILURE", "FAILED", "AUTHLOG"),
        (payload.get("journal_auth") or [], re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Accepted .* for (?P<user>\S+) from (?P<ip>\S+) .*ssh2"), "LOGIN_SUCCESS", "SUCCESS", "JOURNALCTL"),
        (payload.get("journal_auth") or [], re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Failed .* for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) .*ssh2"), "LOGIN_FAILURE", "FAILED", "JOURNALCTL"),
    ]
    current_year = datetime.now(timezone.utc).year
    for lines, rgx, etype, result, source in regexes:
        for raw in lines:
            m = rgx.search(str(raw))
            if not m or m.group("user") != user:
                continue
            ts = m.group("ts")
            dt = parse_generic_date(ts if ts.startswith("20") else f"{ts} {current_year}")
            events.append({
                "event_time_utc": iso_or_none(dt),
                "event_type_code": etype,
                "event_result_code": result,
                "source_ip": m.group("ip"),
                "source_port": None,
                "tty_name": None,
                "session_id": None,
                "process_name": "sshd",
                "process_id": None,
                "service_name": "sshd",
                "auth_mechanism": "password",
                "actor_username": None,
                "actor_uid": None,
                "raw_source": source,
                "raw_message": str(raw),
                "confidence_code": "HIGH",
            })
    return sorted(events, key=lambda x: (x.get("event_time_utc") or "", x.get("event_type_code") or ""), reverse=True)[:50]


def parse_auditd_created_disabled(user: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    created_at = None
    disabled_at = None
    for raw in payload.get("auditd") or []:
        text = str(raw)
        if user in text and ("useradd" in text or "/etc/passwd" in text):
            created_at = created_at or text
        if user in text and ("usermod" in text or "passwd" in text or "chage" in text):
            if "lock" in text.lower() or "expire" in text.lower() or "disable" in text.lower():
                disabled_at = disabled_at or text
    return {
        "account_created_source": "AUDITD" if created_at else None,
        "account_created_at_best_effort_utc": None,
        "account_disabled_source": "AUDITD" if disabled_at else None,
        "account_disabled_at_best_effort_utc": None,
    }


def build_report_row(payload: Dict[str, Any]) -> Dict[str, Any]:
    passwd = parse_passwd(payload.get("passwd") or [])
    shadow = parse_shadow(payload.get("shadow") or [])
    passwd_status = parse_passwd_status(normalize_result_map(payload.get("passwd_status") or []))
    chage = parse_chage(normalize_result_map(payload.get("chage") or []))
    lastlog = parse_lastlog(normalize_result_map(payload.get("lastlog") or []))
    success = parse_last_lines(payload.get("last") or [], success=True)
    failure = parse_last_lines(payload.get("lastb") or [], success=False)
    faillock = parse_faillock(normalize_result_map(payload.get("faillock") or []))
    authkeys = parse_authorized_keys(payload.get("authorized_keys") or [])

    users = []
    user_names = sorted(passwd.keys())
    for user in user_names:
        row: Dict[str, Any] = {}
        row.update(passwd.get(user, {}))
        row.update(shadow.get(user, {}))
        row.update(chage.get(user, {}))
        row.update(lastlog.get(user, {}))
        row.update(success.get(user, {}))
        row.update(failure.get(user, {}))
        row.update(faillock.get(user, {}))
        row.update(authkeys.get(user, {}))
        row.update(passwd_status.get(user, {}))
        row.update(parse_auditd_created_disabled(user, payload))
        row.setdefault("user_name", user)
        row.setdefault("password_hash_present_flag", False)
        row.setdefault("password_locked_flag", False)
        row.setdefault("account_locked_flag", False)
        row.setdefault("account_disabled_flag", False)
        row.setdefault("must_change_password_flag", False)
        row.setdefault("faillock_count", 0)
        row.setdefault("faillock_locked_flag", False)
        row.setdefault("ssh_authorized_keys_count", 0)
        row.setdefault("distinct_source_ip_count_30d", 0)
        row.setdefault("distinct_source_ip_count_90d", 0)
        row.setdefault("successful_login_count_7d", 0)
        row.setdefault("successful_login_count_30d", 0)
        row.setdefault("successful_login_count_90d", 0)
        row.setdefault("failed_login_count_7d", 0)
        row.setdefault("failed_login_count_30d", 0)
        row.setdefault("failed_login_count_90d", 0)
        row["source_confidence_code"] = "HIGH" if row.get("last_login_at_utc") or row.get("passwd_status_code") else "MEDIUM"
        row["source_files_json"] = [x for x in ["/etc/passwd", "/etc/shadow", "/var/log/lastlog", "/var/log/auth.log", "/var/log/secure", "/var/log/audit/audit.log"]]
        row["raw_payload_json"] = {
            "passwd_status": row.get("passwd_status_raw"),
            "lastlog_source": "/var/log/lastlog",
        }
        row["events"] = collect_events(user, payload)
        users.append(row)

    summary = {
        "account_count": len(users),
        "successful_login_count_30d": sum(int(u.get("successful_login_count_30d") or 0) for u in users),
        "failed_login_count_30d": sum(int(u.get("failed_login_count_30d") or 0) for u in users),
        "locked_account_count": sum(1 for u in users if bool(u.get("account_locked_flag"))),
        "disabled_account_count": sum(1 for u in users if bool(u.get("account_disabled_flag"))),
    }

    details = {
        "report_type": "client_account_activity",
        "collector_version": "1.0.0",
        "source_window_days": int(payload.get("window_days") or 90),
        "summary": summary,
        "users": users,
    }

    return {
        "hostname": payload.get("hostname") or "",
        "group": payload.get("host_group_csv") or "",
        "ip_address": payload.get("ip_address") or "",
        "os_distro": payload.get("os_distro") or "",
        "os_version": payload.get("os_version") or "",
        "hw_arch": payload.get("hw_arch") or "",
        "time": payload.get("host_time_text") or "",
        "changed": str(payload.get("changed") if payload.get("changed") is not None else False).lower(),
        "unreachable": str(payload.get("unreachable") if payload.get("unreachable") is not None else False).lower(),
        "failed": str(payload.get("failed") if payload.get("failed") is not None else False).lower(),
        "details": json.dumps(details, ensure_ascii=False, separators=(",", ":")),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Build client_account_activity_report.csv from raw fetched JSON payloads")
    ap.add_argument("--input-dir", type=Path, required=True)
    ap.add_argument("--output-file", type=Path, required=True)
    args = ap.parse_args()

    rows = []
    for fp in sorted(args.input_dir.glob("*_account_activity_raw.json")):
        payload = json.loads(fp.read_text(encoding="utf-8"))
        rows.append(build_report_row(payload))

    args.output_file.parent.mkdir(parents=True, exist_ok=True)
    with args.output_file.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
