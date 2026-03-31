#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

REPORT_TYPE = "client_account_activity"
COLLECTOR_VERSION = "3.0.0"
COLLECTION_PROFILE = "minimal_privilege_signals"

EPOCH_DATE = date(1970, 1, 1)

SERVICE_CONTROL_RE = re.compile(r"\b(systemctl|service|svcadm|rc-service|initctl)\b", re.IGNORECASE)
SU_CMD_RE = re.compile(r"(^|[\s,])(/usr/bin/su|/bin/su|\bsu\b)([\s,]|$)", re.IGNORECASE)
USER_MGMT_RE = re.compile(r"\b(useradd|usermod|userdel|passwd|chage|vipw|visudo)\b", re.IGNORECASE)
SHELL_ESCAPE_RE = re.compile(r"\b(/bin/bash|/bin/sh|/bin/zsh|/bin/ksh|/usr/bin/env|sudoedit)\b", re.IGNORECASE)
PASSWD_STATUS_RE = re.compile(r"^(?P<user>\S+)\s+(?P<code>[A-Z]{1,3})\b")


def json_load(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_isoish(ts: str | None) -> datetime | None:
    value = (ts or "").strip()
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", normalized):
        normalized = normalized[:-5] + normalized[-5:-2] + ":" + normalized[-2:]
    try:
        dt = datetime.fromisoformat(normalized)
    except Exception:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def dt_text(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def _to_int(text: str | int | None) -> int | None:
    if text is None or text == "":
        return None
    try:
        return int(text)
    except Exception:
        return None


def _days_since_epoch_to_date_text(days_value: int | None) -> str | None:
    if days_value is None:
        return None
    try:
        return (EPOCH_DATE + timedelta(days=int(days_value))).isoformat()
    except Exception:
        return None


def _normalize_password_state(value: str | None) -> str:
    state = (value or "").strip().upper()
    if state in {"HASH", "LOCKED", "EMPTY", "OTHER"}:
        return state
    return "OTHER"


def _normalize_chage_date(value: str | None) -> str | None:
    value = (value or "").strip()
    if not value or value.lower() == "never":
        return None
    for fmt in ("%b %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).date().isoformat()
        except Exception:
            pass
    return value


def _guess_service_account(user_name: str, shell_is_interactive: bool, systemd_service_count: int) -> bool:
    if systemd_service_count > 0:
        return True
    if not shell_is_interactive:
        return True
    return bool(re.search(r"(svc|service|daemon|batch|app|oracle|postgres|mysql|nginx|httpd|tomcat|jenkins|backup|splunk)", user_name, re.IGNORECASE))


def _dedupe_keep_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def parse_passwd_rows(rows: Iterable[str]) -> dict[str, dict[str, Any]]:
    users: dict[str, dict[str, Any]] = {}
    for row in rows or []:
        parts = row.rstrip("\n").split(":")
        if len(parts) < 7:
            continue
        user = parts[0]
        if not user or user in users:
            continue
        shell = parts[6] or None
        shell_text = (shell or "").lower()
        shell_is_interactive = not any(token in shell_text for token in ("nologin", "/bin/false", "/usr/sbin/nologin", "/sbin/nologin", "/bin/sync", "/sbin/halt", "/sbin/shutdown"))
        users[user] = {
            "user_name": user,
            "uid_number": _to_int(parts[2]),
            "gid_number": _to_int(parts[3]),
            "gecos": parts[4] or None,
            "home_dir": parts[5] or None,
            "login_shell": shell,
            "shell_is_interactive_flag": shell_is_interactive,
        }
    return users


def parse_group_rows(rows: Iterable[str]) -> tuple[dict[str, dict[str, Any]], dict[int, str], dict[str, list[dict[str, Any]]]]:
    groups: dict[str, dict[str, Any]] = {}
    gid_to_group: dict[int, str] = {}
    memberships: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows or []:
        parts = row.rstrip("\n").split(":")
        if len(parts) < 4:
            continue
        group_name = parts[0]
        gid = _to_int(parts[2])
        members = [m.strip() for m in parts[3].split(",") if m.strip()]
        groups[group_name] = {"group_name": group_name, "gid_number": gid, "members": members}
        if gid is not None and gid not in gid_to_group:
            gid_to_group[gid] = group_name
        for member in members:
            memberships[member].append(
                {
                    "group_name": group_name,
                    "gid_number": gid,
                    "membership_type": "secondary",
                }
            )
    return groups, gid_to_group, memberships


def parse_shadow_rows(rows: Iterable[str]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in rows or []:
        line = row.rstrip("\n")
        if "|" in line:
            parts = line.split("|")
            if len(parts) < 8:
                continue
            user = parts[0]
            out[user] = {
                "password_state": _normalize_password_state(parts[1]),
                "shadow_last_change_days": _to_int(parts[2]),
                "shadow_min_days": _to_int(parts[3]),
                "shadow_max_days": _to_int(parts[4]),
                "shadow_warn_days": _to_int(parts[5]),
                "shadow_inactive_days": _to_int(parts[6]),
                "shadow_expire_days": _to_int(parts[7]),
            }
            continue

        parts = line.split(":")
        if len(parts) < 2:
            continue
        user = parts[0]
        password_field = parts[1]
        if not password_field:
            password_state = "EMPTY"
        elif password_field in {"*", "!*", "!", "!!"} or password_field.startswith("!"):
            password_state = "LOCKED"
        elif password_field.startswith("$") or password_field.startswith("y$"):
            password_state = "HASH"
        else:
            password_state = "OTHER"
        out[user] = {
            "password_state": password_state,
            "shadow_last_change_days": _to_int(parts[2]) if len(parts) > 2 else None,
            "shadow_min_days": _to_int(parts[3]) if len(parts) > 3 else None,
            "shadow_max_days": _to_int(parts[4]) if len(parts) > 4 else None,
            "shadow_warn_days": _to_int(parts[5]) if len(parts) > 5 else None,
            "shadow_inactive_days": _to_int(parts[6]) if len(parts) > 6 else None,
            "shadow_expire_days": _to_int(parts[7]) if len(parts) > 7 else None,
        }
    return out


def parse_passwd_status(results: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for rec in results or []:
        user = rec.get("item")
        stdout = (rec.get("stdout") or "").strip()
        stderr = (rec.get("stderr") or "").strip()
        if not user:
            continue
        code = None
        m = PASSWD_STATUS_RE.match(stdout)
        if m and m.group("user") == user:
            code = m.group("code")
        out[user] = {
            "passwd_status_code": code,
            "raw": stdout or stderr or None,
            "rc": rec.get("rc"),
        }
    return out


def parse_authorized_keys(lines: Iterable[str]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for line in lines or []:
        parts = line.split("|")
        if len(parts) < 3:
            continue
        user = parts[0]
        path = parts[1]
        count = _to_int(parts[2]) or 0
        out[user] = {
            "count": count,
            "path": path,
        }
    return out


def parse_pam_su(lines: Iterable[str]) -> dict[str, Any]:
    parsed_lines: list[str] = []
    restricted_groups: list[str] = []
    pam_wheel_lines: list[str] = []
    pam_rootok_present = False
    for line in lines or []:
        text = str(line).strip()
        if not text:
            continue
        parsed_lines.append(text)
        lowered = text.lower()
        if "pam_rootok.so" in lowered:
            pam_rootok_present = True
        if "pam_wheel.so" in lowered:
            pam_wheel_lines.append(text)
            match = re.search(r"group=([A-Za-z0-9_.-]+)", text)
            restricted_groups.append(match.group(1) if match else "wheel")
    restriction_mode = "pam_wheel_group" if restricted_groups else "not_group_restricted_detected"
    return {
        "restriction_mode": restriction_mode,
        "restricted_group_names": _dedupe_keep_order(restricted_groups),
        "pam_rootok_present_flag": pam_rootok_present,
        "pam_wheel_present_flag": bool(pam_wheel_lines),
        "evidence_lines": parsed_lines[:20],
    }


def _extract_sudo_command_lines(user: str, lines: list[str]) -> list[str]:
    command_lines: list[str] = []
    after_header = False
    header_re = re.compile(rf"User\s+{re.escape(user)}\s+may run the following commands", re.IGNORECASE)
    for raw in lines:
        line = raw.rstrip()
        if header_re.search(line):
            after_header = True
            continue
        if not after_header:
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("matching defaults entries"):
            continue
        command_lines.append(stripped)
    return command_lines


def _is_sudo_all_rule(line: str) -> bool:
    text = line.strip()
    if text == "ALL":
        return True
    if re.search(r"\)\s*(NOPASSWD:|PASSWD:)?\s*ALL$", text):
        return True
    return False


def parse_sudo_list(results: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for rec in results or []:
        user = rec.get("item")
        if not user:
            continue
        lines = list(rec.get("stdout_lines") or []) + list(rec.get("stderr_lines") or [])
        text = "\n".join(lines)
        command_lines = _extract_sudo_command_lines(user, lines)
        sudo_all = any(_is_sudo_all_rule(line) for line in command_lines)
        nopasswd = "NOPASSWD:" in text
        allows_su = sudo_all or bool(SU_CMD_RE.search(text))
        allows_service_control = sudo_all or bool(SERVICE_CONTROL_RE.search(text))
        allows_user_management = sudo_all or bool(USER_MGMT_RE.search(text))
        allows_shell_escape = sudo_all or bool(SHELL_ESCAPE_RE.search(text))
        has_rules = bool(command_lines) or bool(re.search(rf"User\s+{re.escape(user)}\s+may run the following commands", text, re.IGNORECASE))
        out[user] = {
            "has_sudo_rules_flag": has_rules,
            "sudo_rule_count": len(command_lines),
            "sudo_all_privileges_flag": sudo_all,
            "sudo_nopasswd_flag": nopasswd,
            "sudo_allows_su_flag": allows_su,
            "sudo_allows_service_control_flag": allows_service_control,
            "sudo_allows_user_management_flag": allows_user_management,
            "sudo_allows_shell_escape_flag": allows_shell_escape,
            "sudo_commands_sample": command_lines[:12],
            "sudo_raw_hint": lines[:20],
            "sudo_rc": rec.get("rc"),
        }
    return out


def parse_systemd_service_users(lines: Iterable[str]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "units": []})
    for line in lines or []:
        parts = str(line).split("|")
        if len(parts) < 3:
            continue
        user = parts[0].strip()
        unit_file = parts[1].strip()
        unit_name = parts[2].strip()
        if not user:
            continue
        out[user]["count"] += 1
        if unit_name:
            out[user]["units"].append(unit_name)
        elif unit_file:
            out[user]["units"].append(unit_file)
    for user, payload in out.items():
        payload["units"] = _dedupe_keep_order(payload["units"])
    return dict(out)


def _build_group_memberships_for_user(
    user_name: str,
    users: dict[str, dict[str, Any]],
    memberships_by_user: dict[str, list[dict[str, Any]]],
    gid_to_group: dict[int, str],
) -> tuple[str | None, list[dict[str, Any]]]:
    entries = list(memberships_by_user.get(user_name, []))
    primary_gid = users[user_name].get("gid_number")
    primary_group_name = gid_to_group.get(primary_gid) if primary_gid is not None else None
    if primary_group_name:
        entries.append(
            {
                "group_name": primary_group_name,
                "gid_number": primary_gid,
                "membership_type": "primary",
            }
        )
    entries = sorted(
        _dedupe_membership_entries(entries),
        key=lambda x: ((x.get("group_name") or ""), x.get("membership_type") != "primary"),
    )
    return primary_group_name, entries


def _dedupe_membership_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, int | None, str]] = set()
    out: list[dict[str, Any]] = []
    for entry in entries:
        key = (
            str(entry.get("group_name") or ""),
            _to_int(entry.get("gid_number")),
            str(entry.get("membership_type") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "group_name": entry.get("group_name") or None,
                "gid_number": _to_int(entry.get("gid_number")),
                "membership_type": entry.get("membership_type") or None,
            }
        )
    return out


def _password_expire_date(last_change_days: int | None, max_days: int | None) -> str | None:
    if last_change_days is None or max_days is None or max_days < 0:
        return None
    return _days_since_epoch_to_date_text(last_change_days + max_days)


def _source_confidence(has_sudo_data: bool, has_group_data: bool, has_shadow_data: bool) -> str:
    if has_sudo_data and has_group_data:
        return "HIGH"
    if has_group_data or has_shadow_data:
        return "MEDIUM"
    return "LOW"


def build_host_row(raw: dict[str, Any]) -> dict[str, Any]:
    collected_at = parse_isoish(raw.get("host_time_text")) or datetime.now(timezone.utc)

    users = parse_passwd_rows(raw.get("passwd") or [])
    groups, gid_to_group, memberships_by_user = parse_group_rows(raw.get("group") or [])
    shadow = parse_shadow_rows(raw.get("shadow") or [])
    passwd_status = parse_passwd_status(raw.get("passwd_status") or [])
    authorized_keys = parse_authorized_keys(raw.get("authorized_keys") or [])
    pam_su = parse_pam_su(raw.get("pam_su") or [])
    sudo_by_user = parse_sudo_list(raw.get("sudo_list") or [])
    systemd_users = parse_systemd_service_users(raw.get("systemd_service_users") or [])

    configured_priv_group_names = {
        str(v).strip().lower()
        for v in (raw.get("configured_privileged_group_names") or ["root", "wheel", "sudo", "adm", "admin"])
        if str(v).strip()
    }
    configured_priv_group_gids = {
        int(v)
        for v in (raw.get("configured_privileged_group_gids") or [0])
        if str(v).strip()
    }

    su_command_path = (raw.get("su_command_path") or "").strip() or None
    su_command_available_flag = bool(su_command_path)

    user_rows: list[dict[str, Any]] = []

    for user_name, base in sorted(users.items()):
        primary_group_name, group_memberships = _build_group_memberships_for_user(user_name, users, memberships_by_user, gid_to_group)
        group_names = [entry.get("group_name") for entry in group_memberships if entry.get("group_name")]
        group_gids = [entry.get("gid_number") for entry in group_memberships if entry.get("gid_number") is not None]
        privileged_groups = [
            entry for entry in group_memberships
            if (
                (entry.get("group_name") or "").lower() in configured_priv_group_names
                or entry.get("gid_number") in configured_priv_group_gids
            )
        ]

        shadow_info = shadow.get(user_name, {})
        passwd_info = passwd_status.get(user_name, {})
        authkeys_info = authorized_keys.get(user_name, {"count": 0, "path": None})
        sudo_info = sudo_by_user.get(
            user_name,
            {
                "has_sudo_rules_flag": False,
                "sudo_rule_count": 0,
                "sudo_all_privileges_flag": False,
                "sudo_nopasswd_flag": False,
                "sudo_allows_su_flag": False,
                "sudo_allows_service_control_flag": False,
                "sudo_allows_user_management_flag": False,
                "sudo_allows_shell_escape_flag": False,
                "sudo_commands_sample": [],
                "sudo_raw_hint": [],
                "sudo_rc": None,
            },
        )
        systemd_info = systemd_users.get(user_name, {"count": 0, "units": []})

        password_state = shadow_info.get("password_state")
        passwd_status_code = passwd_info.get("passwd_status_code")
        password_hash_present = password_state == "HASH"
        password_locked = bool(
            password_state == "LOCKED"
            or passwd_status_code in {"L", "LK"}
        )

        shadow_last_change_days = shadow_info.get("shadow_last_change_days")
        shadow_min_days = shadow_info.get("shadow_min_days")
        shadow_max_days = shadow_info.get("shadow_max_days")
        shadow_warn_days = shadow_info.get("shadow_warn_days")
        shadow_inactive_days = shadow_info.get("shadow_inactive_days")
        shadow_expire_days = shadow_info.get("shadow_expire_days")

        restricted_groups = set(pam_su.get("restricted_group_names") or [])
        su_access_by_group = user_name == "root" or bool(restricted_groups.intersection(set(group_names)))
        effective_su_access = user_name == "root" or su_access_by_group or bool(sudo_info.get("sudo_allows_su_flag"))

        service_count = int(systemd_info.get("count") or 0)
        service_units = list(systemd_info.get("units") or [])
        service_management_capability = user_name == "root" or bool(sudo_info.get("sudo_allows_service_control_flag"))

        is_privileged_candidate = bool(
            (base.get("uid_number") == 0)
            or privileged_groups
            or sudo_info.get("has_sudo_rules_flag")
            or effective_su_access
            or service_management_capability
        )

        is_service_account_candidate = _guess_service_account(
            user_name=user_name,
            shell_is_interactive=bool(base.get("shell_is_interactive_flag")),
            systemd_service_count=service_count,
        )

        source_confidence_code = _source_confidence(
            has_sudo_data=user_name in sudo_by_user,
            has_group_data=bool(group_memberships),
            has_shadow_data=user_name in shadow,
        )

        privilege_evidence: list[dict[str, Any]] = []
        if base.get("uid_number") == 0:
            privilege_evidence.append({"signal": "uid_0", "value": 0})
        for entry in privileged_groups[:10]:
            privilege_evidence.append(
                {
                    "signal": "privileged_group_membership",
                    "group_name": entry.get("group_name"),
                    "gid_number": entry.get("gid_number"),
                    "membership_type": entry.get("membership_type"),
                }
            )
        if sudo_info.get("sudo_all_privileges_flag"):
            privilege_evidence.append({"signal": "sudo_all"})
        if sudo_info.get("sudo_allows_su_flag"):
            privilege_evidence.append({"signal": "sudo_allows_su"})
        if sudo_info.get("sudo_allows_service_control_flag"):
            privilege_evidence.append({"signal": "sudo_allows_service_control"})
        if service_count > 0:
            privilege_evidence.append({"signal": "systemd_service_user", "service_count": service_count, "sample_units": service_units[:5]})

        user_obj = {
            **base,
            "primary_group_name": primary_group_name,
            "group_count": len(group_memberships),
            "group_names": group_names,
            "group_gid_numbers": group_gids,
            "group_memberships": group_memberships,
            "privileged_group_match_flag": bool(privileged_groups),
            "privileged_groups": [{"group_name": e.get("group_name"), "gid_number": e.get("gid_number")} for e in privileged_groups],
            "passwd_status_code": passwd_status_code,
            "password_state_code": password_state,
            "password_hash_present_flag": password_hash_present,
            "password_locked_flag": password_locked,
            "account_locked_flag": password_locked,
            "account_disabled_flag": False,
            "must_change_password_flag": passwd_status_code in {"NP"},
            "password_last_change_date": _days_since_epoch_to_date_text(shadow_last_change_days),
            "password_min_days": shadow_min_days,
            "password_max_days": shadow_max_days,
            "password_warn_days": shadow_warn_days,
            "password_inactive_days": shadow_inactive_days,
            "password_expire_date": _password_expire_date(shadow_last_change_days, shadow_max_days),
            "account_expire_date": _days_since_epoch_to_date_text(shadow_expire_days),
            "faillock_count": 0,
            "faillock_locked_flag": False,
            "ssh_authorized_keys_count": authkeys_info.get("count", 0),
            "ssh_authorized_keys_present_flag": bool(authkeys_info.get("count", 0)),
            "ssh_authorized_keys_path": authkeys_info.get("path"),
            "successful_login_count_7d": 0,
            "successful_login_count_30d": 0,
            "successful_login_count_90d": 0,
            "last_login_at_utc": None,
            "last_login_source_ip": None,
            "last_login_tty": None,
            "last_success_login_at_utc": None,
            "last_success_login_ip": None,
            "failed_login_count_7d": 0,
            "failed_login_count_30d": 0,
            "failed_login_count_90d": 0,
            "last_failed_login_at_utc": None,
            "last_failed_login_ip": None,
            "distinct_source_ip_count_30d": 0,
            "distinct_source_ip_count_90d": 0,
            "account_created_source": None,
            "account_created_at_best_effort_utc": None,
            "account_disabled_source": None,
            "account_disabled_at_best_effort_utc": None,
            "source_confidence_code": source_confidence_code,
            "activity_source_confidence_code": source_confidence_code,
            "activity_status_code": "NOT_COLLECTED_MINIMAL_PROFILE",
            "su_command_path": su_command_path,
            "su_command_available_flag": su_command_available_flag,
            "su_restriction_mode": pam_su.get("restriction_mode"),
            "su_restricted_group_names": pam_su.get("restricted_group_names"),
            "su_access_by_group_flag": su_access_by_group,
            "sudo_allows_su_flag": bool(sudo_info.get("sudo_allows_su_flag")),
            "effective_su_access_flag": effective_su_access,
            "has_sudo_rules_flag": bool(sudo_info.get("has_sudo_rules_flag")),
            "sudo_rule_count": int(sudo_info.get("sudo_rule_count") or 0),
            "sudo_all_privileges_flag": bool(sudo_info.get("sudo_all_privileges_flag")),
            "sudo_nopasswd_flag": bool(sudo_info.get("sudo_nopasswd_flag")),
            "sudo_allows_service_control_flag": bool(sudo_info.get("sudo_allows_service_control_flag")),
            "sudo_allows_user_management_flag": bool(sudo_info.get("sudo_allows_user_management_flag")),
            "sudo_allows_shell_escape_flag": bool(sudo_info.get("sudo_allows_shell_escape_flag")),
            "sudo_commands_sample": sudo_info.get("sudo_commands_sample") or [],
            "service_management_capability_flag": service_management_capability,
            "systemd_service_count_as_user": service_count,
            "systemd_services_sample": service_units[:20],
            "is_service_account_candidate_flag": is_service_account_candidate,
            "is_privileged_candidate_flag": is_privileged_candidate,
            "snapshot_collected_at_utc": dt_text(collected_at),
            "source_files_json": [
                "/etc/passwd",
                "/etc/group",
                "/etc/shadow",
                "/etc/pam.d/su",
                "sudo -l -U <user>",
                "systemd unit files (*.service User=)",
            ],
            "raw_payload_json": {
                "passwd_status": passwd_info.get("raw"),
                "platform_family_detected": (raw.get("platform_family_detected") or "").strip() or None,
                "auth_log_hint": (raw.get("auth_log_hint") or "").strip() or None,
                "ssh_service_hint": (raw.get("ssh_service_hint") or "").strip() or None,
                "sudo_rc": sudo_info.get("sudo_rc"),
                "pam_su_summary": pam_su.get("evidence_lines"),
            },
            "privilege_evidence": privilege_evidence,
            "events": [],
        }
        user_rows.append(user_obj)

    summary = {
        "account_count": len(user_rows),
        "interactive_account_count": sum(1 for u in user_rows if u.get("shell_is_interactive_flag")),
        "privileged_candidate_count": sum(1 for u in user_rows if u.get("is_privileged_candidate_flag")),
        "service_account_candidate_count": sum(1 for u in user_rows if u.get("is_service_account_candidate_flag")),
        "sudo_capable_count": sum(1 for u in user_rows if u.get("has_sudo_rules_flag")),
        "service_management_capable_count": sum(1 for u in user_rows if u.get("service_management_capability_flag")),
    }

    details = {
        "report_type": REPORT_TYPE,
        "collector_version": COLLECTOR_VERSION,
        "collection_profile_code": COLLECTION_PROFILE,
        "source_window_days": raw.get("window_days"),
        "summary": summary,
        "users": user_rows,
    }

    return {
        "hostname": raw.get("hostname") or "",
        "group": raw.get("host_group_csv") or "",
        "ip_address": str(raw.get("ip_address") or ""),
        "os_distro": raw.get("os_distro") or "",
        "os_version": raw.get("os_version") or "",
        "hw_arch": raw.get("hw_arch") or "",
        "time": raw.get("host_time_text") or dt_text(collected_at) or "",
        "changed": str(bool(raw.get("changed", False))).lower(),
        "unreachable": str(bool(raw.get("unreachable", False))).lower(),
        "failed": str(bool(raw.get("failed", False))).lower(),
        "details": json.dumps(details, ensure_ascii=False, separators=(",", ":")),
    }


def build_rows(input_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(input_dir.glob("*_account_activity_raw.json")):
        rows.append(build_host_row(json_load(path)))
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
