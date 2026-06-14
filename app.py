from __future__ import annotations

import os
import re
import secrets
import threading
import time
import uuid
from urllib.parse import urlparse

from flask import Flask, g, jsonify, render_template, request

from sophos_api import SophosAPIError, SophosFirewallClient, VALID_STATUSES


def parse_bool(value: str | None, default: bool = True) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def configured_rule_names() -> list[str]:
    raw_rules = os.environ.get("RULE_NAMES", "")
    names = []
    seen = set()
    for item in re.split(r"[,;\n]", raw_rules):
        name = item.strip()
        if not name:
            continue
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        names.append(name)
    return sorted(names, key=str.casefold)


def configured_rule_groups() -> dict[str, str]:
    raw_groups = os.environ.get("RULE_GROUPS", "")
    groups = {}
    for item in re.split(r"[;\n]", raw_groups):
        item = item.strip()
        if not item:
            continue
        separator = "|" if "|" in item else "="
        if separator not in item:
            continue
        rule_name, group_name = item.split(separator, 1)
        rule_name = rule_name.strip()
        group_name = group_name.strip()
        if rule_name and group_name:
            groups[rule_name] = group_name
    return groups


def make_client() -> SophosFirewallClient:
    return SophosFirewallClient(
        host=os.environ.get("SFOS_HOST", ""),
        port=os.environ.get("SFOS_PORT", "4444"),
        username=os.environ.get("SFOS_USERNAME", ""),
        password=os.environ.get("SFOS_PASSWORD", ""),
        verify_tls=parse_bool(os.environ.get("SFOS_VERIFY_TLS"), default=True),
        timeout=int(os.environ.get("SFOS_TIMEOUT", "30")),
    )


def toggle_method() -> str:
    return os.environ.get("SFOS_TOGGLE_METHOD", "gui").strip().lower()


def configured_allowed_origins() -> set[str]:
    raw_origins = os.environ.get("REMOTE_FW_ALLOWED_ORIGINS", "")
    return {
        origin.strip().lower().rstrip("/")
        for origin in re.split(r"[,;\n]", raw_origins)
        if origin.strip()
    }


def origin_allowed() -> bool:
    origin = request.headers.get("Origin", "")
    if not origin:
        return True

    parsed = urlparse(origin)
    if not parsed.scheme or not parsed.netloc:
        return False

    origin_host = parsed.netloc.lower()
    if origin_host == request.host.lower():
        return True

    allowed = configured_allowed_origins()
    normalized_origin = f"{parsed.scheme.lower()}://{origin_host}"
    return normalized_origin in allowed or origin_host in allowed


app = Flask(__name__)
app.config["APP_TITLE"] = os.environ.get("APP_TITLE", "Remote Firewall")
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("REMOTE_FW_MAX_CONTENT_LENGTH", "16384"))

RESTORE_JOBS: dict[str, dict[str, object]] = {}
RESTORE_JOBS_LOCK = threading.Lock()
RESTORE_JOB_TTL_SECONDS = 900
MUTATION_LOCK = threading.Lock()
MUTATION_STATE: dict[str, object] = {
    "status": "idle",
    "rule_name": "",
    "group_name": "",
    "started_at": 0.0,
    "updated_at": 0.0,
}
MUTATION_STATE_LOCK = threading.Lock()


@app.before_request
def apply_request_guards():
    g.csp_nonce = secrets.token_urlsafe(16)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not origin_allowed():
        return jsonify({"error": "Cross-origin requests are not allowed"}), 403
    return None


@app.after_request
def apply_security_headers(response):
    nonce = getattr(g, "csp_nonce", "")
    if nonce:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'none'; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"style-src 'self' 'nonce-{nonce}'"
        )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), geolocation=(), microphone=()"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def set_mutation_state(status: str, rule_name: str = "", group_name: str = "") -> None:
    now = time.time()
    with MUTATION_STATE_LOCK:
        MUTATION_STATE.update(
            {
                "status": status,
                "rule_name": rule_name,
                "group_name": group_name,
                "started_at": MUTATION_STATE.get("started_at") if status != "updating_rule" else now,
                "updated_at": now,
            }
        )


def clear_mutation_state() -> None:
    with MUTATION_STATE_LOCK:
        MUTATION_STATE.update(
            {
                "status": "idle",
                "rule_name": "",
                "group_name": "",
                "started_at": 0.0,
                "updated_at": time.time(),
            }
        )


def current_mutation() -> dict[str, object]:
    with MUTATION_STATE_LOCK:
        return dict(MUTATION_STATE)


def release_mutation_lock() -> None:
    clear_mutation_state()
    if MUTATION_LOCK.locked():
        MUTATION_LOCK.release()


def restore_job_for_rule(rule_name: str) -> dict[str, object] | None:
    now = time.time()
    with RESTORE_JOBS_LOCK:
        stale_keys = [
            key
            for key, job in RESTORE_JOBS.items()
            if job.get("status") in {"done", "error"} and now - float(job.get("updated_at", now)) > RESTORE_JOB_TTL_SECONDS
        ]
        for key in stale_keys:
            RESTORE_JOBS.pop(key, None)
        job = RESTORE_JOBS.get(rule_name)
        return dict(job) if job else None


def start_group_restore_job(rule_name: str, group_name: str, group_snapshot_xml: str) -> dict[str, object]:
    job = {
        "id": uuid.uuid4().hex,
        "rule_name": rule_name,
        "group_name": group_name,
        "status": "pending",
        "error": "",
        "started_at": time.time(),
        "updated_at": time.time(),
    }
    with RESTORE_JOBS_LOCK:
        RESTORE_JOBS[rule_name] = job
    set_mutation_state("restoring_group", rule_name=rule_name, group_name=group_name)

    thread = threading.Thread(
        target=run_group_restore_job,
        args=(rule_name, group_snapshot_xml),
        daemon=True,
    )
    thread.start()
    return dict(job)


def run_group_restore_job(rule_name: str, group_snapshot_xml: str) -> None:
    try:
        make_client().restore_rule_group_snapshot(group_snapshot_xml)
    except Exception as exc:  # Keep this background worker alive and expose the error to UI.
        with RESTORE_JOBS_LOCK:
            if rule_name in RESTORE_JOBS:
                RESTORE_JOBS[rule_name].update(
                    {
                        "status": "error",
                        "error": str(exc),
                        "updated_at": time.time(),
                    }
                )
        release_mutation_lock()
        return

    with RESTORE_JOBS_LOCK:
        if rule_name in RESTORE_JOBS:
            RESTORE_JOBS[rule_name].update(
                {
                    "status": "done",
                    "error": "",
                    "updated_at": time.time(),
                }
            )
    release_mutation_lock()


@app.get("/")
def index():
    return render_template("index.html", title=app.config["APP_TITLE"], csp_nonce=g.csp_nonce)


@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})


@app.get("/status")
def status():
    client = make_client()
    rules = []
    rule_names = configured_rule_names()
    configured_groups = configured_rule_groups()
    try:
        dynamic_groups = client.get_rule_group_memberships(rule_names)
    except SophosAPIError:
        dynamic_groups = {}

    for name in rule_names:
        try:
            rule = client.get_rule_status(name).as_dict()
            rule["group_name"] = dynamic_groups.get(name) or configured_groups.get(name, "")
            restore_job = restore_job_for_rule(name)
            if restore_job:
                rule["restore_status"] = restore_job.get("status", "")
                rule["restore_error"] = restore_job.get("error", "")
            rules.append(rule)
        except SophosAPIError as exc:
            restore_job = restore_job_for_rule(name)
            rules.append(
                {
                    "name": name,
                    "status": "Unknown",
                    "enabled": None,
                    "policy_type": "",
                    "ip_family": "",
                    "source_zones": [],
                    "source_networks": [],
                    "group_name": dynamic_groups.get(name) or configured_groups.get(name, ""),
                    "restore_status": restore_job.get("status", "") if restore_job else "",
                    "restore_error": restore_job.get("error", "") if restore_job else "",
                    "error": str(exc),
                }
            )
    return jsonify({"rules": rules, "mutation": current_mutation()})


@app.get("/restore-status")
def restore_status():
    name = str(request.args.get("name", "")).strip()
    if not name:
        return jsonify({"error": "Missing rule name"}), 400
    job = restore_job_for_rule(name)
    if not job:
        return jsonify({"status": "none"})
    return jsonify(
        {
            "status": job.get("status", ""),
            "group_name": job.get("group_name", ""),
            "error": job.get("error", ""),
        }
    )


@app.post("/toggle")
def toggle():
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "Expected JSON body"}), 415

    name = str(payload.get("name", "")).strip()
    allowed_names = set(configured_rule_names())
    if name not in allowed_names:
        return jsonify({"error": "Unknown or unconfigured firewall rule"}), 400

    if not MUTATION_LOCK.acquire(blocking=False):
        mutation = current_mutation()
        rule_name = mutation.get("rule_name") or "another rule"
        return (
            jsonify(
                {
                    "error": f"A firewall change is already in progress for {rule_name}.",
                    "mutation": mutation,
                }
            ),
            409,
        )

    target_status = payload.get("target_status")
    client = make_client()
    # Optional fallback for repair cases. If absent, the client detects the current group dynamically.
    group_name = configured_rule_groups().get(name)
    try:
        set_mutation_state("updating_rule", rule_name=name, group_name=group_name)
        if target_status is None:
            current = client.get_rule_status(name)
            target_status = "Disable" if current.enabled else "Enable"
        else:
            target_status = str(target_status)
            if target_status not in VALID_STATUSES:
                release_mutation_lock()
                return jsonify({"error": "target_status must be Enable or Disable"}), 400

        if toggle_method() in {"xml", "xml-api", "api"}:
            update = client.set_rule_status_deferred_group_restore(
                name,
                target_status,
                group_name=group_name,
            )
            result = update.rule_status
            group_restore = {"status": "none"}
            if update.group_snapshot_xml:
                job = start_group_restore_job(
                    name,
                    update.group_name,
                    update.group_snapshot_xml,
                )
                group_restore = {
                    "status": job["status"],
                    "group_name": job["group_name"],
                }
            else:
                release_mutation_lock()
        else:
            result = client.set_rule_status_via_gui(name, target_status)
            group_restore = {"status": "none"}
            release_mutation_lock()
    except SophosAPIError as exc:
        release_mutation_lock()
        return jsonify({"error": str(exc)}), 502
    except Exception:
        release_mutation_lock()
        raise

    rule = result.as_dict()
    if group_restore.get("group_name"):
        rule["group_name"] = group_restore["group_name"]
    return jsonify({"rule": rule, "group_restore": group_restore})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
