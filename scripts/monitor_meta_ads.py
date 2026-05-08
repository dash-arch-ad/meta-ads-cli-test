#!/usr/bin/env python
from __future__ import annotations

import argparse
import ast
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNS_LOG = PROJECT_ROOT / "logs" / "runs.log"
PAUSED_LOG = PROJECT_ROOT / "logs" / "paused_ads.log"

ALLOWED_MODES = {"dry_run", "active"}
ALLOWED_ACTIONS = {"pause_ad"}
PAUSED_STATUS = "PAUSED"
SENSITIVE_ENV_HINTS = ("TOKEN", "SECRET", "PASSWORD", "API_KEY")
DEFAULT_INSIGHTS_FIELDS = "ad_id,ad_name,campaign_id,campaign_name,spend,conversions,actions,date_start,date_stop"

DATE_PRESET_FALLBACKS = {
    "maximum": "last_90d",
    "max": "last_90d",
    "37_months": "last_90d",
}


@dataclass(frozen=True)
class Match:
    ad: dict[str, Any]
    rule: dict[str, Any]
    reason: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def sync_meta_cli_env() -> None:
    meta_token = os.getenv("META_ACCESS_TOKEN")
    meta_account_id = os.getenv("META_AD_ACCOUNT_ID")

    if meta_token:
        os.environ.setdefault("ACCESS_TOKEN", meta_token)

    if meta_account_id:
        os.environ.setdefault("AD_ACCOUNT_ID", meta_account_id.removeprefix("act_"))


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh) or {}

    if not isinstance(config, dict):
        raise ValueError("Config root must be a mapping.")

    return config


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def short_hash(value: Any) -> str:
    return sha256(str(value).encode("utf-8")).hexdigest()[:12]


def secret_values() -> list[str]:
    values: list[str] = []

    for key, value in os.environ.items():
        if not value:
            continue
        if any(hint in key.upper() for hint in SENSITIVE_ENV_HINTS):
            values.append(value)

    account_id = os.getenv("META_AD_ACCOUNT_ID")
    if account_id:
        values.extend([account_id, account_id.removeprefix("act_")])

    room_id = os.getenv("CHATWORK_ROOM_ID")
    if room_id:
        values.append(room_id)

    allowed_campaign_ids = os.getenv("META_ALLOWED_CAMPAIGN_IDS")
    if allowed_campaign_ids:
        values.extend(
            item.strip()
            for item in allowed_campaign_ids.replace("\n", ",").split(",")
            if item.strip()
        )

    return sorted(set(values), key=len, reverse=True)


def redact_text(value: Any) -> str:
    text = str(value)

    for secret in secret_values():
        if secret:
            text = text.replace(secret, "[REDACTED]")

    return text


def sanitize_command_like_result(result: dict[str, Any]) -> dict[str, Any]:
    command = result.get("command") or []

    return {
        "command": [redact_text(part) for part in command],
        "returncode": result.get("returncode"),
        "stdout_bytes": len(result.get("stdout") or ""),
        "stderr_preview": redact_text(result.get("stderr") or "")[:500],
    }


def sanitize_command_like_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [sanitize_command_like_result(result) for result in results]


def public_ad_ref(ad_id: Any) -> str:
    return f"ad_{short_hash(ad_id)}"


def public_campaign_ref(campaign_id: Any) -> str:
    return f"campaign_{short_hash(campaign_id)}"


def sanitize_match(match: Match, selected_for_pause: bool) -> dict[str, Any]:
    return {
        "ad_ref": public_ad_ref(match.ad["ad_id"]),
        "campaign_ref": public_campaign_ref(match.ad.get("campaign_id")),
        "rule": match.rule.get("name"),
        "status": match.ad.get("status") or "",
        "selected_for_pause": selected_for_pause,
    }


def sanitize_chatwork_result(result: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(result)

    if "response" in sanitized:
        sanitized["response"] = "[REDACTED]"

    if "error" in sanitized:
        sanitized["error"] = redact_text(sanitized["error"])[:500]

    if "reason" in sanitized:
        sanitized["reason"] = redact_text(sanitized["reason"])

    return sanitized


def sanitize_paused_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": record.get("timestamp"),
        "ad_account_ref": short_hash(record.get("ad_account_id")),
        "ad_ref": public_ad_ref(record.get("ad_id")),
        "campaign_ref": public_campaign_ref(record.get("campaign_id")),
        "rule": record.get("rule"),
        "reason": record.get("reason"),
        "paused": record.get("paused"),
        "dry_run": record.get("dry_run", False),
        "skip_reason": record.get("skip_reason"),
        "meta_cli_result": sanitize_command_like_result(record.get("meta_cli_result") or {}),
        "chatwork_notification": sanitize_chatwork_result(record.get("chatwork_notification") or {}),
    }


def rule_public_summary(rule: dict[str, Any]) -> dict[str, Any]:
    allowed_keys = {
        "name",
        "level",
        "window",
        "spend_gt",
        "min_spend",
        "conversions_lt",
        "min_conversions",
        "max_conversions",
        "max_cpa",
        "action",
    }

    return {key: rule.get(key) for key in allowed_keys if key in rule}


def require_safe_config(config: dict[str, Any]) -> None:
    mode = config.get("mode", "dry_run")
    if mode not in ALLOWED_MODES:
        raise ValueError(f"Unsupported mode: {mode!r}. Use dry_run or active.")

    safety = config.get("safety") or {}
    forbidden_flags = {
        "allow_delete": False,
        "allow_campaign_change": False,
        "allow_adset_change": False,
        "allow_budget_change": False,
    }

    for key, required in forbidden_flags.items():
        if safety.get(key) is not required:
            raise ValueError(f"Unsafe config: safety.{key} must be {required}.")

    max_pauses = int(safety.get("max_pauses_per_run", 0))
    if max_pauses < 1 or max_pauses > 100:
        raise ValueError("Unsafe config: safety.max_pauses_per_run must be between 1 and 100.")

    allowed_campaign_ids = allowed_campaign_ids_from_config_or_env(config)
    if not allowed_campaign_ids:
        raise ValueError(
            "Unsafe config: META_ALLOWED_CAMPAIGN_IDS or target.allowed_campaign_ids must not be empty."
        )

    for rule in config.get("rules") or []:
        if rule.get("level") != "ad":
            raise ValueError(f"Unsupported rule level for {rule.get('name')}: only ad is allowed.")

        if rule.get("action") not in ALLOWED_ACTIONS:
            raise ValueError(
                f"Unsupported rule action for {rule.get('name')}: only pause_ad is allowed."
            )


def resolve_ad_account_id(config: dict[str, Any]) -> str:
    account_id = os.getenv("META_AD_ACCOUNT_ID") or (config.get("meta") or {}).get("ad_account_id")

    if not account_id or account_id == "act_xxxxxxxxxx":
        raise ValueError("META_AD_ACCOUNT_ID or meta.ad_account_id must be set.")

    return account_id


def allowed_campaign_ids_from_config_or_env(config: dict[str, Any]) -> list[str]:
    env_value = os.getenv("META_ALLOWED_CAMPAIGN_IDS", "")

    if env_value.strip():
        normalized = env_value.replace("\n", ",")
        return [
            item.strip().strip('"').strip("'")
            for item in normalized.split(",")
            if item.strip()
        ]

    return [
        str(cid)
        for cid in ((config.get("target") or {}).get("allowed_campaign_ids") or [])
        if str(cid) and not str(cid).startswith("SET_")
    ]


def require_token() -> None:
    if not os.getenv("META_ACCESS_TOKEN"):
        raise ValueError("META_ACCESS_TOKEN must be set in the environment or .env.")


def meta_access_token() -> str:
    token = os.getenv("META_ACCESS_TOKEN") or os.getenv("ACCESS_TOKEN")
    if not token:
        raise ValueError("META_ACCESS_TOKEN must be set.")
    return token


def graph_api_version(config: dict[str, Any]) -> str:
    return (
        os.getenv("META_GRAPH_API_VERSION")
        or (config.get("meta_api") or {}).get("version")
        or "v25.0"
    )


def format_args(args: list[str], values: dict[str, Any]) -> list[str]:
    return [str(arg).format(**values) for arg in args]


def run_cli(executable: str, args: list[str]) -> dict[str, Any]:
    command = [executable, *args]

    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def graph_api_get_json(
    config: dict[str, Any],
    path: str,
    params: dict[str, Any] | None = None,
    *,
    absolute_url: str | None = None,
) -> dict[str, Any]:
    if absolute_url:
        url = absolute_url
    else:
        version = graph_api_version(config)
        base_url = f"https://graph.facebook.com/{version}/{path.lstrip('/')}"
        query_params = dict(params or {})
        query_params["access_token"] = meta_access_token()
        url = f"{base_url}?{urllib.parse.urlencode(query_params)}"

    request = urllib.request.Request(url, method="GET")

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8", errors="replace")
            payload = json.loads(body)
            if not isinstance(payload, dict):
                raise RuntimeError("Meta Graph API returned non-object JSON.")
            return payload

    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Meta Graph API request failed: status={exc.code}, body={redact_text(body)[:1000]}"
        ) from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(f"Meta Graph API request failed: {redact_text(exc)}") from exc


def graph_api_get_paginated_data(
    config: dict[str, Any],
    path: str,
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    pages = 0

    payload = graph_api_get_json(config, path, params)
    pages += 1

    while True:
        data = payload.get("data") or []
        if not isinstance(data, list):
            raise RuntimeError("Meta Graph API data field was not a list.")

        rows.extend([row for row in data if isinstance(row, dict)])

        next_url = (payload.get("paging") or {}).get("next")
        if not next_url:
            break

        payload = graph_api_get_json(config, "", absolute_url=next_url)
        pages += 1

    return rows, pages


def allowed_graph_date_preset(window: str) -> str:
    return DATE_PRESET_FALLBACKS.get(window, window)


def parse_json_output(stdout: str) -> list[dict[str, Any]]:
    if not stdout:
        return []

    payload = json.loads(stdout)

    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]

    if isinstance(payload, dict):
        for key in ("data", "results", "ads", "insights"):
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]

        return [payload]

    raise ValueError("Meta Ads CLI output must be a JSON object or array.")


def number(value: Any, default: float = 0.0) -> float:
    if value is None or value == "":
        return default

    if isinstance(value, (int, float)):
        return float(value)

    try:
        return float(str(value).replace(",", ""))
    except (TypeError, ValueError):
        return default


def parse_action_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]

    if not isinstance(value, str) or not value.strip():
        return []

    text = value.strip()

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        try:
            payload = ast.literal_eval(text)
        except (ValueError, SyntaxError):
            return []

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    return []


def action_value(actions: list[dict[str, Any]], conversion_event: str) -> float | None:
    candidates = {conversion_event}

    if conversion_event == "purchase":
        candidates.update(
            {
                "purchase",
                "omni_purchase",
                "offsite_conversion.fb_pixel_purchase",
                "offsite_conversion.fb_pixel_custom.purchase",
                "onsite_conversion.purchase",
            }
        )

    total = 0.0
    found = False

    for action in actions:
        action_type = str(
            action.get("action_type")
            or action.get("type")
            or action.get("name")
            or ""
        )

        if action_type in candidates or action_type.endswith(f".{conversion_event}"):
            total += number(action.get("value") or action.get("count"))
            found = True

    return total if found else None


def conversions_from_ad(ad: dict[str, Any], conversion_event: str) -> float:
    action_sources: list[dict[str, Any]] = []

    for key in ("actions", "conversions"):
        action_sources.extend(parse_action_list(ad.get(key)))

    from_actions = action_value(action_sources, conversion_event)

    if from_actions is not None:
        return from_actions

    for key in ("conversion_count", "cv"):
        if key in ad:
            return number(ad.get(key))

    if "conversions" in ad and not isinstance(ad.get("conversions"), (list, dict)):
        return number(ad.get("conversions"))

    return 0.0


def normalize_ad(raw: dict[str, Any], conversion_event: str) -> dict[str, Any]:
    spend = number(raw.get("spend"))
    conversions = conversions_from_ad(raw, conversion_event)
    cpa = spend / conversions if conversions > 0 else None

    return {
        **raw,
        "ad_id": str(raw.get("ad_id") or raw.get("id") or ""),
        "ad_name": raw.get("ad_name") or raw.get("name") or "",
        "campaign_id": str(raw.get("campaign_id") or ""),
        "campaign_name": raw.get("campaign_name") or "",
        "spend": spend,
        "conversions": conversions,
        "cpa": cpa,
        "status": raw.get("status") or raw.get("effective_status") or "",
    }


def evaluate_rule_with_diagnostic(
    ad: dict[str, Any],
    rule: dict[str, Any],
) -> tuple[str | None, dict[str, Any]]:
    spend = float(ad["spend"])
    conversions = float(ad["conversions"])
    cpa = ad["cpa"]

    diagnostic = {
        "rule": rule.get("name"),
        "matched": False,
        "decision": None,
        "detail": None,
        "thresholds": rule_public_summary(rule),
    }

    if "spend_gt" in rule and spend <= float(rule["spend_gt"]):
        diagnostic["decision"] = "spend_not_gt"
        diagnostic["detail"] = f"spend={spend:g} threshold={float(rule['spend_gt']):g}"
        return None, diagnostic

    if "min_spend" in rule and spend < float(rule["min_spend"]):
        diagnostic["decision"] = "spend_below_min"
        diagnostic["detail"] = f"spend={spend:g} threshold={float(rule['min_spend']):g}"
        return None, diagnostic

    if "conversions_lt" in rule and conversions >= float(rule["conversions_lt"]):
        diagnostic["decision"] = "conversions_not_lt"
        diagnostic["detail"] = (
            f"conversions={conversions:g} threshold={float(rule['conversions_lt']):g}"
        )
        return None, diagnostic

    if "min_conversions" in rule and conversions < float(rule["min_conversions"]):
        diagnostic["decision"] = "conversions_below_min"
        diagnostic["detail"] = (
            f"conversions={conversions:g} threshold={float(rule['min_conversions']):g}"
        )
        return None, diagnostic

    if "max_conversions" in rule and conversions > float(rule["max_conversions"]):
        diagnostic["decision"] = "conversions_above_max"
        diagnostic["detail"] = (
            f"conversions={conversions:g} threshold={float(rule['max_conversions']):g}"
        )
        return None, diagnostic

    if "max_cpa" in rule:
        if cpa is None:
            diagnostic["decision"] = "cpa_none"
            diagnostic["detail"] = "cpa=None"
            return None, diagnostic

        if cpa < float(rule["max_cpa"]):
            diagnostic["decision"] = "cpa_below_threshold"
            diagnostic["detail"] = f"cpa={cpa:g} threshold={float(rule['max_cpa']):g}"
            return None, diagnostic

    reason_parts = [
        f"rule={rule.get('name')}",
        f"spend={spend:g}",
        f"conversions={conversions:g}",
    ]

    if cpa is not None:
        reason_parts.append(f"cpa={cpa:g}")

    reason = ", ".join(reason_parts)

    diagnostic["matched"] = True
    diagnostic["decision"] = "matched"
    diagnostic["detail"] = reason

    return reason, diagnostic


def find_matches_with_diagnostics(
    ads: list[dict[str, Any]],
    config: dict[str, Any],
) -> tuple[list[Match], list[dict[str, Any]], dict[str, int]]:
    conversion_event = (config.get("meta") or {}).get("conversion_event", "")
    allowed_campaign_ids = set(allowed_campaign_ids_from_config_or_env(config))

    matches: list[Match] = []
    diagnostics: list[dict[str, Any]] = []
    matched_ad_ids: set[str] = set()

    summary = {
        "fetched": len(ads),
        "not_allowed_campaign": 0,
        "already_paused": 0,
        "missing_ad_id": 0,
        "evaluated": 0,
        "matched": 0,
    }

    for raw in ads:
        ad = normalize_ad(raw, conversion_event)

        diagnostic = {
            "ad_ref": public_ad_ref(ad.get("ad_id") or "missing"),
            "campaign_ref": public_campaign_ref(ad.get("campaign_id") or "missing"),
            "spend": ad.get("spend"),
            "conversions": ad.get("conversions"),
            "cpa": ad.get("cpa"),
            "status": ad.get("status") or "",
            "skipped": False,
            "skip_reason": None,
            "rule_evaluations": [],
        }

        if ad["campaign_id"] not in allowed_campaign_ids:
            summary["not_allowed_campaign"] += 1
            diagnostic["skipped"] = True
            diagnostic["skip_reason"] = "campaign_not_allowed"
            diagnostics.append(diagnostic)
            continue

        if ad["status"] == PAUSED_STATUS:
            summary["already_paused"] += 1
            diagnostic["skipped"] = True
            diagnostic["skip_reason"] = "already_paused"
            diagnostics.append(diagnostic)
            continue

        if not ad["ad_id"]:
            summary["missing_ad_id"] += 1
            diagnostic["skipped"] = True
            diagnostic["skip_reason"] = "missing_ad_id"
            diagnostics.append(diagnostic)
            continue

        summary["evaluated"] += 1

        for rule in config.get("rules") or []:
            reason, rule_diagnostic = evaluate_rule_with_diagnostic(ad, rule)
            diagnostic["rule_evaluations"].append(rule_diagnostic)

            if reason and ad["ad_id"] not in matched_ad_ids:
                matches.append(Match(ad=ad, rule=rule, reason=reason))
                matched_ad_ids.add(ad["ad_id"])
                summary["matched"] += 1
                break

        diagnostics.append(diagnostic)

    return matches, diagnostics, summary


def insights_window(config: dict[str, Any]) -> str:
    windows = {
        str(rule.get("window"))
        for rule in (config.get("rules") or [])
        if rule.get("window")
    }

    if not windows:
        return "24h"

    if len(windows) > 1:
        raise ValueError("All initial rules must use the same window for one insights call.")

    return next(iter(windows))


def ensure_ad_level_insights(rows: list[dict[str, Any]]) -> None:
    if not rows:
        return

    missing_ad_id_rows = [row for row in rows if not (row.get("ad_id") or row.get("id"))]

    if missing_ad_id_rows and len(missing_ad_id_rows) == len(rows):
        sample = missing_ad_id_rows[0]
        safe_keys = sorted(str(key) for key in sample.keys())

        raise RuntimeError(
            "Meta Graph API insights did not return ad-level rows. "
            "No ad_id was present, so ads cannot be paused. "
            "The fetch must use level=ad. "
            f"Returned keys: {safe_keys}"
        )


def fetch_insights(
    config: dict[str, Any],
    ad_account_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch ad-level insights directly from Meta Graph API.

    The Meta Ads CLI in this environment returned campaign-level aggregate rows,
    even though the monitor needs ad_id. Therefore this function does not use
    `meta ads insights get`; it calls the campaign insights edge with level=ad.
    """
    del ad_account_id  # Kept in the signature for compatibility with existing main().

    meta_api = config.get("meta_api") or {}
    fields = meta_api.get("insights_fields") or (config.get("meta_cli") or {}).get(
        "insights_fields",
        DEFAULT_INSIGHTS_FIELDS,
    )

    window = allowed_graph_date_preset(insights_window(config))

    all_ads: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for campaign_id in allowed_campaign_ids_from_config_or_env(config):
        params = {
            "level": "ad",
            "date_preset": window,
            "fields": fields,
            "limit": int(meta_api.get("limit", 500)),
        }

        rows, pages = graph_api_get_paginated_data(
            config,
            f"{campaign_id}/insights",
            params,
        )

        ensure_ad_level_insights(rows)
        all_ads.extend(rows)

        results.append(
            {
                "command": [
                    "meta-graph-api",
                    f"/{public_campaign_ref(campaign_id)}/insights",
                    "level=ad",
                    f"date_preset={window}",
                    f"fields={fields}",
                ],
                "returncode": 0,
                "stdout": json.dumps(
                    {
                        "rows": len(rows),
                        "pages": pages,
                    },
                    ensure_ascii=False,
                ),
                "stderr": "",
            }
        )

    return all_ads, results


def fetch_ad_status(config: dict[str, Any], ad_id: str) -> str:
    payload = graph_api_get_json(
        config,
        ad_id,
        {
            "fields": "effective_status,status",
        },
    )

    return str(payload.get("effective_status") or payload.get("status") or "")


def pause_ad(config: dict[str, Any], ad_id: str) -> dict[str, Any]:
    cli = config.get("meta_cli") or {}
    executable = cli.get("executable", "meta")

    args_template = cli.get("pause_args") or []
    args = format_args(args_template, {"ad_id": ad_id, "status": PAUSED_STATUS})

    result = run_cli(executable, args)

    if result["returncode"] != 0:
        raise RuntimeError(
            f"Meta Ads CLI pause command failed for {public_ad_ref(ad_id)}: "
            f"{redact_text(result['stderr'] or result['stdout'])}"
        )

    return result


def build_chatwork_message(paused_record: dict[str, Any]) -> str:
    return "\n".join(
        [
            "[info][title]Meta ad paused[/title]",
            f"Ad ref: {public_ad_ref(paused_record.get('ad_id'))}",
            f"Campaign ref: {public_campaign_ref(paused_record.get('campaign_id'))}",
            f"Rule: {paused_record.get('rule') or '-'}",
            f"Reason: {paused_record.get('reason') or '-'}",
            f"Ad account ref: {short_hash(paused_record.get('ad_account_id'))}",
            f"Run time (UTC): {paused_record.get('timestamp') or '-'}",
            "[/info]",
        ]
    )


def notify_chatwork(message: str) -> dict[str, Any]:
    token = os.getenv("CHATWORK_API_TOKEN")
    room_id = os.getenv("CHATWORK_ROOM_ID")

    if not token or not room_id:
        return {
            "enabled": False,
            "sent": False,
            "reason": "CHATWORK_API_TOKEN or CHATWORK_ROOM_ID is not set.",
        }

    url = f"https://api.chatwork.com/v2/rooms/{room_id}/messages"
    data = urllib.parse.urlencode({"body": message, "self_unread": "0"}).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "x-chatworktoken": token,
            "content-type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8", errors="replace")
            return {
                "enabled": True,
                "sent": 200 <= response.status < 300,
                "status": response.status,
                "response": body,
            }

    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {
            "enabled": True,
            "sent": False,
            "status": exc.code,
            "error": body,
        }

    except Exception as exc:
        return {
            "enabled": True,
            "sent": False,
            "error": str(exc),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Pause Meta ads that match local guard rules.")
    parser.add_argument("--config", default=str(PROJECT_ROOT / "config" / "rules.yml"))
    args = parser.parse_args()

    load_dotenv(PROJECT_ROOT / ".env")
    sync_meta_cli_env()

    config_path = Path(args.config).resolve()

    run_record: dict[str, Any] = {
        "timestamp": utc_now_iso(),
        "config": str(config_path),
        "mode": None,
        "ad_account_ref": None,
        "fetch_source": "meta_graph_api",
        "ads_fetched": 0,
        "rules": [],
        "evaluation_summary": {},
        "evaluated_ads": [],
        "matched_ads": [],
        "paused_ads": [],
        "errors": [],
    }

    try:
        config = load_config(config_path)
        require_safe_config(config)
        require_token()

        ad_account_id = resolve_ad_account_id(config)
        mode = config.get("mode", "dry_run")
        max_pauses = int((config.get("safety") or {}).get("max_pauses_per_run", 3))

        run_record["mode"] = mode
        run_record["ad_account_ref"] = short_hash(ad_account_id)
        run_record["rules"] = [
            rule_public_summary(rule)
            for rule in (config.get("rules") or [])
        ]

        ads, fetch_result = fetch_insights(config, ad_account_id)
        matches, ad_diagnostics, evaluation_summary = find_matches_with_diagnostics(
            ads,
            config,
        )
        limited_matches = matches[:max_pauses]

        run_record["ads_fetched"] = len(ads)
        run_record["meta_api_fetch"] = sanitize_command_like_results(fetch_result)
        run_record["evaluation_summary"] = evaluation_summary
        run_record["evaluated_ads"] = ad_diagnostics
        run_record["matched_ads"] = [
            sanitize_match(match, match in limited_matches)
            for match in matches
        ]

        if mode == "active":
            for match in limited_matches:
                current_status = fetch_ad_status(config, match.ad["ad_id"])

                if current_status == PAUSED_STATUS:
                    already_paused_record = {
                        "timestamp": utc_now_iso(),
                        "ad_account_id": ad_account_id,
                        "ad_id": match.ad["ad_id"],
                        "campaign_id": match.ad["campaign_id"],
                        "rule": match.rule.get("name"),
                        "reason": match.reason,
                        "paused": False,
                        "skip_reason": "already_paused_before_pause_call",
                    }
                    run_record["paused_ads"].append(sanitize_paused_record(already_paused_record))
                    continue

                pause_result = pause_ad(config, match.ad["ad_id"])

                paused_record = {
                    "timestamp": utc_now_iso(),
                    "ad_account_id": ad_account_id,
                    "ad_id": match.ad["ad_id"],
                    "ad_name": match.ad["ad_name"],
                    "campaign_id": match.ad["campaign_id"],
                    "rule": match.rule.get("name"),
                    "reason": match.reason,
                    "paused": True,
                    "meta_cli_result": pause_result,
                }

                chatwork_result = notify_chatwork(build_chatwork_message(paused_record))
                paused_record["chatwork_notification"] = chatwork_result

                if chatwork_result.get("enabled") and not chatwork_result.get("sent"):
                    run_record["errors"].append(
                        f"Chatwork notification failed for {public_ad_ref(match.ad['ad_id'])}: "
                        f"{redact_text(chatwork_result.get('error') or chatwork_result.get('status'))}"
                    )

                sanitized_paused_record = sanitize_paused_record(paused_record)
                run_record["paused_ads"].append(sanitized_paused_record)
                append_jsonl(PAUSED_LOG, sanitized_paused_record)

        else:
            for match in limited_matches:
                run_record["paused_ads"].append(
                    sanitize_paused_record(
                        {
                            "timestamp": utc_now_iso(),
                            "ad_account_id": ad_account_id,
                            "ad_id": match.ad["ad_id"],
                            "campaign_id": match.ad["campaign_id"],
                            "rule": match.rule.get("name"),
                            "reason": match.reason,
                            "paused": False,
                            "dry_run": True,
                        }
                    )
                )

        append_jsonl(RUNS_LOG, run_record)
        print(json.dumps(run_record, ensure_ascii=False, indent=2))
        return 0

    except Exception as exc:
        run_record["errors"].append(redact_text(exc))
        append_jsonl(RUNS_LOG, run_record)
        print(json.dumps(run_record, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
