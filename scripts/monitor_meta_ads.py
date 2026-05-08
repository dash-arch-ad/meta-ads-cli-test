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


def short_hash(value: Any) -> str:
    return sha256(str(value).encode("utf-8")).hexdigest()[:12]


def public_ad_ref(ad_id: Any) -> str:
    return f"ad_{short_hash(ad_id)}"


def public_campaign_ref(campaign_id: Any) -> str:
    return f"campaign_{short_hash(campaign_id)}"


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


def sanitized_cli_summary(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "returncode": result.get("returncode"),
        "stderr_preview": redact_text(result.get("stderr") or "")[:300],
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
            raise ValueError(f"Unsupported rule action for {rule.get('name')}: only pause_ad is allowed.")


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


def evaluate_rule(ad: dict[str, Any], rule: dict[str, Any]) -> tuple[str | None, str, str]:
    spend = float(ad["spend"])
    conversions = float(ad["conversions"])
    cpa = ad["cpa"]

    if "spend_gt" in rule and spend <= float(rule["spend_gt"]):
        return None, "spend_not_gt", f"spend={spend:g} threshold={float(rule['spend_gt']):g}"

    if "min_spend" in rule and spend < float(rule["min_spend"]):
        return None, "spend_below_min", f"spend={spend:g} threshold={float(rule['min_spend']):g}"

    if "conversions_lt" in rule and conversions >= float(rule["conversions_lt"]):
        return None, "conversions_not_lt", (
            f"conversions={conversions:g} threshold={float(rule['conversions_lt']):g}"
        )

    if "min_conversions" in rule and conversions < float(rule["min_conversions"]):
        return None, "conversions_below_min", (
            f"conversions={conversions:g} threshold={float(rule['min_conversions']):g}"
        )

    if "max_conversions" in rule and conversions > float(rule["max_conversions"]):
        return None, "conversions_above_max", (
            f"conversions={conversions:g} threshold={float(rule['max_conversions']):g}"
        )

    if "max_cpa" in rule:
        if cpa is None:
            return None, "cpa_none", "cpa=None"

        if cpa < float(rule["max_cpa"]):
            return None, "cpa_below_threshold", f"cpa={cpa:g} threshold={float(rule['max_cpa']):g}"

    reason_parts = [
        f"rule={rule.get('name')}",
        f"spend={spend:g}",
        f"conversions={conversions:g}",
    ]

    if cpa is not None:
        reason_parts.append(f"cpa={cpa:g}")

    return ", ".join(reason_parts), "matched", "matched"


def find_matches(
    ads: list[dict[str, Any]],
    config: dict[str, Any],
) -> tuple[list[Match], dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    conversion_event = (config.get("meta") or {}).get("conversion_event", "")
    allowed_campaign_ids = set(allowed_campaign_ids_from_config_or_env(config))

    matches: list[Match] = []
    matched_ad_ids: set[str] = set()
    matched_ads_summary: list[dict[str, Any]] = []
    decision_counts: dict[str, int] = {}

    summary: dict[str, Any] = {
        "fetched": len(ads),
        "not_allowed_campaign": 0,
        "already_paused_from_insights": 0,
        "missing_ad_id": 0,
        "evaluated": 0,
        "matched": 0,
    }

    for raw in ads:
        ad = normalize_ad(raw, conversion_event)

        if ad["campaign_id"] not in allowed_campaign_ids:
            summary["not_allowed_campaign"] += 1
            decision_counts["campaign_not_allowed"] = decision_counts.get("campaign_not_allowed", 0) + 1
            continue

        if ad["status"] == PAUSED_STATUS:
            summary["already_paused_from_insights"] += 1
            decision_counts["already_paused_from_insights"] = decision_counts.get("already_paused_from_insights", 0) + 1
            continue

        if not ad["ad_id"]:
            summary["missing_ad_id"] += 1
            decision_counts["missing_ad_id"] = decision_counts.get("missing_ad_id", 0) + 1
            continue

        summary["evaluated"] += 1

        matched_this_ad = False
        first_not_matched_decision = None

        for rule in config.get("rules") or []:
            reason, decision, detail = evaluate_rule(ad, rule)

            if reason and ad["ad_id"] not in matched_ad_ids:
                matches.append(Match(ad=ad, rule=rule, reason=reason))
                matched_ad_ids.add(ad["ad_id"])
                summary["matched"] += 1
                decision_counts["matched"] = decision_counts.get("matched", 0) + 1
                matched_this_ad = True

                matched_ads_summary.append(
                    {
                        "ad_ref": public_ad_ref(ad["ad_id"]),
                        "campaign_ref": public_campaign_ref(ad["campaign_id"]),
                        "rule": rule.get("name"),
                        "spend": ad["spend"],
                        "conversions": ad["conversions"],
                        "cpa": ad["cpa"],
                        "selected_for_pause": False,
                    }
                )
                break

            if first_not_matched_decision is None:
                first_not_matched_decision = decision

        if not matched_this_ad:
            decision = first_not_matched_decision or "not_matched"
            decision_counts[decision] = decision_counts.get(decision, 0) + 1

    return matches, summary, matched_ads_summary, decision_counts


def insights_window(config: dict[str, Any]) -> str:
    windows = {
        str(rule.get("window"))
        for rule in (config.get("rules") or [])
        if rule.get("window")
    }

    if not windows:
        return "24h"

    if len(windows) > 1:
        raise ValueError("All rules must use the same window for one insights call.")

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
    del ad_account_id  # Kept for compatibility with main().

    meta_api = config.get("meta_api") or {}
    fields = meta_api.get("insights_fields") or (config.get("meta_cli") or {}).get(
        "insights_fields",
        DEFAULT_INSIGHTS_FIELDS,
    )

    window = allowed_graph_date_preset(insights_window(config))

    all_ads: list[dict[str, Any]] = []
    fetch_summaries: list[dict[str, Any]] = []

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

        fetch_summaries.append(
            {
                "campaign_ref": public_campaign_ref(campaign_id),
                "rows": len(rows),
                "pages": pages,
                "level": "ad",
                "date_preset": window,
            }
        )

    return all_ads, fetch_summaries


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
            f"Ad ref: {paused_record.get('ad_ref')}",
            f"Campaign ref: {paused_record.get('campaign_ref')}",
            f"Rule: {paused_record.get('rule') or '-'}",
            f"Reason: {paused_record.get('reason') or '-'}",
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
                "response": "[REDACTED]",
            }

    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {
            "enabled": True,
            "sent": False,
            "status": exc.code,
            "error": redact_text(body)[:300],
        }

    except Exception as exc:
        return {
            "enabled": True,
            "sent": False,
            "error": redact_text(exc),
        }


def make_pause_summary_record(
    match: Match,
    *,
    paused: bool,
    dry_run: bool = False,
    skip_reason: str | None = None,
    meta_cli_result: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "ad_ref": public_ad_ref(match.ad["ad_id"]),
        "campaign_ref": public_campaign_ref(match.ad["campaign_id"]),
        "rule": match.rule.get("name"),
        "spend": match.ad["spend"],
        "conversions": match.ad["conversions"],
        "cpa": match.ad["cpa"],
        "paused": paused,
        "dry_run": dry_run,
        "skip_reason": skip_reason,
        "meta_cli_result": sanitized_cli_summary(meta_cli_result or {}),
        "error": error,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Pause Meta ads that match local guard rules.")
    parser.add_argument("--config", default=str(PROJECT_ROOT / "config" / "rules.yml"))
    args = parser.parse_args()

    load_dotenv(PROJECT_ROOT / ".env")
    sync_meta_cli_env()

    config_path = Path(args.config).resolve()

    output: dict[str, Any] = {
        "timestamp": utc_now_iso(),
        "mode": None,
        "fetch_source": "meta_graph_api",
        "ad_account_ref": None,
        "rules": [],
        "fetch": [],
        "evaluation_summary": {},
        "decision_counts": {},
        "matched_ads": [],
        "paused_ads": [],
        "errors": [],
    }

    exit_code = 0

    try:
        config = load_config(config_path)
        require_safe_config(config)
        require_token()

        ad_account_id = resolve_ad_account_id(config)
        mode = config.get("mode", "dry_run")
        max_pauses = int((config.get("safety") or {}).get("max_pauses_per_run", 3))

        output["mode"] = mode
        output["ad_account_ref"] = short_hash(ad_account_id)
        output["rules"] = [rule_public_summary(rule) for rule in (config.get("rules") or [])]

        ads, fetch_summaries = fetch_insights(config, ad_account_id)
        matches, evaluation_summary, matched_ads_summary, decision_counts = find_matches(ads, config)

        limited_matches = matches[:max_pauses]
        selected_refs = {public_ad_ref(match.ad["ad_id"]) for match in limited_matches}

        for item in matched_ads_summary:
            item["selected_for_pause"] = item["ad_ref"] in selected_refs

        output["fetch"] = fetch_summaries
        output["evaluation_summary"] = {
            **evaluation_summary,
            "selected_for_pause": len(limited_matches),
            "not_selected_due_to_max_pauses": max(0, len(matches) - len(limited_matches)),
        }
        output["decision_counts"] = decision_counts
        output["matched_ads"] = matched_ads_summary

        if mode == "active":
            for match in limited_matches:
                try:
                    pause_result = pause_ad(config, match.ad["ad_id"])
                    record = make_pause_summary_record(
                        match,
                        paused=True,
                        meta_cli_result=pause_result,
                    )
                    output["paused_ads"].append(record)

                    chatwork_record = {
                        "timestamp": utc_now_iso(),
                        "ad_ref": record["ad_ref"],
                        "campaign_ref": record["campaign_ref"],
                        "rule": record["rule"],
                        "reason": match.reason,
                    }
                    chatwork_result = notify_chatwork(build_chatwork_message(chatwork_record))
                    record["chatwork"] = {
                        "enabled": chatwork_result.get("enabled", False),
                        "sent": chatwork_result.get("sent", False),
                        "status": chatwork_result.get("status"),
                        "error": chatwork_result.get("error"),
                    }

                    if chatwork_result.get("enabled") and not chatwork_result.get("sent"):
                        output["errors"].append(
                            f"Chatwork notification failed for {record['ad_ref']}: "
                            f"{redact_text(chatwork_result.get('error') or chatwork_result.get('status'))}"
                        )

                except Exception as exc:
                    exit_code = 1
                    output["paused_ads"].append(
                        make_pause_summary_record(
                            match,
                            paused=False,
                            error=redact_text(exc),
                        )
                    )
                    output["errors"].append(f"Pause failed for {public_ad_ref(match.ad['ad_id'])}: {redact_text(exc)}")

        else:
            for match in limited_matches:
                output["paused_ads"].append(
                    make_pause_summary_record(
                        match,
                        paused=False,
                        dry_run=True,
                        skip_reason="dry_run",
                    )
                )

        output["pause_summary"] = {
            "matched": len(matches),
            "selected_for_pause": len(limited_matches),
            "pause_attempted": len(output["paused_ads"]),
            "paused": sum(1 for item in output["paused_ads"] if item.get("paused") is True),
            "not_paused": sum(1 for item in output["paused_ads"] if item.get("paused") is not True),
            "errors": len(output["errors"]),
        }

        print(json.dumps(output, ensure_ascii=False, indent=2))
        return exit_code

    except Exception as exc:
        output["errors"].append(redact_text(exc))
        output["pause_summary"] = {
            "matched": 0,
            "selected_for_pause": 0,
            "pause_attempted": 0,
            "paused": 0,
            "not_paused": 0,
            "errors": len(output["errors"]),
        }
        print(json.dumps(output, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
