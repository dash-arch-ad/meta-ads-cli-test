#!/usr/bin/env python
from __future__ import annotations

import argparse
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


def sanitize_cli_result(result: dict[str, Any]) -> dict[str, Any]:
    command = result.get("command") or []
    return {
        "command": [redact_text(part) for part in command],
        "returncode": result.get("returncode"),
        "stdout_bytes": len(result.get("stdout") or ""),
        "stderr_preview": redact_text(result.get("stderr") or "")[:500],
    }


def sanitize_cli_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [sanitize_cli_result(result) for result in results]


def public_ad_ref(ad_id: Any) -> str:
    return f"ad_{short_hash(ad_id)}"


def sanitize_match(match: Match, selected_for_pause: bool) -> dict[str, Any]:
    return {
        "ad_ref": public_ad_ref(match.ad["ad_id"]),
        "rule": match.rule.get("name"),
        "status": match.ad["status"],
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
        "rule": record.get("rule"),
        "paused": record.get("paused"),
        "dry_run": record.get("dry_run", False),
        "meta_cli_result": sanitize_cli_result(record.get("meta_cli_result") or {}),
        "chatwork_notification": sanitize_chatwork_result(record.get("chatwork_notification") or {}),
    }


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
        raise ValueError("Unsafe config: META_ALLOWED_CAMPAIGN_IDS or target.allowed_campaign_ids must not be empty.")

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
        return [item.strip().strip('"').strip("'") for item in normalized.split(",") if item.strip()]
    return [
        str(cid)
        for cid in ((config.get("target") or {}).get("allowed_campaign_ids") or [])
        if str(cid) and not str(cid).startswith("SET_")
    ]


def require_token() -> None:
    if not os.getenv("META_ACCESS_TOKEN"):
        raise ValueError("META_ACCESS_TOKEN must be set in the environment or .env.")


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
    return float(str(value).replace(",", ""))


def conversions_from_ad(ad: dict[str, Any], conversion_event: str) -> float:
    for key in ("conversions", "conversion_count", "cv"):
        if key in ad:
            return number(ad.get(key))

    actions = ad.get("actions") or []
    if isinstance(actions, list):
        for action in actions:
            if not isinstance(action, dict):
                continue
            action_type = action.get("action_type") or action.get("type") or action.get("name")
            if action_type == conversion_event:
                return number(action.get("value") or action.get("count"))
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


def evaluate_rule(ad: dict[str, Any], rule: dict[str, Any]) -> str | None:
    spend = float(ad["spend"])
    conversions = float(ad["conversions"])
    cpa = ad["cpa"]

    if "spend_gt" in rule and spend <= float(rule["spend_gt"]):
        return None
    if "min_spend" in rule and spend < float(rule["min_spend"]):
        return None
    if "conversions_lt" in rule and conversions >= float(rule["conversions_lt"]):
        return None
    if "min_conversions" in rule and conversions < float(rule["min_conversions"]):
        return None
    if "max_conversions" in rule and conversions > float(rule["max_conversions"]):
        return None
    if "max_cpa" in rule:
        if cpa is None or cpa < float(rule["max_cpa"]):
            return None

    parts = [f"rule={rule.get('name')}", f"spend={spend:g}", f"conversions={conversions:g}"]
    if cpa is not None:
        parts.append(f"cpa={cpa:g}")
    return ", ".join(parts)


def find_matches(ads: list[dict[str, Any]], config: dict[str, Any]) -> list[Match]:
    conversion_event = (config.get("meta") or {}).get("conversion_event", "")
    allowed_campaign_ids = set(allowed_campaign_ids_from_config_or_env(config))
    matches: list[Match] = []
    matched_ad_ids: set[str] = set()

    for raw in ads:
        ad = normalize_ad(raw, conversion_event)
        if ad["campaign_id"] not in allowed_campaign_ids:
            continue
        if ad["status"] == PAUSED_STATUS:
            continue
        if not ad["ad_id"]:
            continue
        for rule in config.get("rules") or []:
            reason = evaluate_rule(ad, rule)
            if reason and ad["ad_id"] not in matched_ad_ids:
                matches.append(Match(ad=ad, rule=rule, reason=reason))
                matched_ad_ids.add(ad["ad_id"])
                break
    return matches


def insights_window(config: dict[str, Any]) -> str:
    windows = {
        str(rule.get("window"))
        for rule in (config.get("rules") or [])
        if rule.get("window")
    }
    if not windows:
        return "24h"
    if len(windows) > 1:
        raise ValueError("All initial rules must use the same window for one CLI insights call.")
    return next(iter(windows))


def fetch_insights(config: dict[str, Any], ad_account_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cli = config.get("meta_cli") or {}
    executable = cli.get("executable", "meta")
    args_template = cli.get("insights_args") or []
    all_ads: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for campaign_id in allowed_campaign_ids_from_config_or_env(config):
        args = format_args(
            args_template,
            {
                "ad_account_id": ad_account_id,
                "campaign_id": campaign_id,
                "window": insights_window(config),
            },
        )
        result = run_cli(executable, args)
        results.append(result)
        if result["returncode"] != 0:
            raise RuntimeError(f"Meta Ads CLI insights command failed: {result['stderr'] or result['stdout']}")
        all_ads.extend(parse_json_output(result["stdout"]))

    return all_ads, results


def pause_ad(config: dict[str, Any], ad_id: str) -> dict[str, Any]:
    cli = config.get("meta_cli") or {}
    executable = cli.get("executable", "meta")
    args_template = cli.get("pause_args") or []
    args = format_args(args_template, {"ad_id": ad_id, "status": PAUSED_STATUS})
    result = run_cli(executable, args)
    if result["returncode"] != 0:
        raise RuntimeError(f"Meta Ads CLI pause command failed for {ad_id}: {result['stderr'] or result['stdout']}")
    return result


def build_chatwork_message(paused_record: dict[str, Any]) -> str:
    return "\n".join(
        [
            "[info][title]Meta ad paused[/title]",
            f"Ad ID: {paused_record['ad_id']}",
            f"Ad name: {paused_record.get('ad_name') or '-'}",
            f"Campaign ID: {paused_record.get('campaign_id') or '-'}",
            f"Rule: {paused_record.get('rule') or '-'}",
            f"Reason: {paused_record.get('reason') or '-'}",
            f"Ad account: {paused_record.get('ad_account_id') or '-'}",
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
        "ads_fetched": 0,
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

        ads, fetch_result = fetch_insights(config, ad_account_id)
        matches = find_matches(ads, config)
        limited_matches = matches[:max_pauses]

        run_record["ads_fetched"] = len(ads)
        run_record["meta_cli_fetch"] = sanitize_cli_results(fetch_result)
        run_record["matched_ads"] = [
            sanitize_match(match, match in limited_matches)
            for match in matches
        ]

        if mode == "active":
            for match in limited_matches:
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
                        f"Chatwork notification failed for {public_ad_ref(match.ad['ad_id'])}: {redact_text(chatwork_result.get('error') or chatwork_result.get('status'))}"
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
