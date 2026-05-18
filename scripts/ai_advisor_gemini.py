from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml


DEFAULT_MODEL = "gemini-2.5-flash"
GEMINI_ENDPOINT_TEMPLATE = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)

ALLOWED_ACTIONS = {
    "pause_review",
    "keep",
    "watch",
    "resume_test_review",
    "creative_test_review",
    "measurement_check",
    "lp_check",
}

FORBIDDEN_ACTIONS = {
    "pause_now",
    "resume_now",
    "increase_budget_now",
    "create_ad_now",
    "change_campaign_now",
}

VALID_PRIORITIES = {"high", "medium", "low", "reference"}
VALID_CONFIDENCES = {"high", "medium", "low"}


AD_DECISION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "ad_ref": {"type": "string"},
        "priority": {"type": "string", "enum": ["high", "medium", "low"]},
        "reason": {"type": "string"},
        "recommended_action": {
            "type": "string",
            "enum": [
                "pause_review",
                "keep",
                "watch",
                "resume_test_review",
                "measurement_check",
                "lp_check",
            ],
        },
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    },
    "required": ["ad_ref", "priority", "reason", "recommended_action", "confidence"],
}

ADVISOR_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "pause_candidates": {"type": "array", "items": AD_DECISION_SCHEMA},
        "keep_candidates": {"type": "array", "items": AD_DECISION_SCHEMA},
        "resume_candidates": {"type": "array", "items": AD_DECISION_SCHEMA},
        "creative_suggestions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "theme": {"type": "string"},
                    "message": {"type": "string"},
                    "reason": {"type": "string"},
                    "priority": {"type": "string", "enum": ["high", "medium", "low"]},
                },
                "required": ["theme", "message", "reason", "priority"],
            },
        },
        "warnings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "message": {"type": "string"},
                },
                "required": ["type", "message"],
            },
        },
    },
    "required": [
        "summary",
        "pause_candidates",
        "keep_candidates",
        "resume_candidates",
        "creative_suggestions",
        "warnings",
    ],
}


def load_ai_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"enabled": False, "skip_reason": f"{path} does not exist."}

    with path.open("r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh) or {}

    if not isinstance(config, dict):
        raise ValueError("AI advisor config root must be a mapping.")

    return config


def advisor_enabled(config: dict[str, Any]) -> bool:
    return bool(config.get("enabled", False))


def resolve_model(config: dict[str, Any]) -> str:
    model_env = str(config.get("model_env") or "GEMINI_MODEL")
    return os.getenv(model_env) or str(config.get("model") or DEFAULT_MODEL)


def prompt_for(ai_input: dict[str, Any]) -> str:
    return "\n".join(
        [
            "あなたはMeta広告運用の分析アシスタントです。",
            "停止・再開・予算増額・広告作成・キャンペーン変更は絶対に実行判断しません。",
            "返す内容は提案のみで、必ず指定JSON Schemaに沿ったJSONだけにしてください。",
            "",
            "許可されるrecommended_action:",
            ", ".join(sorted(ALLOWED_ACTIONS)),
            "",
            "禁止されるrecommended_action:",
            ", ".join(sorted(FORBIDDEN_ACTIONS)),
            "",
            "判断方針:",
            "- 消化額が最低額未満の広告は停止候補にしない。",
            "- CVが出ている広告を停止検討に入れる場合は慎重に理由を書く。",
            "- 計測異常や判断保留があればwarningsに入れる。",
            "- 新規バナー案は実行指示ではなく、訴求テーマの提案に限定する。",
            "",
            "入力データ:",
            json.dumps(ai_input, ensure_ascii=False, separators=(",", ":")),
        ]
    )


def build_request_payload(ai_input: dict[str, Any]) -> dict[str, Any]:
    return {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt_for(ai_input)}],
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "responseFormat": {
                "text": {
                    "mimeType": "application/json",
                    "schema": ADVISOR_RESPONSE_SCHEMA,
                }
            },
        },
    }


def call_gemini(ai_input: dict[str, Any], config: dict[str, Any], api_key: str) -> dict[str, Any]:
    model = resolve_model(config)
    url = GEMINI_ENDPOINT_TEMPLATE.format(model=model)
    payload = json.dumps(build_request_payload(ai_input), ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "content-type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            body = response.read().decode("utf-8", errors="replace")
            api_payload = json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Gemini API request failed: status={exc.code}, body={body[:800]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Gemini API request failed: {exc}") from exc

    text = extract_text(api_payload)
    try:
        response_json = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Gemini response was not valid JSON: {text[:800]}") from exc

    if not isinstance(response_json, dict):
        raise ValueError("Gemini response JSON root must be an object.")

    return {
        "model": model,
        "raw_response": api_payload,
        "proposal": response_json,
    }


def extract_text(api_payload: dict[str, Any]) -> str:
    candidates = api_payload.get("candidates") or []
    if not candidates:
        raise ValueError("Gemini response did not include candidates.")

    parts = ((candidates[0].get("content") or {}).get("parts") or [])
    texts = [str(part.get("text") or "") for part in parts if isinstance(part, dict)]
    text = "".join(texts).strip()
    if not text:
        raise ValueError("Gemini response did not include text.")

    return text


def validate_proposal(
    proposal: dict[str, Any],
    ai_input: dict[str, Any],
    config: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    ads = ai_input.get("ads") or []
    ad_by_ref = {str(ad.get("ad_ref")): ad for ad in ads if ad.get("ad_ref")}
    thresholds = config.get("thresholds") or {}
    min_pause_spend = float(thresholds.get("min_spend_for_pause_review", 0) or 0)
    validation_notes: list[str] = []

    clean: dict[str, Any] = {
        "summary": str(proposal.get("summary") or ""),
        "pause_candidates": [],
        "keep_candidates": [],
        "resume_candidates": [],
        "creative_suggestions": [],
        "warnings": [],
    }

    for section, expected_actions in (
        ("pause_candidates", {"pause_review", "watch", "measurement_check", "lp_check"}),
        ("keep_candidates", {"keep", "watch"}),
        ("resume_candidates", {"resume_test_review", "watch"}),
    ):
        items = proposal.get(section) or []
        if not isinstance(items, list):
            validation_notes.append(f"{section}: not_list")
            continue

        for item in items:
            normalized = normalize_decision_item(item)
            if not normalized:
                validation_notes.append(f"{section}: invalid_item")
                continue

            ad_ref = normalized["ad_ref"]
            action = normalized["recommended_action"]
            ad = ad_by_ref.get(ad_ref)

            if not ad:
                validation_notes.append(f"{section}: unknown_ad_ref:{ad_ref}")
                continue

            if action in FORBIDDEN_ACTIONS or action not in ALLOWED_ACTIONS or action not in expected_actions:
                validation_notes.append(f"{section}: disallowed_action:{ad_ref}:{action}")
                continue

            if section == "pause_candidates":
                spend = float(ad.get("spend") or 0)
                conversions = float(ad.get("conversions") or 0)

                if spend < min_pause_spend:
                    validation_notes.append(f"{section}: spend_below_min:{ad_ref}")
                    continue

                if normalized["confidence"] == "low":
                    normalized["priority"] = "reference"
                    normalized["guard_note"] = "low_confidence_pause_downgraded_to_reference"

                if conversions > 0:
                    normalized["guard_warning"] = "conversions_exist_pause_requires_human_review"
                    clean["warnings"].append(
                        {
                            "type": "pause_with_conversions",
                            "message": f"{ad_ref} はCVがあるため、停止検討は人の確認が必要です。",
                        }
                    )

            clean[section].append(normalized)

    clean["creative_suggestions"] = clean_creative_suggestions(
        proposal.get("creative_suggestions") or []
    )
    clean["warnings"].extend(clean_warnings(proposal.get("warnings") or []))

    return clean, validation_notes


def normalize_decision_item(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None

    ad_ref = str(item.get("ad_ref") or "").strip()
    priority = str(item.get("priority") or "medium").strip()
    reason = str(item.get("reason") or "").strip()
    action = str(item.get("recommended_action") or "").strip()
    confidence = str(item.get("confidence") or "medium").strip()

    if not ad_ref or not reason or not action:
        return None
    if priority not in VALID_PRIORITIES:
        priority = "medium"
    if confidence not in VALID_CONFIDENCES:
        confidence = "medium"

    return {
        "ad_ref": ad_ref,
        "priority": priority,
        "reason": reason,
        "recommended_action": action,
        "confidence": confidence,
    }


def clean_creative_suggestions(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []

    clean: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue

        theme = str(item.get("theme") or "").strip()
        message = str(item.get("message") or "").strip()
        reason = str(item.get("reason") or "").strip()
        priority = str(item.get("priority") or "medium").strip()

        if not theme or not message or not reason:
            continue
        if priority not in {"high", "medium", "low"}:
            priority = "medium"

        clean.append(
            {
                "theme": theme,
                "message": message,
                "reason": reason,
                "priority": priority,
                "recommended_action": "creative_test_review",
            }
        )

    return clean


def clean_warnings(items: Any) -> list[dict[str, str]]:
    if not isinstance(items, list):
        return []

    clean: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue

        warning_type = str(item.get("type") or "notice").strip()
        message = str(item.get("message") or "").strip()
        if not message:
            continue

        clean.append({"type": warning_type, "message": message})

    return clean


def run_ai_advisor(ai_input: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "enabled": advisor_enabled(config),
        "provider": config.get("provider") or "gemini",
        "model": resolve_model(config),
        "sent_to_model": False,
        "skipped": False,
        "proposal": None,
        "validation_notes": [],
        "error": None,
        "error_type": None,
    }

    if not result["enabled"]:
        result["skipped"] = True
        result["skip_reason"] = config.get("skip_reason") or "AI advisor is disabled."
        return result

    if result["provider"] != "gemini":
        result["skipped"] = True
        result["skip_reason"] = f"Unsupported AI advisor provider: {result['provider']}"
        return result

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        result["skipped"] = True
        result["skip_reason"] = "GEMINI_API_KEY is not set."
        return result

    try:
        gemini_result = call_gemini(ai_input, config, api_key)
        result["sent_to_model"] = True
        result["model"] = gemini_result["model"]
        proposal, validation_notes = validate_proposal(gemini_result["proposal"], ai_input, config)
        result["proposal"] = proposal
        result["validation_notes"] = validation_notes
        return result
    except ValueError as exc:
        result["error"] = str(exc)
        result["error_type"] = "invalid_response"
        return result
    except RuntimeError as exc:
        result["error"] = str(exc)
        result["error_type"] = "api_error"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = "unexpected_error"
        return result


def build_chatwork_message(result: dict[str, Any], config: dict[str, Any]) -> str:
    if result.get("error"):
        if result.get("error_type") == "api_error":
            return ""

        return "\n".join(
            [
                "【配信テスト中】Meta広告 AI運用提案",
                "",
                "※AI提案生成失敗。停止・再開・バナー追加は自動実行していません。",
            ]
        )

    proposal = result.get("proposal")
    if not proposal:
        return ""

    notification = config.get("notification") or {}
    max_items = int(notification.get("max_items_per_section", 5) or 5)
    lines = [
        "【配信テスト中】Meta広告 AI運用提案",
        "",
        "※AI提案です。停止・再開・バナー追加は自動実行していません。",
        "",
    ]

    if notification.get("include_ai_summary", True):
        lines.extend(["■ 全体所感", proposal.get("summary") or "-", ""])

    if notification.get("include_pause_candidates", True):
        append_decision_section(lines, "■ 停止検討", proposal.get("pause_candidates") or [], max_items)

    append_decision_section(lines, "■ 継続", proposal.get("keep_candidates") or [], max_items)

    if notification.get("include_resume_candidates", True):
        append_decision_section(lines, "■ 再開テスト候補", proposal.get("resume_candidates") or [], max_items)

    if notification.get("include_creative_suggestions", True):
        append_creative_section(lines, proposal.get("creative_suggestions") or [], max_items)

    append_warning_section(lines, proposal.get("warnings") or [], max_items)

    return "\n".join(lines).rstrip()


def append_decision_section(
    lines: list[str],
    title: str,
    items: list[dict[str, Any]],
    max_items: int,
) -> None:
    lines.append(title)
    if not items:
        lines.extend(["-", ""])
        return

    for item in items[:max_items]:
        priority = item.get("priority") or "-"
        confidence = item.get("confidence") or "-"
        if item.get("guard_note") == "low_confidence_pause_downgraded_to_reference":
            priority = "reference"

        lines.extend(
            [
                f"- {item.get('ad_ref') or '-'}",
                f"  理由: {item.get('reason') or '-'}",
                f"  優先度: {priority}",
                f"  確信度: {confidence}",
            ]
        )
        if item.get("guard_warning"):
            lines.append(f"  注意: {item['guard_warning']}")

    lines.append("")


def append_creative_section(
    lines: list[str],
    items: list[dict[str, Any]],
    max_items: int,
) -> None:
    lines.append("■ 新規バナー案")
    if not items:
        lines.extend(["-", ""])
        return

    for item in items[:max_items]:
        lines.extend(
            [
                f"- {item.get('theme') or '-'}",
                f"  メッセージ: {item.get('message') or '-'}",
                f"  理由: {item.get('reason') or '-'}",
                f"  優先度: {item.get('priority') or '-'}",
            ]
        )

    lines.append("")


def append_warning_section(
    lines: list[str],
    items: list[dict[str, str]],
    max_items: int,
) -> None:
    lines.append("■ 注意")
    if not items:
        lines.append("-")
        return

    for item in items[:max_items]:
        lines.append(f"- {item.get('type') or 'notice'}: {item.get('message') or '-'}")
