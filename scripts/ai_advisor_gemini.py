from __future__ import annotations

import json
import os
import socket
import time
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
VALID_RISKS = {"high", "medium", "low"}
TRANSIENT_GEMINI_STATUSES = {429, 500, 502, 503, 504}


class GeminiApiError(RuntimeError):
    def __init__(self, status: int | None, message: str, *, transient: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.transient = transient


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
        "evidence_fields": {
            "type": "array",
            "maxItems": 6,
            "items": {"type": "string"},
        },
        "missing_fields": {
            "type": "array",
            "maxItems": 6,
            "items": {"type": "string"},
        },
    },
    "required": [
        "ad_ref",
        "priority",
        "reason",
        "recommended_action",
        "confidence",
        "evidence_fields",
        "missing_fields",
    ],
}

ADVISOR_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "pause_candidates": {"type": "array", "maxItems": 3, "items": AD_DECISION_SCHEMA},
        "keep_candidates": {"type": "array", "maxItems": 3, "items": AD_DECISION_SCHEMA},
        "resume_candidates": {"type": "array", "maxItems": 3, "items": AD_DECISION_SCHEMA},
        "creative_suggestions": {
            "type": "array",
            "maxItems": 3,
            "items": {
                "type": "object",
                "properties": {
                    "theme": {"type": "string"},
                    "message": {"type": "string"},
                    "reason": {"type": "string"},
                    "priority": {"type": "string", "enum": ["high", "medium", "low"]},
                    "evidence_fields": {
                        "type": "array",
                        "maxItems": 6,
                        "items": {"type": "string"},
                    },
                    "missing_fields": {
                        "type": "array",
                        "maxItems": 6,
                        "items": {"type": "string"},
                    },
                },
                "required": ["theme", "message", "reason", "priority", "evidence_fields", "missing_fields"],
            },
        },
        "warnings": {
            "type": "array",
            "maxItems": 3,
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "message": {"type": "string"},
                },
                "required": ["type", "message"],
            },
        },
        "rule_change_suggestions": {
            "type": "array",
            "maxItems": 3,
            "items": {
                "type": "object",
                "properties": {
                    "rule_name": {"type": "string"},
                    "suggested_change": {"type": "string"},
                    "reason": {"type": "string"},
                    "risk": {"type": "string", "enum": ["high", "medium", "low"]},
                    "approval_required": {"type": "boolean"},
                    "evidence_fields": {
                        "type": "array",
                        "maxItems": 6,
                        "items": {"type": "string"},
                    },
                    "missing_fields": {
                        "type": "array",
                        "maxItems": 6,
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "rule_name",
                    "suggested_change",
                    "reason",
                    "risk",
                    "approval_required",
                    "evidence_fields",
                    "missing_fields",
                ],
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
        "rule_change_suggestions",
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


def load_ai_memory(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    if not path.exists():
        return None, [f"ai_memory_not_found:{path}"]

    try:
        with path.open("r", encoding="utf-8") as fh:
            memory = yaml.safe_load(fh) or {}
    except Exception as exc:
        return None, [f"ai_memory_load_failed:{exc}"]

    if not isinstance(memory, dict):
        return None, ["ai_memory_root_not_mapping"]

    return memory, []


def advisor_enabled(config: dict[str, Any]) -> bool:
    return bool(config.get("enabled", False))


def resolve_model(config: dict[str, Any]) -> str:
    model_env = str(config.get("model_env") or "GEMINI_MODEL")
    return os.getenv(model_env) or str(config.get("model") or DEFAULT_MODEL)


def prompt_for(ai_input: dict[str, Any], *, compact_retry: bool = False) -> str:
    if compact_retry:
        return "\n".join(
            [
                "Return only one valid JSON object. No markdown.",
                "You are an ad-operations advisor. Propose only; never execute changes.",
                "Allowed actions: pause_review, keep, watch, resume_test_review, creative_test_review, measurement_check, lp_check.",
                "Forbidden actions: pause_now, resume_now, increase_budget_now, create_ad_now, change_campaign_now.",
                "Use these exact keys: summary, pause_candidates, keep_candidates, resume_candidates, creative_suggestions, warnings, rule_change_suggestions.",
                "All arrays must have at most 2 items. Keep Japanese text short.",
                "For each ad or creative item include evidence_fields and missing_fields arrays.",
                "Use operation_philosophy as the senior policy, but do not override safety guards or forbidden actions.",
                "rule_change_suggestions are suggestions only and must require approval.",
                "Use only data_contract.allowed_evidence. Never infer from missing_evidence or ad names.",
                "Data:",
                json.dumps(ai_input, ensure_ascii=False, separators=(",", ":")),
            ]
        )

    return "\n".join(
        [
            "Return only valid JSON that matches the schema. No markdown.",
            "You are a Meta ads operations advisor.",
            "Make proposals only. Never execute or recommend immediate execution.",
            "",
            "Allowed recommended_action:",
            ", ".join(sorted(ALLOWED_ACTIONS)),
            "",
            "Forbidden recommended_action:",
            ", ".join(sorted(FORBIDDEN_ACTIONS)),
            "",
            "Rules:",
            "- Write Japanese values.",
            "- Treat operation_philosophy as the operator's senior policy memory.",
            "- Do not let operation_philosophy override safety guards or forbidden actions.",
            "- Use only fields listed in data_contract.allowed_evidence as evidence.",
            "- Never infer demographics, targeting, offer, LP content, or creative content from ad_name/campaign_name.",
            "- If needed evidence is listed in data_contract.missing_evidence, say it is missing.",
            "- Each ad candidate must include evidence_fields and missing_fields arrays.",
            "- Each creative_suggestions item must include evidence_fields and missing_fields arrays.",
            "- Each rule_change_suggestions item must include evidence_fields and missing_fields arrays.",
            "- If rules.target_cpa_source is unset, do not compare against a target CPA or suggest a target CPA amount.",
            "- If ad.adset_target_cpa exists, it is the Meta ad set result cost goal and may be used as target CPA evidence.",
            "- Judge spend thresholds by ad.adset_target_cpa multipliers in rules, not by fixed yen amounts.",
            "- summary <= 80 Japanese chars.",
            "- each array <= 3 items.",
            "- reason/message <= 60 Japanese chars.",
            "- Do not put low-spend ads in pause_candidates.",
            "- If an ad has conversions, be cautious about pause review.",
            "- Put measurement or pending-judgment issues in warnings.",
            "- creative_suggestions are creative review points only. Do not write concrete banner copy unless creative_text or creative_image is provided.",
            "- rule_change_suggestions are proposal-only. Never imply automatic application.",
            "- Set approval_required=true for every rule_change_suggestion.",
            "",
            "Data:",
            json.dumps(ai_input, ensure_ascii=False, separators=(",", ":")),
        ]
    )


def build_request_payload(
    ai_input: dict[str, Any],
    config: dict[str, Any] | None = None,
    *,
    use_schema: bool = True,
    compact_retry: bool = False,
) -> dict[str, Any]:
    config = config or {}
    generation_config: dict[str, Any] = {
        "temperature": 0.1,
        "maxOutputTokens": int(config.get("max_output_tokens", 2048) or 2048),
        "responseMimeType": "application/json",
        "thinkingConfig": {
            "thinkingBudget": int(config.get("thinking_budget", 0) or 0),
        },
    }

    if use_schema and bool(config.get("use_response_schema", True)):
        generation_config["responseJsonSchema"] = ADVISOR_RESPONSE_SCHEMA

    return {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt_for(ai_input, compact_retry=compact_retry)}],
            }
        ],
        "generationConfig": generation_config,
    }


def call_gemini(
    ai_input: dict[str, Any],
    config: dict[str, Any],
    api_key: str,
    *,
    use_schema: bool = True,
    compact_retry: bool = False,
) -> dict[str, Any]:
    model = resolve_model(config)
    url = GEMINI_ENDPOINT_TEMPLATE.format(model=model)
    payload = json.dumps(
        build_request_payload(
            ai_input,
            config,
            use_schema=use_schema,
            compact_retry=compact_retry,
        ),
        ensure_ascii=False,
    ).encode("utf-8")
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
        timeout = int(config.get("timeout_seconds", 20) or 20)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            api_payload = json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise GeminiApiError(
            exc.code,
            f"Gemini API request failed: status={exc.code}, body={body[:800]}",
            transient=exc.code in TRANSIENT_GEMINI_STATUSES,
        ) from exc
    except urllib.error.URLError as exc:
        raise GeminiApiError(None, f"Gemini API request failed: {exc}", transient=True) from exc

    text = extract_text(api_payload)
    try:
        response_json = parse_json_object_text(text)
    except json.JSONDecodeError as exc:
        first_candidate = (api_payload.get("candidates") or [{}])[0]
        finish_reason = first_candidate.get("finishReason") or "unknown"
        raise ValueError(
            "Gemini response was not valid JSON: "
            f"finish_reason={finish_reason}, text={text[:800]}"
        ) from exc

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


def parse_json_object_text(text: str) -> dict[str, Any]:
    cleaned = text.strip()

    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`").strip()
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()

    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start < 0 or end <= start:
            raise
        payload = json.loads(cleaned[start : end + 1])

    if not isinstance(payload, dict):
        raise ValueError("Gemini response JSON root must be an object.")

    return payload


def clean_field_list(value: Any, allowed_values: set[str] | None = None, max_items: int = 6) -> list[str]:
    if not isinstance(value, list):
        return []

    fields: list[str] = []
    for item in value:
        field = str(item or "").strip()
        if not field:
            continue
        if allowed_values is not None and field not in allowed_values:
            continue
        if field not in fields:
            fields.append(field)
        if len(fields) >= max_items:
            break

    return fields


def evidence_contract(ai_input: dict[str, Any]) -> tuple[set[str], set[str]]:
    contract = ai_input.get("data_contract") or {}
    allowed = {
        str(item)
        for item in (contract.get("allowed_evidence") or [])
        if str(item).strip()
    }
    missing = {
        str(item)
        for item in (contract.get("missing_evidence") or [])
        if str(item).strip()
    }
    return allowed, missing


def positive_float(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None

    if number <= 0:
        return None
    return number


def pause_review_min_spend_for_ad(ad: dict[str, Any], thresholds: dict[str, Any]) -> float:
    target_cpa = positive_float(ad.get("adset_target_cpa"))
    multiplier = positive_float(thresholds.get("pause_review_target_cpa_multiplier"))

    if target_cpa is not None and multiplier is not None:
        return target_cpa * multiplier

    legacy_fixed_amount = positive_float(thresholds.get("min_spend_for_pause_review"))
    return legacy_fixed_amount or 0.0


def proposal_has_section_items(proposal: dict[str, Any]) -> bool:
    for key in (
        "pause_candidates",
        "keep_candidates",
        "resume_candidates",
        "creative_suggestions",
        "warnings",
        "rule_change_suggestions",
    ):
        value = proposal.get(key)
        if isinstance(value, list) and value:
            return True
    return False


def status_is_active(ad: dict[str, Any]) -> bool:
    return (
        str(ad.get("configured_status") or "").upper() == "ACTIVE"
        and str(ad.get("effective_status") or "").upper() == "ACTIVE"
    )


def status_is_not_active(ad: dict[str, Any]) -> bool:
    return not status_is_active(ad)


def ad_display_name(ad: dict[str, Any]) -> str:
    return str(ad.get("ad_name") or ad.get("ad_ref") or "広告").strip()


def target_cpa_for_ad(ad: dict[str, Any], rules: dict[str, Any]) -> float | None:
    return positive_float(ad.get("adset_target_cpa")) or positive_float(rules.get("target_cpa"))


def evidence_subset(fields: list[str], allowed_evidence: set[str]) -> list[str]:
    return [field for field in fields if field in allowed_evidence][:6]


def missing_subset(fields: list[str], missing_evidence: set[str]) -> list[str]:
    return [field for field in fields if field in missing_evidence][:6]


def enrich_empty_proposal(
    clean: dict[str, Any],
    ai_input: dict[str, Any],
    config: dict[str, Any],
    allowed_evidence: set[str],
    missing_evidence: set[str],
    validation_notes: list[str],
) -> None:
    if proposal_has_section_items(clean):
        return

    ads = [ad for ad in (ai_input.get("ads") or []) if isinstance(ad, dict)]
    if not ads:
        clean["warnings"].append(
            {
                "type": "data_empty",
                "message": "AI判定用の広告データがありません。対象キャンペーンや取得条件を確認してください。",
            }
        )
        validation_notes.append("fallback: no_ads")
        return

    thresholds = config.get("thresholds") or {}
    rules = ai_input.get("rules") or {}
    active_ads = [ad for ad in ads if status_is_active(ad)]
    inactive_ads = [ad for ad in ads if status_is_not_active(ad)]
    min_keep_conversions = int(float(thresholds.get("min_conversions_for_keep", 1) or 1))
    min_scale_conversions = int(float(thresholds.get("min_conversions_for_scale_review", 2) or 2))

    if not clean.get("summary"):
        clean["summary"] = "AI候補が空のため、取得済み数値から判断保留点を補足します。"
    else:
        clean["summary"] = f"{clean['summary']} 数値ベースの補足を追加します。"

    for ad in sorted(active_ads, key=lambda item: -float(item.get("spend") or 0))[:2]:
        spend = float(ad.get("spend") or 0)
        conversions = float(ad.get("conversions") or 0)
        target_cpa = target_cpa_for_ad(ad, rules)
        pause_watch_multiplier = positive_float(rules.get("pause_watch_target_cpa_multiplier")) or 1.5
        pause_review_multiplier = positive_float(rules.get("pause_review_target_cpa_multiplier")) or 2.0
        evidence = evidence_subset(
            ["configured_status", "effective_status", "spend", "conversions", "cpa", "adset_target_cpa", "ctr", "cvr"],
            allowed_evidence,
        )
        missing = missing_subset(["learning_status", "change_history"], missing_evidence)

        if conversions >= min_keep_conversions:
            reason = "CV実績があるため、CPAと前段指標を見ながら観察継続。"
            confidence = "medium"
        elif target_cpa is not None and spend < target_cpa * pause_watch_multiplier:
            reason = "消化額が目標CPAの警戒倍率未満のため、停止判断はまだ早い。"
            confidence = "high"
        elif target_cpa is not None and spend < target_cpa * pause_review_multiplier:
            reason = "CVはないが停止検討倍率未満のため、前段指標を確認して観察。"
            confidence = "medium"
        else:
            reason = "停止候補には未分類。CTR、CVR、計測状態を確認して判断保留。"
            confidence = "low"

        clean["keep_candidates"].append(
            {
                "ad_ref": ad.get("ad_ref"),
                "ad_name": ad.get("ad_name") or "",
                "campaign_name": ad.get("campaign_name") or "",
                "campaign_ref": ad.get("campaign_ref") or "",
                "priority": "medium",
                "reason": reason,
                "recommended_action": "watch",
                "confidence": confidence,
                "evidence_fields": evidence,
                "missing_fields": missing,
            }
        )

    stopped_with_cv = [
        ad
        for ad in inactive_ads
        if float(ad.get("conversions") or 0) >= min_keep_conversions
    ]
    for ad in sorted(stopped_with_cv, key=lambda item: -float(item.get("conversions") or 0))[:2]:
        conversions = float(ad.get("conversions") or 0)
        cpa = positive_float(ad.get("cpa"))
        target_cpa = target_cpa_for_ad(ad, rules)
        priority = "medium"
        confidence = "medium"
        if conversions >= min_scale_conversions:
            priority = "high"
        if target_cpa is not None and cpa is not None and cpa > target_cpa:
            priority = "medium"
            confidence = "low"

        clean["resume_candidates"].append(
            {
                "ad_ref": ad.get("ad_ref"),
                "ad_name": ad.get("ad_name") or "",
                "campaign_name": ad.get("campaign_name") or "",
                "campaign_ref": ad.get("campaign_ref") or "",
                "priority": priority,
                "reason": "停止中だがCV実績あり。上位階層の停止理由を確認して再開テスト検討。",
                "recommended_action": "resume_test_review",
                "confidence": confidence,
                "evidence_fields": evidence_subset(
                    ["configured_status", "effective_status", "conversions", "cpa", "spend", "adset_target_cpa"],
                    allowed_evidence,
                ),
                "missing_fields": missing_subset(["learning_status", "change_history"], missing_evidence),
            }
        )

    if inactive_ads:
        clean["warnings"].append(
            {
                "type": "delivery_state",
                "message": f"取得{len(ads)}件中{len(inactive_ads)}件が停止中です。現役評価と再開検討を分けて見てください。",
            }
        )

    if "learning_status" in missing_evidence or "change_history" in missing_evidence:
        clean["warnings"].append(
            {
                "type": "pending_judgment",
                "message": "学習状態と変更履歴が未取得のため、停止・再開は人間確認前提です。",
            }
        )

    if "creative_text" in missing_evidence or "creative_image" in missing_evidence:
        clean["creative_suggestions"].append(
            {
                "theme": "勝ち広告の実物確認",
                "message": "画像・テキストを取得して、CTR低下やCVR低下の原因を確認する。",
                "reason": "現在はクリエイティブ実物が未取得で、訴求内容を断定できません。",
                "priority": "medium",
                "recommended_action": "creative_test_review",
                "evidence_fields": evidence_subset(["ctr", "cvr", "spend", "conversions"], allowed_evidence),
                "missing_fields": missing_subset(["creative_text", "creative_image"], missing_evidence),
            }
        )

    if rules.get("target_cpa_source") != "unset" and rules.get("pause_review_target_cpa_multiplier"):
        clean["rule_change_suggestions"].append(
            {
                "rule_name": "ai_pause_review_basis",
                "suggested_change": "AI提案は固定金額ではなくMeta目標CPA倍率で判断し続ける。",
                "reason": "広告セットごとの目標CPA差を反映でき、二重管理を減らせます。",
                "risk": "low",
                "approval_required": True,
                "evidence_fields": evidence_subset(["adset_target_cpa", "spend", "conversions"], allowed_evidence),
                "missing_fields": [],
            }
        )

    validation_notes.append("fallback: enriched_empty_ai_proposal")


def validate_proposal(
    proposal: dict[str, Any],
    ai_input: dict[str, Any],
    config: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    ads = ai_input.get("ads") or []
    ad_by_ref = {str(ad.get("ad_ref")): ad for ad in ads if ad.get("ad_ref")}
    thresholds = config.get("thresholds") or {}
    rules = ai_input.get("rules") or {}
    allowed_evidence, missing_evidence = evidence_contract(ai_input)
    validation_notes: list[str] = []

    clean: dict[str, Any] = {
        "summary": str(proposal.get("summary") or ""),
        "pause_candidates": [],
        "keep_candidates": [],
        "resume_candidates": [],
        "creative_suggestions": [],
        "warnings": [],
        "rule_change_suggestions": [],
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

            normalized["ad_name"] = str(ad.get("ad_name") or "").strip()
            normalized["campaign_name"] = str(ad.get("campaign_name") or "").strip()
            normalized["campaign_ref"] = str(ad.get("campaign_ref") or "").strip()
            normalized["evidence_fields"] = clean_field_list(
                normalized.get("evidence_fields"),
                allowed_evidence,
            )
            normalized["missing_fields"] = clean_field_list(
                normalized.get("missing_fields"),
                missing_evidence,
            )

            if not normalized["evidence_fields"]:
                normalized["evidence_fields"] = ["spend", "conversions"]
                validation_notes.append(f"{section}: empty_evidence_fields:{ad_ref}")

            if rules.get("target_cpa_source") == "unset" and "target_cpa" not in normalized["missing_fields"]:
                normalized["missing_fields"].append("target_cpa")

            if section == "pause_candidates":
                spend = float(ad.get("spend") or 0)
                conversions = float(ad.get("conversions") or 0)
                min_pause_spend = pause_review_min_spend_for_ad(ad, thresholds)

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
        proposal.get("creative_suggestions") or [],
        allowed_evidence,
        missing_evidence,
    )
    clean["warnings"].extend(clean_warnings(proposal.get("warnings") or []))
    clean["rule_change_suggestions"] = clean_rule_change_suggestions(
        proposal.get("rule_change_suggestions") or [],
        validation_notes,
        allowed_evidence,
        missing_evidence,
        rules.get("target_cpa_source") != "unset",
    )
    enrich_empty_proposal(
        clean,
        ai_input,
        config,
        allowed_evidence,
        missing_evidence,
        validation_notes,
    )

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
        "evidence_fields": item.get("evidence_fields") or [],
        "missing_fields": item.get("missing_fields") or [],
    }


def clean_creative_suggestions(
    items: Any,
    allowed_evidence: set[str],
    missing_evidence: set[str],
) -> list[dict[str, Any]]:
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

        missing_fields = clean_field_list(item.get("missing_fields"), missing_evidence)
        for field in ("creative_text", "creative_image"):
            if field in missing_evidence and field not in missing_fields:
                missing_fields.append(field)

        clean.append(
            {
                "theme": theme,
                "message": message,
                "reason": reason,
                "priority": priority,
                "recommended_action": "creative_test_review",
                "evidence_fields": clean_field_list(item.get("evidence_fields"), allowed_evidence),
                "missing_fields": missing_fields[:6],
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


def clean_rule_change_suggestions(
    items: Any,
    validation_notes: list[str],
    allowed_evidence: set[str],
    missing_evidence: set[str],
    target_cpa_configured: bool,
) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        validation_notes.append("rule_change_suggestions: not_list")
        return []

    clean: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            validation_notes.append("rule_change_suggestions: invalid_item")
            continue

        rule_name = str(item.get("rule_name") or "").strip()
        suggested_change = str(item.get("suggested_change") or "").strip()
        reason = str(item.get("reason") or "").strip()
        risk = str(item.get("risk") or "medium").strip()

        if not rule_name or not suggested_change or not reason:
            validation_notes.append("rule_change_suggestions: missing_required_field")
            continue

        target_cpa_text = f"{rule_name} {suggested_change} {reason}".lower()
        if not target_cpa_configured and (
            rule_name.lower() == "target_cpa"
            or "目標cpaを" in target_cpa_text
            or "target_cpaを" in target_cpa_text
            or "5000" in target_cpa_text
            or "5,000" in target_cpa_text
        ):
            validation_notes.append("rule_change_suggestions: rejected_target_cpa_without_config")
            continue

        if risk not in VALID_RISKS:
            risk = "medium"

        clean.append(
            {
                "rule_name": rule_name,
                "suggested_change": suggested_change,
                "reason": reason,
                "risk": risk,
                "approval_required": True,
                "evidence_fields": clean_field_list(item.get("evidence_fields"), allowed_evidence),
                "missing_fields": clean_field_list(item.get("missing_fields"), missing_evidence),
            }
        )

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
        "api_calls": 0,
        "retried": False,
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
        result["sent_to_model"] = True
        result["api_calls"] = 1
        use_response_schema = bool(config.get("use_response_schema", True))
        gemini_result = call_gemini(ai_input, config, api_key, use_schema=use_response_schema)
        result["model"] = gemini_result["model"]
        proposal, validation_notes = validate_proposal(gemini_result["proposal"], ai_input, config)
        result["proposal"] = proposal
        result["validation_notes"] = validation_notes
        return result
    except (TimeoutError, socket.timeout) as exc:
        result["error"] = str(exc)
        result["error_type"] = "api_timeout"
        return result
    except ValueError as exc:
        max_calls = int(config.get("max_gemini_calls_per_run", 1) or 1)
        if bool(config.get("retry_on_invalid_json", False)) and max_calls >= 2:
            try:
                result["retried"] = True
                result["api_calls"] = 2
                gemini_result = call_gemini(
                    ai_input,
                    config,
                    api_key,
                    use_schema=False,
                    compact_retry=True,
                )
                result["model"] = gemini_result["model"]
                proposal, validation_notes = validate_proposal(
                    gemini_result["proposal"],
                    ai_input,
                    config,
                )
                result["proposal"] = proposal
                result["validation_notes"] = [
                    "retried_without_schema_after_invalid_json",
                    *validation_notes,
                ]
                return result
            except Exception as retry_exc:
                result["error"] = f"first={exc}; retry={retry_exc}"
                result["error_type"] = "invalid_response"
                return result

        result["error"] = str(exc)
        result["error_type"] = "invalid_response"
        return result
    except GeminiApiError as exc:
        max_calls = int(config.get("max_gemini_calls_per_run", 1) or 1)
        should_retry = (
            exc.transient
            and bool(config.get("retry_on_transient_api_error", False))
            and max_calls >= 2
        )

        if should_retry:
            try:
                result["retried"] = True
                result["api_calls"] = 2
                delay = float(config.get("retry_delay_seconds", 5) or 5)
                if delay > 0:
                    time.sleep(delay)

                gemini_result = call_gemini(
                    ai_input,
                    config,
                    api_key,
                    use_schema=bool(config.get("use_response_schema", True)),
                )
                result["model"] = gemini_result["model"]
                proposal, validation_notes = validate_proposal(
                    gemini_result["proposal"],
                    ai_input,
                    config,
                )
                result["proposal"] = proposal
                result["validation_notes"] = [
                    f"retried_after_transient_api_error:{exc.status}",
                    *validation_notes,
                ]
                return result
            except Exception as retry_exc:
                result["error"] = f"first={exc}; retry={retry_exc}"
                result["error_type"] = "api_error"
                return result

        result["error"] = str(exc)
        result["error_type"] = "api_error"
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
    input_summary = result.get("input_summary") or {}

    if result.get("skipped"):
        return "\n".join(
            [
                "【配信テスト中】Meta広告 AI運用提案",
                "",
                "※AI提案はスキップされました。停止・再開・バナー追加は自動実行していません。",
                "",
                "■ 状態",
                f"理由: {result.get('skip_reason') or '-'}",
                f"model: {result.get('model') or '-'}",
                f"AI入力広告数: {input_summary.get('ads', '-')}",
                f"Gemini呼び出し回数: {result.get('api_calls', 0)}",
            ]
        )

    if result.get("error"):
        return "\n".join(
            [
                "【配信テスト中】Meta広告 AI運用提案",
                "",
                "※AI提案生成失敗。停止・再開・バナー追加は自動実行していません。",
                "",
                "■ 状態",
                f"種別: {result.get('error_type') or 'unknown'}",
                f"model: {result.get('model') or '-'}",
                f"AI入力広告数: {input_summary.get('ads', '-')}",
                f"Gemini呼び出し回数: {result.get('api_calls', 0)}",
            ]
        )

    proposal = result.get("proposal")
    if not proposal:
        return "\n".join(
            [
                "【配信テスト中】Meta広告 AI運用提案",
                "",
                "※AI提案は生成されませんでした。停止・再開・バナー追加は自動実行していません。",
                "",
                "■ 状態",
                f"model: {result.get('model') or '-'}",
                f"AI入力広告数: {input_summary.get('ads', '-')}",
                f"Gemini呼び出し回数: {result.get('api_calls', 0)}",
            ]
        )

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
    append_rule_change_section(lines, proposal.get("rule_change_suggestions") or [], max_items)

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

        ad_label = item.get("ad_name") or item.get("ad_ref") or "-"
        campaign_label = item.get("campaign_name") or item.get("campaign_ref") or "-"

        lines.extend(
            [
                f"- {ad_label}",
                f"  キャンペーン: {campaign_label}",
                f"  参照ID: {item.get('ad_ref') or '-'}",
                f"  理由: {item.get('reason') or '-'}",
                f"  優先度: {priority}",
                f"  確信度: {confidence}",
                f"  根拠データ: {format_field_list(item.get('evidence_fields'))}",
                f"  未取得データ: {format_field_list(item.get('missing_fields'))}",
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
    lines.append("■ クリエイティブ確認観点")
    if not items:
        lines.extend(["-", ""])
        return

    for item in items[:max_items]:
        lines.extend(
            [
                f"- {item.get('theme') or '-'}",
                f"  確認観点: {item.get('message') or '-'}",
                f"  理由: {item.get('reason') or '-'}",
                f"  優先度: {item.get('priority') or '-'}",
                f"  根拠データ: {format_field_list(item.get('evidence_fields'))}",
                f"  未取得データ: {format_field_list(item.get('missing_fields'))}",
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


def append_rule_change_section(
    lines: list[str],
    items: list[dict[str, Any]],
    max_items: int,
) -> None:
    lines.append("")
    lines.append("■ ルール改善案")
    if not items:
        lines.append("-")
        return

    for item in items[:max_items]:
        lines.extend(
            [
                f"- {item.get('rule_name') or '-'}",
                f"  変更案: {item.get('suggested_change') or '-'}",
                f"  理由: {item.get('reason') or '-'}",
                f"  リスク: {item.get('risk') or '-'}",
                f"  根拠データ: {format_field_list(item.get('evidence_fields'))}",
                f"  未取得データ: {format_field_list(item.get('missing_fields'))}",
                "  承認: 人間確認が必要",
            ]
        )


def format_field_list(value: Any) -> str:
    if not isinstance(value, list) or not value:
        return "-"

    return ", ".join(str(item) for item in value if str(item).strip()) or "-"
