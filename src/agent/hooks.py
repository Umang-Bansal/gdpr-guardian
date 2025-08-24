from __future__ import annotations

from typing import Any, Dict


def pre_step_guard(state: Dict[str, Any], step: str) -> Dict[str, Any]:
    # Identity must be verified before collection
    if step in {"discover_sources", "collect_artifacts"}:
        status = (state.get("identity") or {}).get("status")
        if status != "verified":
            return {"allow": False, "reason": "Identity not verified"}
    return {"allow": True}


def pre_finalize_guard(state: Dict[str, Any]) -> Dict[str, Any]:
    # Hard stop if legal hold
    if (state.get("legal") or {}).get("hold") is True:
        return {"allow": False, "reason": "Legal hold active"}
    # Ensure required disclosures present (simplified)
    required = (state.get("policy") or {}).get("disclosure", {}).get("require_sections", [])
    missing = [s for s in required if s not in (state.get("disclosures") or {})]
    if missing:
        return {"allow": False, "reason": f"Missing disclosures: {', '.join(missing)}"}
    # Enforce required redaction types unless justified override
    redaction_cfg = (state.get("policy") or {}).get("redaction", {})
    required_types = set(redaction_cfg.get("required_types", []))
    if required_types:
        findings = state.get("pii_findings") or []
        required_findings = [f for f in findings if (f or {}).get("pii_type") in required_types]
        if required_findings:
            proposals = state.get("redaction_proposals") or []
            selected_ids = set((state.get("approvals") or {}).get("selected_proposals") or [])
            selected_by_key = {
                ((p or {}).get("artifact_id"), int((p or {}).get("start", 0)), int((p or {}).get("end", 0))): p
                for p in proposals
                if (p or {}).get("id") in selected_ids and (p or {}).get("pii_type") in required_types
            }
            missing_required: int = 0
            for f in required_findings:
                key = ((f or {}).get("artifact_id"), int((f or {}).get("start", 0)), int((f or {}).get("end", 0)))
                if key not in selected_by_key:
                    missing_required += 1
            if missing_required > 0:
                allow_override = bool(redaction_cfg.get("allow_override_with_justification"))
                justification = ((state.get("approvals") or {}).get("compliance") or {}).get("justification", "")
                if allow_override and justification:
                    return {"allow": True}
                return {"allow": False, "reason": f"Missing required redactions: {missing_required}"}
    return {"allow": True}


def pre_erasure_guard(state: Dict[str, Any]) -> Dict[str, Any]:
    # Block erasure if legal hold or missing approvals
    if (state.get("legal") or {}).get("hold") is True:
        return {"allow": False, "reason": "Legal hold active"}
    approvals = state.get("approvals") or {}
    legal_dec = (approvals.get("legal") or {}).get("decision")
    if legal_dec != "approved":
        return {"allow": False, "reason": "Legal approval missing"}
    # Retention-based blocks
    legal = state.get("legal") or {}
    if legal.get("allow_erasure") is False:
        if legal.get("retain_financial_records"):
            return {"allow": False, "reason": "Data retained for financial regulations"}
        if legal.get("retain_active_service"):
            return {"allow": False, "reason": "Data retained for active service contract"}
        return {"allow": False, "reason": "Legal basis not met"}
    return {"allow": True}



