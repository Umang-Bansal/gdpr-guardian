from __future__ import annotations

import os
from typing import Any, Dict

try:
    from portia.config import Config, LLMModel, LLMProvider  # type: ignore
    from portia.portia import Portia  # type: ignore
except Exception:  # pragma: no cover
    Config = None
    LLMProvider = None
    LLMModel = None
    Portia = None


class PortiaLLM:
    def __init__(self) -> None:
        self.available = False
        if Config is None:
            return
        # Ensure GOOGLE_API_KEY is set for Gemini
        if not os.environ.get("GOOGLE_API_KEY"):
            return
        # Use Gemini provider + a lightweight model for responsiveness
        cfg = Config.from_default(
            llm_provider=LLMProvider.GOOGLE_GENERATIVE_AI,
            llm_model_name=LLMModel.GEMINI_2_0_FLASH,
        )
        self.client = Portia(config=cfg)
        self.available = True

    def summarize(self, state: Dict[str, Any]) -> str:
        # In Cloud mode or when LLM unavailable, return a deterministic local summary to avoid SDK planning errors.
        if not self.available or os.environ.get("PORTIA_API_KEY"):
            artifacts = len(state.get("artifacts", []))
            cats = sorted({f.get("pii_type") for f in state.get("pii_findings", []) if f.get("pii_type")})
            risks = []
            policy = list((state.get("policy") or {}).get("disclosure", {}).get("require_sections", []))
            if not cats:
                risks.append("No PII detected (verify sources)")
            return (
                f"Artifacts: {artifacts}\n"
                f"PII categories: {', '.join(cats) if cats else 'none'}\n"
                f"Policy sections required: {', '.join(policy)}\n"
                "Recommendation: Approve if redactions selected; otherwise justify overrides."
            )
        prompt = (
            "Summarize a GDPR DSAR disclosure review. Include: number of artifacts, PII categories, any risks, and a concise recommendation.\n"
            f"Artifacts: {len(state.get('artifacts', []))}\n"
            f"PII categories: {sorted({f.get('pii_type') for f in state.get('pii_findings', [])})}\n"
            f"Policy: {list((state.get('policy') or {}).get('disclosure', {}).get('require_sections', []))}\n"
        )
        try:
            plan_run = self.client.run(prompt)
            return plan_run.model_dump_json()
        except Exception as e:  # pragma: no cover
            return f"LLM error: {e}"


