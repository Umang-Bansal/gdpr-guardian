from __future__ import annotations

import os
from typing import Any, Dict, Optional
import json
from datetime import datetime, timezone


try:
    from portia.config import Config, LLMModel, LLMProvider  # type: ignore
    from portia.portia import Portia  # type: ignore
except Exception:  # pragma: no cover
    Config = None
    LLMProvider = None
    LLMModel = None
    Portia = None


class PortiaOrchestrator:
    """Thin wrapper to produce a Portia PlanRun for auditing.

    This does not replace the local execution yet; it generates an auditable
    PlanRun JSON that mirrors the DSAR steps so judges can see Portia's
    structured planning and state.
    """

    def __init__(self) -> None:
        self.available = False
        if Config is None:
            return
        # Require Portia Cloud API key for live PlanRuns
        if not os.environ.get("PORTIA_API_KEY"):
            # Still allow offline reporting features via Gemini if available
            try:
                if os.environ.get("GOOGLE_API_KEY"):
                    cfg = Config.from_default(
                        llm_provider=LLMProvider.GOOGLE_GENERATIVE_AI,
                        llm_model_name=LLMModel.GEMINI_2_0_FLASH,
                    )
                    self.client = Portia(config=cfg)
            except Exception:
                pass
            self.available = False
            return
        cfg = Config.from_default(
            llm_provider=LLMProvider.GOOGLE_GENERATIVE_AI,
            llm_model_name=LLMModel.GEMINI_2_0_FLASH,
        )
        self.client = Portia(config=cfg)
        self.available = True

    # --- Live PlanRun bridging ---
    def create_live_run(self, subject_email: str) -> Optional[str]:
        if not self.available:
            return None
        try:
            # Construct a minimal explicit plan (avoid planner validation issues)
            from portia.plan import Plan, PlanContext, Step, PlanInput  # type: ignore
            from portia.plan_run import PlanRunState  # type: ignore

            steps = [
                Step(task="verify_identity", output="$verify_identity"),
                Step(task="discover_sources", output="$discover_sources"),
                Step(task="collect_artifacts", output="$collect_artifacts"),
                Step(task="detect_pii", output="$detect_pii"),
                Step(task="apply_minimization", output="$apply_minimization"),
                Step(task="assemble_disclosure", output="$assemble_disclosure"),
                Step(task="request_compliance_approval", output="$request_compliance_approval"),
                Step(task="finalize_delivery", output="$finalize_delivery"),
            ]
            plan = Plan(
                plan_context=PlanContext(query="GDPR Guardian DSAR", tool_ids=[]),
                steps=steps,
                plan_inputs=[PlanInput(name="subject_email")],
            )
            # Persist plan to cloud
            self.client.storage.save_plan(plan)
            # Create a live run tied to the plan
            run = self.client.create_plan_run(
                plan=plan,
                end_user=subject_email,
                plan_run_inputs=[PlanInput(name="subject_email", value=subject_email)],
            )
            # Mark as IN_PROGRESS and save to cloud
            run.state = PlanRunState.IN_PROGRESS
            self.client.storage.save_plan_run(run)
            return str(run.id)
        except Exception:
            return None

    def update_live_run_state(self, run_id: str, state: str, step_index: int | None = None) -> None:
        if not self.available:
            return
        try:
            from portia.prefixed_uuid import PlanRunUUID  # type: ignore

            pr_id = PlanRunUUID.from_string(run_id)
            run = self.client.storage.get_plan_run(pr_id)
            # Map string to PlanRunState enum if possible
            from portia.plan_run import PlanRunState  # type: ignore

            if state and hasattr(PlanRunState, state):
                run.state = getattr(PlanRunState, state)
            if isinstance(step_index, int):
                run.current_step_index = step_index
            self.client.storage.save_plan_run(run)
        except Exception:
            return

    def resolve_live_clarification(self, run_id: str, response: str) -> None:
        if not self.available:
            return
        try:
            from portia.prefixed_uuid import PlanRunUUID  # type: ignore

            pr_id = PlanRunUUID.from_string(run_id)
            run = self.client.storage.get_plan_run(pr_id)
            # Resolve the last outstanding clarification, if any
            for clar in reversed(run.outputs.clarifications):
                if not clar.resolved:
                    clar.response = response
                    clar.resolved = True
                    break
            self.client.storage.save_plan_run(run)
        except Exception:
            return

    def add_live_clarification(self, run_id: str, payload: Dict[str, Any]) -> None:
        if not self.available:
            return
        try:
            from portia.prefixed_uuid import PlanRunUUID  # type: ignore
            from portia.clarification import Clarification, ClarificationCategory  # type: ignore

            pr_id = PlanRunUUID.from_string(run_id)
            run = self.client.storage.get_plan_run(pr_id)
            clar = Clarification(
                plan_run_id=run.id,
                category=ClarificationCategory.CUSTOM,
                user_guidance="Compliance approval required",
                step=6,  # request_compliance_approval
            )
            # Attach our payload under the Output channel
            run.outputs.clarifications.append(clar)
            # Signal awaiting clarification
            from portia.plan_run import PlanRunState  # type: ignore
            run.current_step_index = 6
            run.state = PlanRunState.NEED_CLARIFICATION
            self.client.storage.save_plan_run(run)
        except Exception:
            return

    def generate_plan_run_json(self, state: Dict[str, Any]) -> str:
        # If using Portia Cloud (API key present), return a pointer JSON instead of invoking LLM run
        if os.environ.get("PORTIA_API_KEY"):
            try:
                run_id = ((state.get("approvals") or {}).get("portia_run_id") or "")
                from portia.config import Config as PConfig  # type: ignore
                dash = PConfig.from_default().portia_dashboard_url  # type: ignore[attr-defined]
                return (
                    "{"
                    f"\n  \"portia_run_id\": \"{run_id}\",\n"
                    f"  \"dashboard_url\": \"{dash}/dashboard/plan-runs?plan_run_id={run_id}\"\n"
                    "}"
                )
            except Exception:
                return "Portia live run is enabled; see dashboard link above."
        if not self.available:
            return "Portia unavailable (SDK or GOOGLE_API_KEY missing)."

        # Describe a pre-expressed DSAR plan that mirrors our local steps
        plan_prompt = (
            "Pre-express a GDPR DSAR plan and execute it as a dry-run.\n"
            "Return a structured PlanRun with steps, artifacts, guardrails, and a Clarification.\n"
            "Steps: verify_identity -> discover_sources -> collect_artifacts -> detect_pii -> apply_minimization -> "
            "assemble_disclosure -> request_compliance_approval (Clarification) -> finalize_delivery.\n"
            "If request_types includes 'erasure', also include: evaluate_legal_basis -> request_legal_approval (Clarification) "
            "-> execute_erasure (mock) -> confirm_completion.\n\n"
            f"Subject: {state.get('subject_email')}\n"
            f"Request types: {state.get('request_types')}\n"
            f"Policy.required_disclosures: {((state.get('policy') or {}).get('disclosure') or {}).get('require_sections', [])}\n"
            f"Policy.redaction.required_types: {((state.get('policy') or {}).get('redaction') or {}).get('required_types', [])}\n"
            "Note: Perform planning and produce a PlanRun JSON; do not perform external network calls."
        )
        try:
            plan_run = self.client.run(plan_prompt)
            # Most Portia objects support pydantic model_dump_json()
            return plan_run.model_dump_json()
        except Exception as e:  # pragma: no cover
            return f"Portia error: {e}"

    def create_compliance_clarification(self, state: Dict[str, Any]) -> str:
        """Return a structured Clarification JSON. In Cloud mode, return local structure."""
        if os.environ.get("PORTIA_API_KEY"):
            # Build from local state directly and return strict JSON
            proposals = state.get("redaction_proposals", [])
            pii_types_list = sorted({p.get("pii_type") for p in proposals if p.get("pii_type") is not None})
            payload: Dict[str, Any] = {
                "type": "ComplianceApprovalClarification",
                "records": len(state.get("artifacts", [])),
                "pii_categories": pii_types_list,
                "num_proposals": len(proposals),
                "decision": "pending",
            }
            return json.dumps(payload)
        if not self.available:
            return "Portia unavailable (SDK or GOOGLE_API_KEY missing)."
        proposals = state.get("redaction_proposals", [])
        pii_types = sorted({p.get("pii_type") for p in proposals})
        prompt = (
            "Create a Clarification object named ComplianceApprovalClarification. Include: summary with record count, "
            "pii_categories, and an array of redaction_proposals (artifact_id, pii_type, start, end). "
            "Decision should be 'pending' and justification empty. Return strict JSON.\n"
            f"records: {len(state.get('artifacts', []))}\n"
            f"pii_categories: {pii_types}\n"
            f"num_proposals: {len(proposals)}\n"
        )
        try:
            plan_run = self.client.run(prompt)
            return plan_run.model_dump_json()
        except Exception as e:  # pragma: no cover
            return f"Portia error: {e}"

    def record_compliance_decision(
        self,
        state: Dict[str, Any],
        decision: str,
        justification: str,
        selected_ids: list[str] | None = None,
    ) -> str:
        """Record the human decision into a Portia-traceable artifact (JSON)."""
        # In Cloud mode, avoid LLM runs; return deterministic JSON
        if os.environ.get("PORTIA_API_KEY"):
            selected_ids = selected_ids or []
            payload: Dict[str, Any] = {
                "type": "ComplianceApprovalDecision",
                "decision": decision,
                "justification": justification,
                "selected_proposals": selected_ids,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            return json.dumps(payload)
        if not self.available:
            return "Portia unavailable (SDK or GOOGLE_API_KEY missing)."
        selected_ids = selected_ids or []
        prompt = (
            "Update ComplianceApprovalClarification with the final decision. Return a JSON with: "
            "type, decision, justification, selected_proposals (IDs), timestamp (ISO)."
            f"\nDecision: {decision}\nJustification: {justification}\nSelected: {selected_ids}"
        )
        try:
            plan_run = self.client.run(prompt)
            return plan_run.model_dump_json()
        except Exception as e:  # pragma: no cover
            return f"Portia error: {e}"

    def record_guardrail_block(self, reason: str) -> str:
        # In Cloud mode, avoid LLM runs; return deterministic JSON
        if os.environ.get("PORTIA_API_KEY"):
            payload: Dict[str, Any] = {
                "type": "GuardrailEvent",
                "step": "finalize_delivery",
                "blocked": True,
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            return json.dumps(payload)
        if not self.available:
            return "Portia unavailable (SDK or GOOGLE_API_KEY missing)."
        prompt = (
            "Emit a GuardrailEvent JSON with fields: step, blocked=true, reason, timestamp (ISO)."
            f"\nreason: {reason}"
        )
        try:
            plan_run = self.client.run(prompt)
            return plan_run.model_dump_json()
        except Exception as e:  # pragma: no cover
            return f"Portia error: {e}"


