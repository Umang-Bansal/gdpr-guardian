from __future__ import annotations

import json
import os
import sys
import uuid
from typing import Any, Dict

import uvicorn
import yaml
from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.agent.plan import GDPRPlan, PlanRunState
from src.agent import hooks
from src.agent.llm import PortiaLLM
from src.agent.portia_orchestrator import PortiaOrchestrator
import time


load_dotenv()
app = FastAPI()

templates = Environment(
    loader=FileSystemLoader(searchpath=str(os.path.join(os.path.dirname(__file__), "templates"))),
    autoescape=select_autoescape(["html", "xml"]),
)


def load_policy() -> Dict[str, Any]:
    policy_path = os.path.join(os.getcwd(), "policy", "policy.yaml")
    with open(policy_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


RUNS: Dict[str, PlanRunState] = {}
def _cleanup_out_ttl(days: int = 30) -> None:
    try:
        out_dir = os.path.join(os.getcwd(), "out")
        if not os.path.isdir(out_dir):
            return
        now = time.time()
        ttl = days * 24 * 60 * 60
        for fname in os.listdir(out_dir):
            fp = os.path.join(out_dir, fname)
            try:
                if os.path.isfile(fp):
                    age = now - os.path.getmtime(fp)
                    if age > ttl:
                        os.remove(fp)
            except Exception:
                continue
    except Exception:
        pass



@app.get("/", response_class=HTMLResponse)
def index() -> str:
    tmpl = templates.get_template("index.html")
    # TTL cleanup best-effort on index hits
    _cleanup_out_ttl(days=int((load_policy().get("sla") or {}).get("access_days", 30)))
    return tmpl.render(runs=list(RUNS.values()))


@app.get("/health")
def health():
    try:
        import portia  # type: ignore

        sdk = True
    except Exception:
        sdk = False
    # Gmail availability check
    gmail_available = False
    gmail_reason = None
    try:
        from src.tools.gmail_tool import GmailTool  # type: ignore

        g = GmailTool()
        gmail_available = bool(getattr(g, "available", False))
        if not gmail_available:
            gmail_reason = getattr(g, "reason_unavailable", None)
    except Exception as e:  # pragma: no cover
        gmail_available = False
        gmail_reason = str(e)
    return {
        "ok": True,
        "python": sys.version,
        "portia_sdk_installed": sdk,
        "google_api_key_present": bool(os.environ.get("GOOGLE_API_KEY")),
        "gmail_available": gmail_available,
        "gmail_reason": gmail_reason,
    }


@app.post("/dsar/new")
async def new_dsar(
    subject_email: str = Form(...),
    request_type: str = Form("access"),
    id_image: UploadFile | None = File(None),
):
    rid = str(uuid.uuid4())
    state = PlanRunState(
        request_id=rid,
        subject_email=subject_email,
        request_types=[request_type],
        policy=load_policy(),
    )
    plan = GDPRPlan(state)
    # Seed legal hold from CRM profile if present
    try:
        crm = {
            "legal_hold": False,
        }
        try:
            crm = json.load(open(os.path.join("data", "crm_profile.json"), "r", encoding="utf-8"))
        except Exception:
            pass
        if isinstance(crm, dict) and "legal_hold" in crm:
            state.legal = {**(state.legal or {}), "hold": bool(crm.get("legal_hold"))}
    except Exception:
        pass

    # Capture ID upload metadata and precompute an identity confidence
    try:
        pre_conf = 0.10
        upload_meta = None
        if id_image is not None:
            data = await id_image.read()
            size = len(data) if data else 0
            filename = id_image.filename or ""
            upload_meta = {"filename": filename, "size": size}
            fname = filename.lower()
            if size > 0:
                if "alice" in fname:
                    pre_conf = 0.95
                elif any(k in fname for k in ["id", "license", "passport"]):
                    pre_conf = 0.60
                else:
                    pre_conf = 0.60
            else:
                pre_conf = 0.10
        state.identity = {**(state.identity or {}), "upload": upload_meta, "precomputed_confidence": pre_conf}
    except Exception:
        # If anything goes wrong, default to low confidence
        state.identity = {**(state.identity or {}), "precomputed_confidence": 0.10}
    # Create live Portia run
    try:
        orchestrator = PortiaOrchestrator()
        live_id = orchestrator.create_live_run(subject_email)
        if live_id:
            state.approvals["portia_run_id"] = live_id
    except Exception:
        pass

    # Execution flow with simple guards
    step = plan.verify_identity()
    if not step.success:
        RUNS[rid] = state
        return RedirectResponse(url=f"/run/{rid}", status_code=303)

    guard = hooks.pre_step_guard(state.__dict__, "discover_sources")
    if not guard["allow"]:
        RUNS[rid] = state
        return RedirectResponse(url=f"/run/{rid}", status_code=303)

    plan.discover_sources()
    plan.collect_artifacts()
    plan.detect_pii()
    plan.apply_minimization()
    plan.assemble_disclosure()
    # Generate LLM summary (Gemini via Portia)
    llm = PortiaLLM()
    llm_summary = llm.summarize(state.__dict__)
    clar = plan.request_compliance_approval()
    # Reflect clarification in live Portia run
    try:
        orchestrator = PortiaOrchestrator()
        if state.approvals.get("portia_run_id"):
            orchestrator.add_live_clarification(state.approvals["portia_run_id"], clar.payload)
            orchestrator.update_live_run_state(state.approvals["portia_run_id"], "NEED_CLARIFICATION")
    except Exception:
        pass
    # attach summary for UI
    state.approvals["summary_llm"] = llm_summary
    # Generate a Portia PlanRun JSON for auditing
    try:
        orchestrator = PortiaOrchestrator()
        state.approvals["portia_plan_run_json"] = orchestrator.generate_plan_run_json(state.__dict__)
        state.approvals["portia_compliance_clarification_json"] = orchestrator.create_compliance_clarification(state.__dict__)
    except Exception as e:
        state.approvals["portia_plan_run_json"] = f"Portia orchestration error: {e}"
        state.approvals["portia_compliance_clarification_json"] = f"Portia orchestration error: {e}"

    RUNS[rid] = state
    return RedirectResponse(url=f"/run/{rid}", status_code=303)


@app.get("/run/{rid}", response_class=HTMLResponse)
def view_run(rid: str) -> str:
    if rid not in RUNS:
        return HTMLResponse(content="Not found", status_code=404)
    state = RUNS[rid]
    tmpl = templates.get_template("run.html")
    audit_pretty = json.dumps(state.audit_log, indent=2)
    return tmpl.render(state=state, audit_pretty=audit_pretty)


@app.post("/legal/{rid}/toggle")
async def toggle_legal_hold(rid: str, hold: str = Form(...)):
    if rid not in RUNS:
        return JSONResponse({"error": "not found"}, status_code=404)
    state = RUNS[rid]
    value = str(hold).strip().lower() in {"1", "true", "yes", "on"}
    state.legal = {**(state.legal or {}), "hold": value}
    state.audit_log.append({"step": "legal_hold_set", "hold": value})
    return RedirectResponse(url=f"/run/{rid}", status_code=303)


@app.post("/approve/{rid}")
async def approve(rid: str, request: Request, decision: str = Form(...), justification: str = Form(""), approval_type: str = Form("compliance")):
    if rid not in RUNS:
        return JSONResponse({"error": "not found"}, status_code=404)
    state = RUNS[rid]
    form = await request.form()
    selected = form.getlist("proposal") if hasattr(form, "getlist") else []
    if approval_type == "legal":
        state.approvals["legal"] = {"decision": decision, "justification": justification}
    else:
        state.approvals["compliance"] = {"decision": decision, "justification": justification}
        state.approvals["selected_proposals"] = selected

    # Finalization guard
    # If this is compliance approval and approved, finalize disclosure
    if approval_type == "compliance":
        guard = hooks.pre_finalize_guard(state.__dict__)
        if not guard["allow"]:
            state.audit_log.append({"step": "finalize_delivery", "blocked": True, "reason": guard["reason"]})
            # Record guardrail block in Portia trace if available
            try:
                orchestrator = PortiaOrchestrator()
                state.approvals["portia_guardrail_event_json"] = orchestrator.record_guardrail_block(guard["reason"])  # type: ignore
                if state.approvals.get("portia_run_id"):
                    orchestrator.update_live_run_state(state.approvals["portia_run_id"], "NEED_CLARIFICATION")
            except Exception:
                pass
            state.approvals["compliance_status"] = {"status": "blocked", "reason": guard["reason"]}
        else:
            plan = GDPRPlan(state)
            plan.finalize_delivery()
            # Reflect decision back into Portia trace
            try:
                orchestrator = PortiaOrchestrator()
                selected_ids = state.approvals.get("selected_proposals") or []
                state.approvals["portia_compliance_decision_json"] = orchestrator.record_compliance_decision(
                    state.__dict__, decision, justification, selected_ids
                )
                if state.approvals.get("portia_run_id"):
                    orchestrator.resolve_live_clarification(state.approvals["portia_run_id"], decision)
                    orchestrator.update_live_run_state(state.approvals["portia_run_id"], "COMPLETE")
            except Exception:
                pass
            state.approvals["compliance_status"] = {"status": "delivered"}

    # If DSAR includes erasure, run legal flow when legal approval present and approved
    if "erasure" in (state.request_types or []) and approval_type == "legal":
        plan = GDPRPlan(state)
        plan.evaluate_legal_basis()
        # Pre-erasure guard
        eguard = hooks.pre_erasure_guard(state.__dict__)
        if not eguard["allow"]:
            state.audit_log.append({"step": "execute_erasure", "blocked": True, "reason": eguard["reason"]})
            state.approvals["legal_status"] = {"status": "blocked", "reason": eguard["reason"]}
            try:
                orchestrator = PortiaOrchestrator()
                if state.approvals.get("portia_run_id"):
                    orchestrator.update_live_run_state(state.approvals["portia_run_id"], "NEED_CLARIFICATION")
            except Exception:
                pass
        else:
            plan.execute_erasure()
            plan.confirm_completion()
            state.approvals["legal_status"] = {"status": "erasure_executed", "deleted": len((state.erasure or {}).get("deleted", []))}
            try:
                orchestrator = PortiaOrchestrator()
                if state.approvals.get("portia_run_id"):
                    orchestrator.update_live_run_state(state.approvals["portia_run_id"], "COMPLETE")
            except Exception:
                pass

    return RedirectResponse(url=f"/run/{rid}", status_code=303)


@app.get("/download/{rid}")
def download(rid: str):
    if rid not in RUNS:
        return JSONResponse({"error": "not found"}, status_code=404)
    state = RUNS[rid]
    path = (state.delivery or {}).get("path")
    if not path or not os.path.exists(path):
        return JSONResponse({"error": "no package"}, status_code=404)
    filename = os.path.basename(path)
    return FileResponse(path, filename=filename, media_type="application/zip")


def main() -> None:
    port = int(os.environ.get("PORT", 3000))
    uvicorn.run("src.server.app:app", host="0.0.0.0", port=port, reload=True)


if __name__ == "__main__":
    main()


