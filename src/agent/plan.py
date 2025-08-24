from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import os

from src.tools.pdfzip_tool import write_disclosure_zip
from src.tools.filesystem_tool import read_json, list_files
from src.tools.pii_tool import detect as detect_pii_text, mask_value
from src.tools.gmail_tool import GmailTool


@dataclass
class Clarification:
    type: str
    payload: Dict[str, Any]


@dataclass
class PlanStepResult:
    step: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class PlanRunState:
    request_id: str
    subject_email: str
    request_types: List[str]
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    pii_findings: List[Dict[str, Any]] = field(default_factory=list)
    redaction_proposals: List[Dict[str, Any]] = field(default_factory=list)
    approvals: Dict[str, Any] = field(default_factory=dict)
    policy: Dict[str, Any] = field(default_factory=dict)
    identity: Dict[str, Any] = field(default_factory=dict)
    legal: Dict[str, Any] = field(default_factory=dict)
    audit_log: List[Dict[str, Any]] = field(default_factory=list)
    disclosures: Dict[str, Any] = field(default_factory=dict)
    delivery: Dict[str, Any] = field(default_factory=dict)
    erasure: Dict[str, Any] = field(default_factory=dict)


class GDPRPlan:
    def __init__(self, state: PlanRunState):
        self.state = state
        self.clarifications: List[Clarification] = []

    def log(self, step: str, detail: Dict[str, Any]) -> None:
        self.state.audit_log.append({"step": step, **detail})

    # --- Helpers ---
    def _known_subject_identifiers(self) -> Dict[str, set]:
        """Return known identifiers for the data subject to distinguish third-party PII.

        Includes email(s) and phone(s) from state and CRM profile if available.
        """
        emails: set = set()
        phones: set = set()
        # Subject email from request
        if isinstance(self.state.subject_email, str) and self.state.subject_email:
            emails.add(self.state.subject_email.strip().lower())
        # Try to enrich from CRM profile
        try:
            crm = read_json(os.path.join("data", "crm_profile.json"))
            if isinstance(crm, dict):
                e = str(crm.get("email") or "").strip().lower()
                p = str(crm.get("phone") or "").strip()
                if e:
                    emails.add(e)
                if p:
                    phones.add(p)
        except Exception:
            pass
        # Also check any identity hints previously stored
        ident = self.state.identity or {}
        e2 = str(ident.get("email") or "").strip().lower()
        p2 = str(ident.get("phone") or "").strip()
        if e2:
            emails.add(e2)
        if p2:
            phones.add(p2)
        return {"emails": emails, "phones": phones}

    def verify_identity(self) -> PlanStepResult:
        # Heuristic confidence from precomputed value or fallback
        policy_id = self.state.policy.get("identity", {}) if isinstance(self.state.policy, dict) else {}
        threshold = float(policy_id.get("min_confidence_for_auto_approval", policy_id.get("min_confidence", 0.85)))
        pre = (self.state.identity or {}).get("precomputed_confidence")
        if isinstance(pre, (int, float)):
            confidence = float(pre)
        else:
            confidence = 0.10
        status = "verified" if confidence >= threshold else "unverified"
        self.state.identity = {**(self.state.identity or {}), "confidence": confidence, "status": status}
        # If unverified, produce an Identity Clarification
        if status != "verified":
            upload = (self.state.identity or {}).get("upload") or {}
            clar = Clarification(
                type="IdentityVerificationClarification",
                payload={
                    "message": f"Identity verification confidence is low ({confidence:.2f}). Please manually review the uploaded ID and approve or deny.",
                    "threshold": threshold,
                    "upload": {"filename": upload.get("filename"), "size": upload.get("size")},
                },
            )
            self.clarifications.append(clar)
        self.log("verify_identity", self.state.identity)
        ok = status == "verified"
        return PlanStepResult(step="verify_identity", success=ok, data=self.state.identity, error=None if ok else "Identity not verified")

    def discover_sources(self) -> PlanStepResult:
        # Placeholder: declare intended sources
        sources = [
            {"name": "gmail_export", "path": "data/gmail_export.json"},
            {"name": "crm_profile", "path": "data/crm_profile.json"},
            {"name": "files", "path": "data/files"},
        ]
        # If Gmail tool available, note live Gmail as a source
        try:
            gmail = GmailTool()
            if gmail.available:
                sources.append({"name": "gmail_live", "path": "gmail:label_or_query"})
        except Exception:
            pass
        self.log("discover_sources", {"sources": sources})
        return PlanStepResult(step="discover_sources", success=True, data={"sources": sources})

    def collect_artifacts(self) -> PlanStepResult:
        artifacts: List[Dict[str, Any]] = []
        # Try to load demo data; fallback to inline samples
        try:
            gmail = read_json(os.path.join("data", "gmail_export.json"))
            for m in gmail:
                artifacts.append({
                    "source": "gmail_export",
                    "id": f"gmail_{m.get('id')}",
                    "type": "email",
                    "content": f"{m.get('subject','')}: {m.get('body','')}"
                })
        except Exception:
            artifacts.append({"source": "gmail_export", "id": "gmail_1", "type": "email", "content": "Hello Alice, phone +1-555-0101"})

        try:
            crm = read_json(os.path.join("data", "crm_profile.json"))
            artifacts.append({
                "source": "crm_profile",
                "id": crm.get("id", "crm_1"),
                "type": "profile",
                "content": f"{crm.get('name','')}, {crm.get('email','')}, {crm.get('address','')}, {crm.get('phone','')}"
            })
        except Exception:
            artifacts.append({"source": "crm_profile", "id": "crm_1", "type": "profile", "content": "Alice, alice@example.com, 221B Baker Street"})

        # Optional: load text files from data/files
        files_dir = os.path.join("data", "files")
        try:
            for fp in list_files(files_dir):
                try:
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                    artifacts.append({
                        "source": "files",
                        "id": os.path.basename(fp),
                        "type": "file",
                        "content": text,
                    })
                except Exception:
                    continue
        except Exception:
            # Directory might not exist in minimal demo; ignore
            pass

        # Optional: load live Gmail messages if configured
        try:
            gmail = GmailTool()
            if gmail.available:
                msgs = gmail.fetch_messages(label_id=os.environ.get("GMAIL_LABEL_ID"), query=os.environ.get("GMAIL_QUERY"))
                for m in msgs:
                    artifacts.append({
                        "source": "gmail_live",
                        "id": f"gmail_live_{m.get('id')}",
                        "type": "email",
                        "content": f"{m.get('subject','')}: {m.get('snippet','')}"
                    })
        except Exception:
            pass
        self.state.artifacts = artifacts
        self.log("collect_artifacts", {"count": len(artifacts)})
        return PlanStepResult(step="collect_artifacts", success=True, data={"artifacts": artifacts})

    def detect_pii(self) -> PlanStepResult:
        findings: List[Dict[str, Any]] = []
        ids = self._known_subject_identifiers()
        for art in self.state.artifacts:
            text = art.get("content", "")
            for f in detect_pii_text(text):
                value = f.get("value", "")
                pii_type = f["pii_type"]
                is_third = False
                if pii_type == "email":
                    is_third = str(value).strip().lower() not in ids["emails"]
                elif pii_type == "phone":
                    is_third = str(value).strip() not in ids["phones"]
                findings.append({
                    "artifact_id": art["id"],
                    "pii_type": pii_type,
                    "value": value,
                    "start": f.get("start", 0),
                    "end": f.get("end", 0),
                    "confidence": f.get("confidence", 0.0),
                    "third_party": is_third,
                })
        self.state.pii_findings = findings
        tp_count = sum(1 for f in findings if f.get("third_party") is True)
        self.log("detect_pii", {"count": len(findings), "third_party": tp_count})
        return PlanStepResult(step="detect_pii", success=True, data={"findings": findings})

    def apply_minimization(self) -> PlanStepResult:
        proposals: List[Dict[str, Any]] = []
        for idx, f in enumerate(self.state.pii_findings):
            proposals.append({
                "id": f"p{idx}",
                "artifact_id": f["artifact_id"],
                "pii_type": f["pii_type"],
                "value": f.get("value", ""),
                "masked_preview": mask_value(f.get("pii_type", ""), str(f.get("value", ""))),
                "start": f.get("start", 0),
                "end": f.get("end", 0),
                "action": "mask",
                "third_party": bool(f.get("third_party", False)),
            })
        self.state.redaction_proposals = proposals
        tp_count = sum(1 for p in proposals if p.get("third_party") is True)
        self.log("apply_minimization", {"proposals": len(proposals), "third_party": tp_count})
        return PlanStepResult(step="apply_minimization", success=True, data={"proposals": proposals})

    def assemble_disclosure(self) -> PlanStepResult:
        package = {"records": len(self.state.artifacts), "pii": len(self.state.pii_findings)}
        required = self.state.policy.get("disclosure", {}).get("require_sections", [])
        # Derive disclosures from current state where possible
        pii_categories = sorted(list({f["pii_type"] for f in self.state.pii_findings}))
        sources = sorted(list({a["source"] for a in self.state.artifacts}))
        retention_days = int(((self.state.policy.get("sla") or {}).get("access_days") or 30))
        disclosures: Dict[str, Any] = {}
        for key in required:
            if key == "purpose_of_processing":
                disclosures[key] = (
                    "Respond to your GDPR Data Subject Access Request by collating your personal data, "
                    "applying data minimization, and delivering a disclosure package for your review."
                )
            elif key == "categories_of_data":
                disclosures[key] = {
                    "pii_categories": pii_categories,
                    "artifact_types": sorted(list({a["type"] for a in self.state.artifacts})),
                }
            elif key == "recipients":
                disclosures[key] = [
                    "You (data subject)",
                    "Internal compliance team (review and approval)",
                    "Supervisory authority upon lawful request",
                ]
            elif key == "retention_period":
                disclosures[key] = f"DSAR artifacts retained for up to {retention_days} days; originals per system policies."
            elif key == "rights_information":
                disclosures[key] = (
                    "You have rights to access, rectification, erasure (subject to exemptions), restriction, objection, "
                    "and data portability. Contact DPO for additional requests."
                )
            else:
                disclosures[key] = "Provided."
        self.state.disclosures = disclosures
        self.log("assemble_disclosure", {**package, "disclosures": list(self.state.disclosures.keys())})
        return PlanStepResult(step="assemble_disclosure", success=True, data={"package": package, "disclosures": self.state.disclosures})

    def request_compliance_approval(self) -> Clarification:
        tp_count = sum(1 for p in self.state.redaction_proposals if p.get("third_party") is True)
        clar = Clarification(
            type="ComplianceApprovalClarification",
            payload={
                "summary": {
                    "records": len(self.state.artifacts),
                    "pii_categories": sorted(list({f["pii_type"] for f in self.state.pii_findings})),
                    "third_party_findings": tp_count,
                },
                "redaction_proposals": self.state.redaction_proposals,
                "decision": "pending",
                "justification": "",
            },
        )
        self.clarifications.append(clar)
        self.log("request_compliance_approval", {"pending": True})
        return clar

    def finalize_delivery(self) -> PlanStepResult:
        approved = self.state.approvals.get("compliance", {}).get("decision") == "approved"
        if not approved:
            return PlanStepResult(step="finalize_delivery", success=False, error="Not approved")
        # Apply selected redactions and write a disclosure zip to out/{request_id}.zip
        selected_ids = set(self.state.approvals.get("selected_proposals", []) or [p["id"] for p in self.state.redaction_proposals])
        # Build redacted artifacts map
        art_id_to_text = {a["id"]: a.get("content", "") for a in self.state.artifacts}
        # Group proposals by artifact and sort by start descending to avoid index shift
        by_art: Dict[str, List[Dict[str, Any]]] = {}
        for p in self.state.redaction_proposals:
            if p["id"] in selected_ids:
                by_art.setdefault(p["artifact_id"], []).append(p)
        for aid, plist in by_art.items():
            text = art_id_to_text.get(aid, "")
            for p in sorted(plist, key=lambda x: int(x.get("start", 0)), reverse=True):
                value = str(p.get("value", ""))
                masked = mask_value(p.get("pii_type", ""), value)
                s, e = int(p.get("start", 0)), int(p.get("end", 0))
                if 0 <= s <= e <= len(text):
                    text = text[:s] + masked + text[e:]
            art_id_to_text[aid] = text

        out_dir = os.path.join(os.getcwd(), "out")
        os.makedirs(out_dir, exist_ok=True)
        output_path = os.path.join(out_dir, f"{self.state.request_id}.zip")
        artifacts_map = {
            "original_artifacts": self.state.artifacts,
            "redacted_artifacts": [{"id": aid, "content": art_id_to_text[aid]} for aid in art_id_to_text],
            "pii_findings": self.state.pii_findings,
            "applied_proposals": [p for p in self.state.redaction_proposals if p["id"] in selected_ids],
            "disclosures": self.state.disclosures,
        }
        write_disclosure_zip(
            output_path,
            {"subject": self.state.subject_email},
            artifacts_map,
            audit=self.state.audit_log,
            policy=self.state.policy,
            approvals=self.state.approvals,
        )
        self.state.delivery = {"path": output_path}
        result = {"delivered": True, "path": output_path}
        self.log("finalize_delivery", result)
        return PlanStepResult(step="finalize_delivery", success=True, data=result)

    # --- Erasure path ---
    def evaluate_legal_basis(self) -> PlanStepResult:
        # Rule engine: legal hold, financial retention, active service retention
        hold = bool((self.state.legal or {}).get("hold", False))
        # Defaults
        retain_financial = False
        retain_active_service = False
        reasons: List[str] = []
        # Load retention thresholds
        retention_cfg = (self.state.policy or {}).get("retention_policies", {}) if isinstance(self.state.policy, dict) else {}
        fin_days = int(retention_cfg.get("financial_transaction_days", 0) or 0)
        svc_days = int(retention_cfg.get("active_service_days", 0) or 0)
        # Evaluate transactions recency
        try:
            txns = read_json(os.path.join("data", "transaction_history.json"))
            now = datetime.now(timezone.utc)
            for t in txns or []:
                date_str = (t or {}).get("date") or ""
                if not isinstance(date_str, str):
                    continue
                try:
                    # Support ISO8601 with 'Z'
                    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                except Exception:
                    continue
                delta_days = (now - dt).days
                if fin_days > 0 and delta_days < fin_days:
                    retain_financial = True
                # crude signal for active service
                if svc_days > 0 and "subscription" in str((t or {}).get("product", "")).lower() and delta_days < svc_days:
                    retain_active_service = True
        except Exception:
            pass
        if hold:
            reasons.append("legal_hold")
        if retain_financial:
            reasons.append("retain_financial_records")
        if retain_active_service:
            reasons.append("retain_active_service")
        allow_erasure = not reasons
        self.state.legal = {
            **(self.state.legal or {}),
            "hold": hold,
            "retain_financial_records": retain_financial,
            "retain_active_service": retain_active_service,
            "allow_erasure": allow_erasure,
        }
        self.log("evaluate_legal_basis", {"legal_hold": hold, "reasons": reasons, "allow_erasure": allow_erasure})
        return PlanStepResult(step="evaluate_legal_basis", success=True, data={"legal_hold": hold, "reasons": reasons, "allow_erasure": allow_erasure})

    def request_legal_approval(self) -> Clarification:
        clar = Clarification(
            type="LegalApprovalClarification",
            payload={
                "request_type": "erasure",
                "exemptions": ["legal_hold"] if (self.state.legal or {}).get("hold") else [],
                "decision": "pending",
                "notes": "",
            },
        )
        self.clarifications.append(clar)
        self.log("request_legal_approval", {"pending": True})
        return clar

    def execute_erasure(self) -> PlanStepResult:
        # Soft-delete: mark artifacts as deleted if approved. We do not mutate original sources.
        deleted = []
        for a in self.state.artifacts:
            deleted.append({"id": a.get("id"), "source": a.get("source"), "status": "deleted"})
        self.state.erasure = {"deleted": deleted}
        self.log("execute_erasure", {"count": len(deleted)})
        return PlanStepResult(step="execute_erasure", success=True, data={"deleted": deleted})

    def confirm_completion(self) -> PlanStepResult:
        result = {"erasure_confirmed": True, "deleted": len(self.state.erasure.get("deleted", []))}
        self.log("confirm_completion", result)
        return PlanStepResult(step="confirm_completion", success=True, data=result)



