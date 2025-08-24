from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional
import hashlib


def write_disclosure_zip(
    output_path: str,
    package: Dict[str, Any],
    artifacts: Dict[str, Any],
    audit: Optional[List[Dict[str, Any]]] = None,
    policy: Optional[Dict[str, Any]] = None,
    approvals: Optional[Dict[str, Any]] = None,
) -> str:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("summary.json", json.dumps(package, indent=2))
        zf.writestr("artifacts.json", json.dumps(artifacts, indent=2))
        if audit is not None:
            zf.writestr("audit_log.json", json.dumps(audit, indent=2))
        if policy is not None:
            zf.writestr("policy_snapshot.json", json.dumps(policy, indent=2))
        if approvals is not None:
            zf.writestr("approvals.json", json.dumps(approvals, indent=2))
    # Compute checksum of the written zip and embed it inside as checksum.txt
    sha256_hex: str
    with out.open("rb") as rf:
        hasher = hashlib.sha256()
        for chunk in iter(lambda: rf.read(8192), b""):
            hasher.update(chunk)
        sha256_hex = hasher.hexdigest()
    with zipfile.ZipFile(out, mode="a", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("checksum.txt", sha256_hex)
    return str(out)



