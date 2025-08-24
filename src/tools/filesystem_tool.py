from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def read_json(path: str) -> Any:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def list_files(dir_path: str, patterns: List[str] | None = None) -> List[str]:
    base = Path(dir_path)
    files: List[str] = []
    for p in base.rglob("*"):
        if p.is_file():
            files.append(str(p))
    return files



