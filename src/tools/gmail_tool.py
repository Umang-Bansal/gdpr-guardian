from __future__ import annotations

from typing import Any, Dict, List, Optional
import os


# Try to import Google API libraries lazily; tool will gracefully degrade if unavailable
try:  # pragma: no cover
    from googleapiclient.discovery import build  # type: ignore
    from google.oauth2.credentials import Credentials  # type: ignore
    from google.auth.transport.requests import Request  # type: ignore
except Exception:  # pragma: no cover
    build = None  # type: ignore
    Credentials = None  # type: ignore
    Request = None  # type: ignore


SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


class GmailTool:
    """Fetch messages from Gmail if token credentials are present; otherwise fallback.

    Configuration:
    - GMAIL_TOKEN_PATH: path to OAuth token JSON (created after initial consent)
    - GMAIL_CREDENTIALS_PATH: optional path to OAuth client secrets (not used for non-interactive)
    - GMAIL_LABEL_ID: optional label ID to filter messages
    - GMAIL_QUERY: optional Gmail search query
    """

    def __init__(self) -> None:
        self.available: bool = False
        self.reason_unavailable: str = ""
        if build is None or Credentials is None:  # google libraries not installed
            self.reason_unavailable = "google-api-python-client not installed"
            return
        # Prefer explicit env var; fall back to ./token.json in project root
        token_path_env = os.environ.get("GMAIL_TOKEN_PATH")
        default_token_path = os.path.join(os.getcwd(), "token.json")
        token_path = token_path_env if (token_path_env and os.path.exists(token_path_env)) else (
            default_token_path if os.path.exists(default_token_path) else None
        )
        if not token_path:
            self.reason_unavailable = "No Gmail OAuth token found (set GMAIL_TOKEN_PATH or place token.json in project root)"
            return
        try:
            creds = Credentials.from_authorized_user_file(token_path, SCOPES)
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            self.service = build("gmail", "v1", credentials=creds, cache_discovery=False)
            self.available = True
        except Exception as e:  # pragma: no cover
            self.reason_unavailable = f"Auth/init error: {e}"

    def fetch_messages(
        self,
        label_id: Optional[str] = None,
        query: Optional[str] = None,
        max_results: int = 10,
    ) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        try:
            user_id = "me"
            params: Dict[str, Any] = {"maxResults": max_results}
            if label_id:
                params["labelIds"] = [label_id]
            if query:
                params["q"] = query
            listing = self.service.users().messages().list(userId=user_id, **params).execute() or {}
            messages = listing.get("messages", [])
            results: List[Dict[str, Any]] = []
            for m in messages:
                msg = self.service.users().messages().get(userId=user_id, id=m.get("id"), format="metadata", metadataHeaders=["Subject"]).execute() or {}
                headers = {h.get("name"): h.get("value") for h in (msg.get("payload", {}).get("headers", []) or [])}
                results.append({
                    "id": msg.get("id"),
                    "snippet": msg.get("snippet", ""),
                    "subject": headers.get("Subject", "(no subject)"),
                })
            return results
        except Exception:  # pragma: no cover
            return []


