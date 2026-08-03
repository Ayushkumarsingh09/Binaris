from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx


class BinarisClient:
    def __init__(self, base_url: str, token: str, timeout: float = 120.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "BinarisClient":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @classmethod
    def login(cls, base_url: str, email: str, password: str) -> "BinarisClient":
        with httpx.Client(base_url=base_url.rstrip("/"), timeout=60.0) as client:
            res = client.post("/v1/auth/login", json={"email": email, "password": password})
            res.raise_for_status()
            data = res.json()
        return cls(base_url, data["token"])

    def list_projects(self) -> list[dict[str, Any]]:
        res = self._client.get("/v1/projects")
        res.raise_for_status()
        return res.json()

    def upload(self, project_id: str, path: str | Path) -> dict[str, Any]:
        path = Path(path)
        with path.open("rb") as fh:
            res = self._client.post(
                f"/v1/projects/{project_id}/upload",
                files={"file": (path.name, fh, "application/octet-stream")},
            )
        res.raise_for_status()
        return res.json()

    def get_analysis(self, analysis_id: str) -> dict[str, Any]:
        res = self._client.get(f"/v1/analyses/{analysis_id}")
        res.raise_for_status()
        return res.json()

    def chat(self, analysis_id: str, message: str, session_id: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"message": message}
        if session_id:
            payload["session_id"] = session_id
        res = self._client.post(f"/v1/analyses/{analysis_id}/chat", json=payload)
        res.raise_for_status()
        return res.json()

    def search(self, analysis_id: str, query: str, kind: str = "all") -> dict[str, Any]:
        res = self._client.get(
            f"/v1/analyses/{analysis_id}/search",
            params={"q": query, "kind": kind},
        )
        res.raise_for_status()
        return res.json()
