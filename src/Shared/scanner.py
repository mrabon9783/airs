from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

import requests

from .config import settings


@dataclass
class CredentialState:
    days_remaining: Optional[int]
    status: str


def parse_graph_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def classify_expiry(end_datetime: Optional[str], now: Optional[datetime] = None) -> CredentialState:
    if now is None:
        now = datetime.now(timezone.utc)
    dt = parse_graph_datetime(end_datetime)
    if dt is None:
        return CredentialState(days_remaining=None, status="unknown")
    days = int((dt - now).total_seconds() // 86400)
    if days < 0:
        return CredentialState(days_remaining=days, status="expired")
    if days <= 7:
        return CredentialState(days_remaining=days, status="expiring_7")
    if days <= 30:
        return CredentialState(days_remaining=days, status="expiring_30")
    if days <= 90:
        return CredentialState(days_remaining=days, status="expiring_90")
    return CredentialState(days_remaining=days, status="healthy")


def classify_stale(last_sign_in: Optional[str], threshold_days: int = 90, now: Optional[datetime] = None) -> str:
    if now is None:
        now = datetime.now(timezone.utc)
    last = parse_graph_datetime(last_sign_in)
    if not last:
        return "never_used"
    age_days = int((now - last).total_seconds() // 86400)
    return "stale" if age_days >= threshold_days else "active"


class GraphClient:
    def __init__(self) -> None:
        self.base_url = settings.graph_base_url.rstrip("/")
        self.token: Optional[str] = None

    def acquire_token(self) -> str:
        if self.token:
            return self.token
        url = f"https://login.microsoftonline.com/{settings.tenant_id}/oauth2/v2.0/token"
        resp = requests.post(
            url,
            data={
                "client_id": settings.client_id,
                "client_secret": settings.client_secret,
                "scope": settings.graph_scope,
                "grant_type": "client_credentials",
            },
            timeout=30,
        )
        resp.raise_for_status()
        self.token = resp.json()["access_token"]
        return self.token

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.acquire_token()}"
        headers["Content-Type"] = "application/json"

        for attempt in range(5):
            resp = requests.request(method, url, headers=headers, timeout=60, **kwargs)
            if resp.status_code not in (429, 500, 502, 503, 504):
                return resp
            retry_after = int(resp.headers.get("Retry-After", "0"))
            sleep_for = retry_after if retry_after > 0 else 2 ** attempt
            time.sleep(min(sleep_for, 30))
        return resp

    def paginate(self, path: str) -> Iterable[Dict]:
        url = f"{self.base_url}{path}"
        while url:
            resp = self._request("GET", url)
            resp.raise_for_status()
            payload = resp.json()
            for row in payload.get("value", []):
                yield row
            url = payload.get("@odata.nextLink")


class Scanner:
    def __init__(self, graph: Optional[GraphClient] = None) -> None:
        self.graph = graph or GraphClient()

    def run(self) -> Dict:
        warnings: List[str] = []
        findings: List[Dict] = []

        apps = list(self.graph.paginate("/v1.0/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials"))
        sps = list(self.graph.paginate("/v1.0/servicePrincipals?$select=id,appId,displayName,passwordCredentials,keyCredentials,owners"))

        signin_by_sp = {}
        if settings.use_beta_signin_activity:
            try:
                for row in self.graph.paginate("/beta/reports/servicePrincipalSignInActivities"):
                    signin_by_sp[row.get("servicePrincipalId")] = row
            except Exception as exc:  # best effort
                warnings.append(f"Beta sign-in activity unavailable: {exc}")

        for entity_kind, entities in (("app", apps), ("servicePrincipal", sps)):
            for entity in entities:
                credentials = (entity.get("passwordCredentials") or []) + (entity.get("keyCredentials") or [])
                if not credentials:
                    findings.append(self._finding(entity_kind, entity, "medium", "hygiene", "no_credentials", "Entity has no credentials configured", {}))

                if entity_kind == "servicePrincipal" and not entity.get("owners"):
                    findings.append(self._finding(entity_kind, entity, "high", "hygiene", "ownerless", "Service principal has no owners", {}))
                if entity_kind == "app":
                    owners = list(self.graph.paginate(f"/v1.0/applications/{entity['id']}/owners?$select=id"))
                    if not owners:
                        findings.append(self._finding(entity_kind, entity, "high", "hygiene", "ownerless", "Application has no owners", {}))

                for cred in credentials:
                    expiry = classify_expiry(cred.get("endDateTime"))
                    if expiry.status in {"expired", "expiring_7", "expiring_30", "expiring_90"}:
                        severity = "critical" if expiry.status == "expired" else "medium"
                        findings.append(
                            self._finding(
                                entity_kind,
                                entity,
                                severity,
                                "credential_expiry",
                                expiry.status,
                                f"Credential is {expiry.status.replace('_', ' ')}",
                                {
                                    "credentialId": cred.get("keyId"),
                                    "daysRemaining": expiry.days_remaining,
                                    "endDateTime": cred.get("endDateTime"),
                                },
                            )
                        )

                if entity_kind == "servicePrincipal":
                    activity = signin_by_sp.get(entity.get("id"), {})
                    stale_state = classify_stale(activity.get("lastSignInDateTime"), settings.stale_days_threshold)
                    if stale_state in {"stale", "never_used"}:
                        findings.append(
                            self._finding(
                                entity_kind,
                                entity,
                                "low",
                                "stale_activity",
                                stale_state,
                                f"Service principal is {stale_state.replace('_', ' ')}",
                                {
                                    "lastSignInDateTime": activity.get("lastSignInDateTime"),
                                    "thresholdDays": settings.stale_days_threshold,
                                },
                            )
                        )

        counts = {
            "total": len(findings),
            "critical": len([f for f in findings if f["severity"] == "critical"]),
            "high": len([f for f in findings if f["severity"] == "high"]),
            "medium": len([f for f in findings if f["severity"] == "medium"]),
            "low": len([f for f in findings if f["severity"] == "low"]),
        }

        return {"warnings": warnings, "findings": findings, "counts": counts}

    @staticmethod
    def _finding(entity_kind: str, entity: Dict, severity: str, category: str, finding_type: str, description: str, metadata: Dict) -> Dict:
        return {
            "entity_kind": entity_kind,
            "entity_id": entity.get("id"),
            "display_name": entity.get("displayName"),
            "severity": severity,
            "category": category,
            "type": finding_type,
            "description": description,
            "metadata": metadata,
        }
