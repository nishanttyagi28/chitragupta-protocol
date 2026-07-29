"""Asynchronous typed Python SDK for the KarmaSakshi Gateway HTTP API
(Milestone A). Identical surface to `karmasakshi.sdk.client.GatewayClient`,
built on `httpx.AsyncClient` instead of `httpx.Client`. See docs/gateway.md.
"""

from __future__ import annotations

from types import TracebackType

import httpx

from karmasakshi.audit.events import AuditEvent
from karmasakshi.gateway.models import GatewayUserRole
from karmasakshi.gateway.schemas import (
    GatewayUserOut,
    LoginOut,
    OrganizationBootstrapOut,
    OrganizationOut,
)
from karmasakshi.passports import ActionPassport, ActionPassportV2
from karmasakshi.portable import EvidencePack, EvidencePackVerificationResult
from karmasakshi.sdk._shared import (
    DEFAULT_BLOCK_THRESHOLD,
    DEFAULT_CURRENCY,
    DEFAULT_GRANT_TTL_SECONDS,
    DEFAULT_POLICY_EFFECTIVE_SECONDS,
    DEFAULT_REVIEW_THRESHOLD,
    DEFAULT_SOURCE_ACCOUNT,
    auth_header,
    raise_for_status,
)
from karmasakshi.sdk.errors import KarmaSakshiConnectionError, KarmaSakshiSdkError
from karmasakshi.sdk.models import (
    ApprovalResult,
    AuditVerificationResult,
    CompensationResult,
    ExecutionResult,
    PolicyActivationResult,
    RefundProposalResult,
    VerificationResult,
)


class AsyncGatewayClient:
    """The async twin of `karmasakshi.sdk.client.GatewayClient` -- same
    methods, same typed responses, `async def` + `await` throughout::

        async with AsyncGatewayClient("http://localhost:8000") as client:
            await client.login(org_id="acme", email="alice@acme.com", password="...")
            ...
    """

    def __init__(
        self,
        base_url: str,
        *,
        platform_token: str | None = None,
        session_token: str | None = None,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """``transport`` is exposed for testing (e.g. `httpx.ASGITransport`
        against an in-process app) -- production callers should leave it
        unset and let httpx open a real connection pool."""
        self._platform_token = platform_token
        self.session_token = session_token
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"), timeout=timeout, transport=transport
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AsyncGatewayClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # --- internals ----------------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: object | None = None,
        params: dict[str, str | int | float | bool | None] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        try:
            response = await self._client.request(
                method, path, json=json, params=params, headers=headers
            )
        except httpx.HTTPError as exc:
            raise KarmaSakshiConnectionError(str(exc)) from exc
        raise_for_status(response)
        return response

    def _session_headers(self) -> dict[str, str]:
        if self.session_token is None:
            raise KarmaSakshiSdkError(
                "no active Gateway session -- call login() first, or pass "
                "session_token= to the constructor"
            )
        return auth_header(self.session_token)

    def _platform_headers(self) -> dict[str, str]:
        return auth_header(self._platform_token) if self._platform_token is not None else {}

    # --- organizations / auth -------------------------------------------------

    async def bootstrap_organization(
        self,
        *,
        org_id: str,
        name: str,
        owner_email: str,
        owner_display_name: str,
        owner_password: str,
    ) -> OrganizationBootstrapOut:
        response = await self._request(
            "POST",
            "/gateway/organizations",
            json={
                "org_id": org_id,
                "name": name,
                "owner_email": owner_email,
                "owner_display_name": owner_display_name,
                "owner_password": owner_password,
            },
            headers=self._platform_headers(),
        )
        return OrganizationBootstrapOut.model_validate(response.json())

    async def login(self, *, org_id: str, email: str, password: str) -> LoginOut:
        response = await self._request(
            "POST",
            "/gateway/auth/login",
            json={"org_id": org_id, "email": email, "password": password},
        )
        result = LoginOut.model_validate(response.json())
        self.session_token = result.session_token
        return result

    async def me(self) -> GatewayUserOut:
        response = await self._request("GET", "/gateway/auth/me", headers=self._session_headers())
        return GatewayUserOut.model_validate(response.json())

    async def get_organization(self, org_id: str) -> OrganizationOut:
        response = await self._request(
            "GET", f"/gateway/organizations/{org_id}", headers=self._session_headers()
        )
        return OrganizationOut.model_validate(response.json())

    async def list_users(self, org_id: str) -> list[GatewayUserOut]:
        response = await self._request(
            "GET", f"/gateway/organizations/{org_id}/users", headers=self._session_headers()
        )
        return [GatewayUserOut.model_validate(u) for u in response.json()["users"]]

    async def create_user(
        self,
        org_id: str,
        *,
        user_id: str,
        email: str,
        display_name: str,
        password: str,
        role: GatewayUserRole = GatewayUserRole.MEMBER,
    ) -> GatewayUserOut:
        response = await self._request(
            "POST",
            f"/gateway/organizations/{org_id}/users",
            json={
                "user_id": user_id,
                "email": email,
                "display_name": display_name,
                "password": password,
                "role": role.value,
            },
            headers=self._session_headers(),
        )
        return GatewayUserOut.model_validate(response.json())

    # --- policy -----------------------------------------------------------

    async def activate_policy(
        self,
        org_id: str,
        *,
        bundle_id: str,
        block_threshold: int = DEFAULT_BLOCK_THRESHOLD,
        review_threshold: int = DEFAULT_REVIEW_THRESHOLD,
        effective_seconds: int = DEFAULT_POLICY_EFFECTIVE_SECONDS,
    ) -> PolicyActivationResult:
        response = await self._request(
            "POST",
            f"/gateway/organizations/{org_id}/policy",
            json={
                "bundle_id": bundle_id,
                "block_threshold": block_threshold,
                "review_threshold": review_threshold,
                "effective_seconds": effective_seconds,
            },
            headers=self._session_headers(),
        )
        return PolicyActivationResult.model_validate(response.json())

    # --- refund journey -----------------------------------------------------

    async def propose_refund(
        self,
        org_id: str,
        *,
        agent_id: str,
        requested_by: str,
        beneficiary: str,
        amount_minor_units: int,
        reference: str,
        idempotency_key: str,
        source_account: str = DEFAULT_SOURCE_ACCOUNT,
        currency: str = DEFAULT_CURRENCY,
    ) -> RefundProposalResult:
        response = await self._request(
            "POST",
            f"/gateway/organizations/{org_id}/refunds/propose",
            json={
                "agent_id": agent_id,
                "requested_by": requested_by,
                "source_account": source_account,
                "beneficiary": beneficiary,
                "amount_minor_units": amount_minor_units,
                "currency": currency,
                "reference": reference,
                "idempotency_key": idempotency_key,
            },
            headers=self._session_headers(),
        )
        return RefundProposalResult.model_validate(response.json())

    async def approve_refund(
        self,
        org_id: str,
        manifest_id: str,
        *,
        ttl_seconds: int = DEFAULT_GRANT_TTL_SECONDS,
        policy_bundle_id: str | None = None,
    ) -> ApprovalResult:
        response = await self._request(
            "POST",
            f"/gateway/organizations/{org_id}/refunds/{manifest_id}/approve",
            json={"ttl_seconds": ttl_seconds, "policy_bundle_id": policy_bundle_id},
            headers=self._session_headers(),
        )
        return ApprovalResult.model_validate(response.json())

    async def execute_refund(
        self, org_id: str, manifest_id: str, *, grant_id: str
    ) -> ExecutionResult:
        response = await self._request(
            "POST",
            f"/gateway/organizations/{org_id}/refunds/{manifest_id}/execute",
            json={"grant_id": grant_id},
            headers=self._session_headers(),
        )
        return ExecutionResult.model_validate(response.json())

    async def verify_refund(self, org_id: str, manifest_id: str) -> VerificationResult:
        response = await self._request(
            "POST",
            f"/gateway/organizations/{org_id}/refunds/{manifest_id}/verify",
            headers=self._session_headers(),
        )
        return VerificationResult.model_validate(response.json())

    async def recover_refund(self, org_id: str, manifest_id: str) -> VerificationResult:
        response = await self._request(
            "POST",
            f"/gateway/organizations/{org_id}/refunds/{manifest_id}/recover",
            headers=self._session_headers(),
        )
        return VerificationResult.model_validate(response.json())

    async def compensate_refund(
        self, org_id: str, manifest_id: str, *, ttl_seconds: int = DEFAULT_GRANT_TTL_SECONDS
    ) -> CompensationResult:
        response = await self._request(
            "POST",
            f"/gateway/organizations/{org_id}/refunds/{manifest_id}/compensate",
            json={"ttl_seconds": ttl_seconds},
            headers=self._session_headers(),
        )
        return CompensationResult.model_validate(response.json())

    # --- passport / evidence / audit -----------------------------------------

    async def get_passport(
        self, org_id: str, manifest_id: str, *, version: str = "v1"
    ) -> ActionPassport | ActionPassportV2:
        response = await self._request(
            "GET",
            f"/gateway/organizations/{org_id}/refunds/{manifest_id}/passport",
            params={"version": version},
            headers=self._session_headers(),
        )
        if version.strip().lower() in {"v2", "2", "2.0"}:
            return ActionPassportV2.model_validate(response.json())
        return ActionPassport.model_validate(response.json())

    async def get_passport_text(
        self, org_id: str, manifest_id: str, *, version: str = "v1", fmt: str = "markdown"
    ) -> str:
        response = await self._request(
            "GET",
            f"/gateway/organizations/{org_id}/refunds/{manifest_id}/passport",
            params={"version": version, "fmt": fmt},
            headers=self._session_headers(),
        )
        return response.text

    async def get_evidence_pack(self, org_id: str, manifest_id: str) -> EvidencePack:
        response = await self._request(
            "GET",
            f"/gateway/organizations/{org_id}/refunds/{manifest_id}/evidence-pack",
            headers=self._session_headers(),
        )
        return EvidencePack.model_validate(response.json())

    async def verify_evidence_pack(self, pack: EvidencePack) -> EvidencePackVerificationResult:
        response = await self._request(
            "POST", "/evidence-pack/verify", json=pack.model_dump(mode="json")
        )
        return EvidencePackVerificationResult.model_validate(response.json())

    async def get_audit(self, org_id: str, *, manifest_id: str | None = None) -> list[AuditEvent]:
        params: dict[str, str | int | float | bool | None] | None = (
            {"manifest_id": manifest_id} if manifest_id is not None else None
        )
        response = await self._request(
            "GET",
            f"/gateway/organizations/{org_id}/audit",
            params=params,
            headers=self._session_headers(),
        )
        return [AuditEvent.model_validate(e) for e in response.json()["events"]]

    async def verify_audit(self, org_id: str) -> bool:
        response = await self._request(
            "GET", f"/gateway/organizations/{org_id}/audit/verify", headers=self._session_headers()
        )
        return AuditVerificationResult.model_validate(response.json()).verified


__all__ = ["AsyncGatewayClient"]
