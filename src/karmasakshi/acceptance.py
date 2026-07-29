"""Buyer-facing Milestone A acceptance runner.

This command drives a running Gateway through its public HTTP API, typed
SDK, and authenticated Control Center routes. It never reaches into server
state and never substitutes hard-coded successful outcomes.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import TYPE_CHECKING

from karmasakshi.passports import ActionPassportV2
from karmasakshi.portable import verify_evidence_pack

if TYPE_CHECKING:
    from karmasakshi.sdk import KarmaSakshiApiError

_AGENT_ID = "refund-agent-1"
_ADAPTER_ID = "payment.simulator"
_ADAPTER_VERSION = "1.0.0"


class AcceptanceError(RuntimeError):
    """One buyer-visible acceptance assertion failed."""


class _CsrfParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.token: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "input":
            return
        values = dict(attrs)
        if values.get("name") == "csrf_token" and values.get("value"):
            self.token = values["value"]


@dataclass(frozen=True)
class AcceptanceCheck:
    name: str
    passed: bool
    detail: str


class AcceptanceReport:
    def __init__(self, *, base_url: str, org_id: str) -> None:
        self.base_url = base_url
        self.org_id = org_id
        self.started_at = datetime.now(timezone.utc)
        self.completed_at: datetime | None = None
        self.checks: list[AcceptanceCheck] = []
        self.error: str | None = None

    def pass_check(self, name: str, detail: str) -> None:
        self.checks.append(AcceptanceCheck(name=name, passed=True, detail=detail))
        print(f"PASS  {name}: {detail}")

    def require(self, condition: bool, name: str, detail: str) -> None:
        if not condition:
            raise AcceptanceError(f"{name}: {detail}")
        self.pass_check(name, detail)

    def finish(self, error: str | None = None) -> None:
        self.completed_at = datetime.now(timezone.utc)
        self.error = error

    def as_json(self) -> dict[str, object]:
        completed_at = self.completed_at or datetime.now(timezone.utc)
        return {
            "format": "karmasakshi.milestone_a_acceptance.v1",
            "base_url": self.base_url,
            "org_id": self.org_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "passed": self.error is None,
            "checks": [asdict(check) for check in self.checks],
            "error": self.error,
        }


def _csrf_from(html: str) -> str:
    parser = _CsrfParser()
    parser.feed(html)
    if parser.token is None:
        raise AcceptanceError("Control Center did not render a CSRF token")
    return parser.token


def _expect_api_error(
    action: Callable[[], object],
    *,
    status_code: int,
    label: str,
) -> KarmaSakshiApiError:
    from karmasakshi.sdk import KarmaSakshiApiError

    try:
        action()
    except KarmaSakshiApiError as exc:
        if exc.status_code != status_code:
            raise AcceptanceError(
                f"{label}: expected HTTP {status_code}, received {exc.status_code}"
            ) from exc
        return exc
    raise AcceptanceError(f"{label}: operation unexpectedly succeeded")


def _control_center_approve(
    *,
    base_url: str,
    org_id: str,
    email: str,
    password: str,
    manifest_id: str,
    report: AcceptanceReport,
    inspect_effect: bool,
) -> None:
    import httpx

    with httpx.Client(base_url=base_url, timeout=30.0, follow_redirects=False) as browser:
        login_page = browser.get("/control-center/login")
        if inspect_effect:
            report.require(
                login_page.status_code == 200,
                "Control Center login available",
                "authenticated buyer UI rendered",
            )
        login = browser.post(
            "/control-center/login",
            data={
                "org_id": org_id,
                "email": email,
                "password": password,
                "csrf_token": _csrf_from(login_page.text),
            },
        )
        if inspect_effect:
            report.require(
                login.status_code == 303 and login.headers.get("location") == "/control-center/",
                "Safe UI session established",
                "server issued an HttpOnly session cookie and redirect",
            )
        inbox = browser.get("/control-center/approvals")
        if inspect_effect:
            report.require(
                inbox.status_code == 200 and manifest_id in inbox.text,
                "Human approval requested",
                "sealed refund appeared in the real approval inbox",
            )
        detail = browser.get(f"/control-center/refunds/{manifest_id}")
        detail_has_effect = (
            detail.status_code == 200
            and "Exact before and after" in detail.text
            and "Risk assessment" in detail.text
            and "Policy decision" in detail.text
        )
        if inspect_effect:
            report.require(
                detail_has_effect,
                "Risk and exact effect displayed",
                "Control Center rendered exact effect, structured risk, and policy decision",
            )
        approval = browser.post(
            f"/control-center/refunds/{manifest_id}/approve",
            data={"csrf_token": _csrf_from(detail.text)},
        )
        if approval.status_code != 303:
            raise AcceptanceError(
                f"Control Center approval failed with HTTP {approval.status_code}"
            )


def _sdk_complete_quorum(
    *,
    base_url: str,
    org_id: str,
    manifest_id: str,
    credentials: list[tuple[str, str]],
) -> str:
    from karmasakshi.sdk import GatewayClient

    grant_id: str | None = None
    for email, password in credentials:
        with GatewayClient(base_url, timeout=30.0) as approver:
            approver.login(org_id=org_id, email=email, password=password)
            result = approver.approve_refund(org_id, manifest_id)
            grant_id = result.grant_id or grant_id
    if grant_id is None:
        raise AcceptanceError("required approvals did not produce an execution grant")
    return grant_id


def _write_report(report: AcceptanceReport, path: Path | None) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.as_json(), indent=2) + "\n", encoding="utf-8")
    print(f"REPORT {path}")


def run_acceptance(
    *,
    base_url: str,
    platform_token: str | None,
    org_id: str,
    owner_email: str,
    owner_password: str,
    report_path: Path | None = None,
) -> AcceptanceReport:
    import httpx

    from karmasakshi.sdk import GatewayClient, KarmaSakshiApiError

    report = AcceptanceReport(base_url=base_url, org_id=org_id)
    other_org_id = f"{org_id}-other"
    other_password = secrets.token_urlsafe(18)
    try:
        with GatewayClient(base_url, platform_token=platform_token, timeout=30.0) as client:
            created = client.bootstrap_organization(
                org_id=org_id,
                name="KarmaSakshi Buyer Evaluation",
                owner_email=owner_email,
                owner_display_name="Evaluation Owner",
                owner_password=owner_password,
            )
            report.require(
                created.organization.org_id == org_id,
                "Organization created",
                f"durable organization {org_id!r} created",
            )

            login = client.login(
                org_id=org_id,
                email=owner_email,
                password=owner_password,
            )
            report.require(
                login.user.org_id == org_id,
                "Authenticated team member",
                f"session bound to {login.user.user_id!r}",
            )

            agent = client.register_agent(
                org_id,
                agent_id=_AGENT_ID,
                display_name="Refund Evaluation Agent",
            )
            report.require(
                agent in client.list_agents(org_id),
                "Refund agent registered",
                f"durable org-scoped agent {_AGENT_ID!r}",
            )

            adapter = client.register_adapter(
                org_id,
                adapter_id=_ADAPTER_ID,
                adapter_version=_ADAPTER_VERSION,
            )
            report.require(
                adapter in client.list_adapters(org_id)
                and "payment.transfer" in adapter.effect_types,
                "Payment simulator adapter registered",
                f"trusted {_ADAPTER_ID}@{_ADAPTER_VERSION} bound to payment.transfer",
            )

            policy = client.activate_policy(org_id, bundle_id="evaluation-refund-policy")
            report.require(
                policy.active and bool(policy.bundle_hash),
                "Signed organization policy activated",
                f"active bundle hash {policy.bundle_hash}",
            )

            proposal = client.propose_refund(
                org_id,
                agent_id=_AGENT_ID,
                requested_by="customer-1001",
                beneficiary="customer-ledger-1001",
                amount_minor_units=50_000,
                reference="order-1001",
                idempotency_key=f"{org_id}-main-refund",
            )
            exact = client.get_refund(org_id, proposal.manifest_id)
            report.require(
                exact.effect.amount_minor_units == 50_000
                and exact.effect.source_balance_expected_after_minor_units
                == exact.effect.source_balance_before_minor_units - 50_000,
                "Exact refund effect proposed",
                f"manifest {proposal.manifest_id} binds amount, recipient, and before/after",
            )
            report.require(
                bool(proposal.assessment.signals) and 0 <= proposal.assessment.score <= 100,
                "Risk assessment displayed",
                (
                    f"score={proposal.assessment.score}, "
                    f"recommendation={proposal.assessment.recommendation}"
                ),
            )

            approver_credentials = [(owner_email, owner_password)]
            for index in range(1, proposal.assessment.required_human_approvals):
                approver_email = f"approver-{index}@{org_id}.invalid"
                approver_password = secrets.token_urlsafe(18)
                client.create_user(
                    org_id,
                    user_id=f"{org_id}-approver-{index}",
                    email=approver_email,
                    display_name=f"Evaluation Approver {index}",
                    password=approver_password,
                )
                approver_credentials.append((approver_email, approver_password))
            for index, (email, password) in enumerate(approver_credentials):
                _control_center_approve(
                    base_url=base_url,
                    org_id=org_id,
                    email=email,
                    password=password,
                    manifest_id=proposal.manifest_id,
                    report=report,
                    inspect_effect=index == 0,
                )
            report.pass_check(
                "Human approval recorded",
                f"{len(approver_credentials)} authenticated UI approval actions recorded",
            )
            approved = client.get_refund(org_id, proposal.manifest_id)
            report.require(
                approved.policy_decision.completed_human_approvals
                >= approved.policy_decision.required_human_approvals,
                "Required quorum completed",
                (
                    f"{approved.policy_decision.completed_human_approvals}/"
                    f"{approved.policy_decision.required_human_approvals} "
                    "required human approvals"
                ),
            )
            if approved.grant_id is None:
                raise AcceptanceError("approval did not issue an execution grant")

            modified = client.propose_refund(
                org_id,
                agent_id=_AGENT_ID,
                requested_by="customer-1001",
                beneficiary="attacker-controlled-recipient",
                amount_minor_units=50_001,
                reference="order-1001-modified",
                idempotency_key=f"{org_id}-modified-refund",
            )
            _expect_api_error(
                lambda: client.execute_refund(
                    org_id,
                    modified.manifest_id,
                    grant_id=approved.grant_id or "",
                ),
                status_code=409,
                label="modified amount or recipient",
            )
            report.pass_check(
                "Modified amount or recipient rejected",
                "grant for the original manifest failed against a changed effect",
            )

            execution = client.execute_refund(
                org_id,
                proposal.manifest_id,
                grant_id=approved.grant_id,
            )
            report.require(
                execution.success and bool(execution.provider_reference),
                "Effect committed exactly once",
                f"payment simulator reference {execution.provider_reference}",
            )
            _expect_api_error(
                lambda: client.execute_refund(
                    org_id,
                    proposal.manifest_id,
                    grant_id=approved.grant_id or "",
                ),
                status_code=409,
                label="duplicate retry",
            )
            report.pass_check(
                "Duplicate retry prevented",
                "second execution attempt failed closed with HTTP 409",
            )

            observation = client.verify_refund(org_id, proposal.manifest_id)
            report.require(
                observation.matched_expected,
                "Independent ledger observation",
                observation.detail or "provider record matched the exact manifest",
            )

            passport = client.get_passport(org_id, proposal.manifest_id, version="v2")
            if not isinstance(passport, ActionPassportV2):
                raise AcceptanceError("Gateway did not return Action Passport V2")
            passport.verify_passport_hash()
            report.require(
                passport.verification.seal_verified
                and passport.verification.grant_verified
                and passport.verification.audit_chain_verified,
                "Signed Action Passport generated",
                f"passport hash {passport.passport_hash}",
            )

            scoped_audit = client.get_audit(org_id, query=proposal.manifest_id)
            report.require(
                bool(scoped_audit)
                and all(event.manifest_id == proposal.manifest_id for event in scoped_audit),
                "Audit trail searchable",
                f"{len(scoped_audit)} manifest-scoped events returned",
            )

            ambiguous = client.propose_refund(
                org_id,
                agent_id=_AGENT_ID,
                requested_by="customer-2002",
                beneficiary="customer-ledger-2002",
                amount_minor_units=25_000,
                reference="order-2002",
                idempotency_key=f"{org_id}-ambiguous-refund",
            )
            ambiguous_grant_id = _sdk_complete_quorum(
                base_url=base_url,
                org_id=org_id,
                manifest_id=ambiguous.manifest_id,
                credentials=approver_credentials,
            )
            report.require(
                client.inject_ambiguous_timeout(org_id).armed,
                "Ambiguous timeout armed",
                "real simulator will settle then return a timeout",
            )
            ambiguous_result = client.execute_refund(
                org_id,
                ambiguous.manifest_id,
                grant_id=ambiguous_grant_id,
            )
            if ambiguous_result.success or "ambiguous" not in (ambiguous_result.detail or ""):
                raise AcceptanceError("simulator did not report the commit as ambiguous")
            recovered = client.recover_refund(org_id, ambiguous.manifest_id)
            report.require(
                recovered.matched_expected,
                "Ambiguous timeout recovered honestly",
                recovered.detail or "provider state was re-observed without blind retry",
            )

            compensation = client.compensate_refund(org_id, proposal.manifest_id)
            report.require(
                compensation.compensation_manifest_id != proposal.manifest_id
                and compensation.attempted,
                "Compensation handled as a separate authorized effect",
                (
                    f"separate manifest {compensation.compensation_manifest_id}; "
                    f"succeeded={compensation.succeeded}"
                ),
            )

            evidence_pack = client.get_evidence_pack(org_id, proposal.manifest_id)
            offline = verify_evidence_pack(evidence_pack)
            report.require(
                offline.all_verified,
                "Offline passport and audit verification successful",
                "seal, grant, passport hash, keys, and audit slice verified locally",
            )

            with GatewayClient(
                base_url,
                platform_token=platform_token,
                timeout=30.0,
            ) as other:
                other.bootstrap_organization(
                    org_id=other_org_id,
                    name="KarmaSakshi Isolation Check",
                    owner_email=f"owner@{other_org_id}.invalid",
                    owner_display_name="Isolation Owner",
                    owner_password=other_password,
                )
                other.login(
                    org_id=other_org_id,
                    email=f"owner@{other_org_id}.invalid",
                    password=other_password,
                )
                _expect_api_error(
                    lambda: other.get_refund(org_id, proposal.manifest_id),
                    status_code=403,
                    label="cross-tenant access",
                )
            report.pass_check(
                "Cross-tenant access rejected",
                "second organization's valid session received HTTP 403",
            )

            report.require(
                client.verify_audit(org_id),
                "Organization audit chain verified",
                "full organization journal hash chain is intact",
            )
    except (AcceptanceError, KarmaSakshiApiError, httpx.HTTPError) as exc:
        report.finish(error=str(exc))
        _write_report(report, report_path)
        raise AcceptanceError(str(exc)) from exc

    report.finish()
    _write_report(report, report_path)
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="karmasakshi-acceptance",
        description="Drive the real Milestone A refund journey through Gateway API, SDK, and UI.",
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("KARMASAKSHI_ACCEPTANCE_BASE_URL", "http://127.0.0.1:8000"),
    )
    parser.add_argument(
        "--platform-token",
        default=os.getenv("KARMASAKSHI_API_TOKEN") or None,
    )
    parser.add_argument(
        "--org-id",
        default=None,
        help="Organization id (default: a collision-resistant evaluation id).",
    )
    parser.add_argument(
        "--owner-email",
        default=None,
        help="Evaluation owner email (default: derived from org id).",
    )
    parser.add_argument(
        "--owner-password",
        default=os.getenv("KARMASAKSHI_ACCEPTANCE_OWNER_PASSWORD") or None,
        help="Evaluation owner password (default: generated and printed once).",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional JSON report output path.",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    suffix = uuid.uuid4().hex[:10]
    org_id = args.org_id or f"ks-eval-{suffix}"
    owner_email = args.owner_email or f"owner@{org_id}.invalid"
    generated_password = args.owner_password is None
    owner_password = args.owner_password or secrets.token_urlsafe(18)
    try:
        report = run_acceptance(
            base_url=str(args.base_url).rstrip("/"),
            platform_token=args.platform_token,
            org_id=org_id,
            owner_email=owner_email,
            owner_password=owner_password,
            report_path=args.report,
        )
    except AcceptanceError as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(f"\nMilestone A acceptance passed ({len(report.checks)} checks).")
    print(f"Control Center: {str(args.base_url).rstrip('/')}/control-center/login")
    print(f"Organization:   {org_id}")
    print(f"Owner email:   {owner_email}")
    if generated_password:
        print(f"Owner password: {owner_password} (generated for this evaluation run)")


if __name__ == "__main__":
    main()


__all__ = ["AcceptanceCheck", "AcceptanceError", "AcceptanceReport", "main", "run_acceptance"]
