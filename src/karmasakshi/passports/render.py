"""Human-readable Action Passport rendering (Markdown and HTML)."""

from __future__ import annotations

import html

from karmasakshi.passports.model import ActionPassport


def _bool_str(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"


def render_passport_markdown(passport: ActionPassport) -> str:
    p = passport
    lines = [
        f"# Action Passport: {p.manifest_id}",
        "",
        f"Generated: {p.generated_at.isoformat()}",
        f"Lifecycle state: **{p.lifecycle_state}**",
        "",
        "## Proposed / Approved Effect",
        "",
        f"- Effect type: `{p.effect_type}`",
        f"- Actor: `{p.actor.principal_id}` ({p.actor.principal_type.value})",
        f"- Principal: `{p.principal.principal_id}` ({p.principal.principal_type.value})",
        f"- Target resource: `{p.target_resource}`",
        f"- Risk: {p.risk.value} / Reversibility: {p.reversibility.value}",
        f"- Manifest hash: `{p.manifest_hash}`",
        "",
        "## Authorization",
        "",
        f"- Grant ID: `{p.grant_id or 'none'}`",
        f"- Authorized by: `{p.authorized_by.principal_id if p.authorized_by else 'n/a'}`",
        f"- Valid from: {p.authorization_valid_from.isoformat() if p.authorization_valid_from else 'n/a'}",  # noqa: E501
        f"- Valid until: {p.authorization_valid_until.isoformat() if p.authorization_valid_until else 'n/a'}",  # noqa: E501
        f"- Revoked: {_bool_str(p.was_revoked)}",
        "",
        "## Execution",
        "",
        f"- Commit attempted: {_bool_str(p.commit_attempted)}",
        f"- Commit success: {_bool_str(p.commit_success)}",
        f"- Provider reference: `{p.provider_reference or 'n/a'}`",
        f"- Detail: {p.commit_detail or 'n/a'}",
        "",
        "## Verification of Outcome",
        "",
        f"- Observed outcome matched expected: {_bool_str(p.observed_matched_expected)}",
        f"- Observed after-state digest: `{p.observed_after_state_digest or 'n/a'}`",
        f"- Detail: {p.observation_detail or 'n/a'}",
        "",
        "## Compensation",
        "",
        f"- Attempted: {_bool_str(p.compensation_attempted)}",
        f"- Succeeded: {_bool_str(p.compensation_succeeded)}",
        f"- Reason: {p.compensation_reason or 'n/a'}",
        "",
        "## Cryptographic Verification Status",
        "",
        f"- Seal verified: {_bool_str(p.verification.seal_verified)}",
        f"- Grant verified: {_bool_str(p.verification.grant_verified)}",
        f"- Audit chain verified: {_bool_str(p.verification.audit_chain_verified)}",
        f"- Detail: {p.verification.detail or 'n/a'}",
        "",
        "---",
        "This passport is a factual record, not a security certification. See docs/limitations.md.",
    ]
    return "\n".join(lines)


def render_passport_html(passport: ActionPassport) -> str:
    md = render_passport_markdown(passport)
    escaped = html.escape(md)
    return f'<article class="karmasakshi-action-passport">\n<pre>{escaped}</pre>\n</article>\n'


__all__ = ["render_passport_html", "render_passport_markdown"]
