"""Human-readable Action Passport rendering (Markdown and HTML)."""

from __future__ import annotations

import html
from typing import TYPE_CHECKING

from karmasakshi.passports.model import ActionPassport

if TYPE_CHECKING:
    from karmasakshi.passports.v2 import ActionPassportV2


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
        "## Effect Intelligence Assessment",
        "",
        *(
            [
                f"- Assessment ID: `{p.assessment_id}`",
                f"- Score: {p.assessment_score}/100 ({p.assessment_risk_level})",
                f"- Recommendation: **{p.assessment_recommendation}** (advisory only -- "
                "not yet enforced by authorize()/commit(), see docs/effect-intelligence.md)",
                f"- Policy: `{p.assessment_policy_id}` (`{p.assessment_policy_hash}`)",
                f"- Required human approvals: {p.assessment_required_human_approvals}",
                f"- Explanation: {p.assessment_explanation}",
            ]
            if p.assessment_id is not None
            else ["- No assessment was recorded for this manifest."]
        ),
        "",
        "## Authorization",
        "",
        f"- Grant ID: `{p.grant_id or 'none'}`",
        f"- Authorized by: `{p.authorized_by.principal_id if p.authorized_by else 'n/a'}`",
        f"- Valid from: {p.authorization_valid_from.isoformat() if p.authorization_valid_from else 'n/a'}",  # noqa: E501
        f"- Valid until: {p.authorization_valid_until.isoformat() if p.authorization_valid_until else 'n/a'}",  # noqa: E501
        f"- Policy bundle: `{p.authorization_policy_bundle_hash or 'none (unpinned)'}`",
        f"- Approval set (quorum): `{p.authorization_approval_set_hash or 'none (single-issuer authorize())'}`",  # noqa: E501
        f"- Decision envelope: `{p.authorization_decision_envelope_hash or 'none'}`",
        f"- Atomic plan (causal graph): `{p.authorization_causal_graph_hash or 'none'}`",
        f"- Revoked: {_bool_str(p.was_revoked)}",
        "",
        "## Role Participation (Separation of Duties)",
        "",
        *(
            [
                f"- {role}: `{principal_ids}`"
                for role, principal_ids in sorted(p.role_participation.items())
            ]
            if p.role_participation
            else ["- No role assignment was recorded for this manifest."]
        ),
        "",
        "## Causal Effect Graph",
        "",
        f"- Graph ID: `{p.causal_graph_id or 'none'}`",
        f"- Graph hash: `{p.causal_graph_hash or 'n/a'}`",
        f"- Signatures verified: {_bool_str(p.causal_graph_verified)}",
        *(
            [f"- Ancestor manifest hash: `{value}`" for value in p.causal_ancestor_manifest_hashes]
            if p.causal_ancestor_manifest_hashes
            else ["- No causal ancestors were recorded."]
        ),
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
        f"- Compensation manifest hash (pointer): `{p.compensation_manifest_hash or 'none'}`",
        f"- Compensation passport status (pointer): `{p.compensation_passport_status or 'n/a'}`",
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


def render_passport_v2_markdown(passport: ActionPassportV2) -> str:
    """Render an Action Passport V2, including format and outcome_status."""
    from karmasakshi.passports.v2 import ActionPassportV2 as ActionPassportV2Type

    if not isinstance(passport, ActionPassportV2Type):
        raise TypeError("render_passport_v2_markdown requires ActionPassportV2")
    p = passport
    body_lines = [
        f"# Action Passport V2: {p.manifest_id}",
        "",
        f"Format: `{p.passport_format}` / schema `{p.schema_version}`",
        f"Passport hash: `{p.passport_hash}`",
        f"Generated: {p.generated_at.isoformat()}",
        f"Lifecycle state: **{p.lifecycle_state}**",
        f"Outcome status: **{p.outcome_status.value}**",
        f"Tenant: `{p.tenant_id or 'none'}`",
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
        "This passport is a factual record, not a security certification. "
        "See docs/limitations.md and docs/action-passport-v2.md.",
    ]
    return "\n".join(body_lines)


def render_passport_v2_html(passport: ActionPassportV2) -> str:
    md = render_passport_v2_markdown(passport)
    escaped = html.escape(md)
    return f'<article class="karmasakshi-action-passport-v2">\n<pre>{escaped}</pre>\n</article>\n'


__all__ = [
    "render_passport_html",
    "render_passport_markdown",
    "render_passport_v2_html",
    "render_passport_v2_markdown",
]
