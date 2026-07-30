"""RA-001 remediation: property-based fuzzing of canonical org-id validation
and the tenant control-plane containment guarantee.

The core property under test: for *any* string, either
`validate_canonical_org_id` rejects it, or -- if accepted -- resolving it as
a tenant directory under an arbitrary root never escapes that root."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from karmasakshi.errors import InvalidOrganizationIdError
from karmasakshi.tenant.control_plane import MultiTenantControlPlane
from karmasakshi.tenant.org_id import validate_canonical_org_id

#: Arbitrary text, biased toward path-hostile characters (including
#: fullwidth Unicode look-alikes of '.' and '/'), plus a printable fallback
#: so the suite isn't dominated by rejects.
_hostile_chars = st.sampled_from("./\\:.\x00\x1f\x7f．／ ")  # noqa: RUF001
_arbitrary_org_id = st.one_of(
    st.text(min_size=0, max_size=80),
    st.text(alphabet=_hostile_chars, min_size=0, max_size=40),
    st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x2FFFF), max_size=40),
)


@given(_arbitrary_org_id)
@settings(max_examples=500, deadline=None)
def test_accepted_ids_never_escape_the_data_root_when_resolved(tmp_path_factory, value):
    root = tmp_path_factory.mktemp("org-id-property-root")
    try:
        validate_canonical_org_id(value)
    except InvalidOrganizationIdError:
        return  # rejection is always an acceptable outcome
    resolved_root = root.resolve()
    tenant_dir = (resolved_root / value).resolve()
    assert tenant_dir.is_relative_to(resolved_root)
    assert tenant_dir != resolved_root
    assert tenant_dir.parent == resolved_root


@given(_arbitrary_org_id)
@settings(max_examples=300, deadline=None)
def test_control_plane_build_state_never_escapes_or_silently_succeeds_unsafely(
    tmp_path_factory, value
):
    root = tmp_path_factory.mktemp("org-id-property-plane-root")
    plane = MultiTenantControlPlane(data_root=root)
    resolved_root = root.resolve()
    try:
        plane._build_state(value)
    except InvalidOrganizationIdError:
        return
    # If it did not raise, the tenant directory must exist and be contained.
    tenant_dir = (resolved_root / value).resolve()
    assert tenant_dir.exists()
    assert tenant_dir.is_relative_to(resolved_root)


@given(
    st.text(
        alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd")), min_size=1, max_size=30
    )
)
@settings(max_examples=200, deadline=None)
def test_validation_is_deterministic(value):
    """Calling the validator twice on the same input must agree -- no
    hidden state, no time-of-check/time-of-use gap."""
    first_ok, second_ok = None, None
    first_exc, second_exc = None, None
    try:
        first_ok = validate_canonical_org_id(value)
    except InvalidOrganizationIdError as exc:
        first_exc = type(exc)
    try:
        second_ok = validate_canonical_org_id(value)
    except InvalidOrganizationIdError as exc:
        second_exc = type(exc)
    assert first_ok == second_ok
    assert first_exc == second_exc
