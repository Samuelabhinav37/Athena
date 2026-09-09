"""Candidate inspection only: matching contact data is never identity proof."""

from sqlalchemy import func

from athena.models import Identity, IdentityType
from athena.tenant_queries import tenant_select


def inspect_candidates(session, identity, authoritative_source, *, limit=50):
    if not 1 <= limit <= 200:
        raise ValueError("Candidate limit must be between 1 and 200")
    result = {
        "identity_id": str(identity.id),
        "state": "unlinked",
        "method": "contact-hint-v1",
        "authoritative_source": authoritative_source,
        "candidates": [],
        "has_more": False,
        "link_confirmed": False,
        "limitations": [
            "Email can be shared or recycled; it does not establish a person link.",
            "Source account IDs and historical evidence remain unchanged.",
            "Candidates cannot authorize cross-source review or access changes.",
        ],
    }
    if identity.identity_type != IdentityType.HUMAN:
        result["state"] = "unsupported_account_type"
        return result
    if not identity.active:
        result["state"] = "inactive_account"
        return result
    email = (identity.email or "").strip().lower()
    if not email or not email.isascii() or email.count("@") != 1:
        result["state"] = "insufficient_evidence"
        return result
    source_filter = (
        Identity.source != authoritative_source
        if identity.source == authoritative_source
        else Identity.source == authoritative_source
    )
    statement = tenant_select(
        session,
        Identity,
        Identity.id != identity.id,
        source_filter,
        Identity.identity_type == IdentityType.HUMAN,
        func.lower(func.trim(Identity.email)) == email,
    ).order_by(Identity.source, Identity.external_id, Identity.id)
    # Fetch two even for limit=1 so a truncated page cannot imply uniqueness.
    matches = list(session.scalars(statement.limit(max(2, limit + 1))))
    result["has_more"] = len(matches) > limit
    if matches:
        result["state"] = "ambiguous" if len(matches) > 1 else "candidate"
    result["candidates"] = [
        {
            "identity_id": str(candidate.id),
            "source": candidate.source,
            "external_id": candidate.external_id,
            "display_name": candidate.display_name,
            "active": candidate.active,
            "reason": "matching_contact_hint",
            "requires_independent_confirmation": True,
        }
        for candidate in matches[:limit]
    ]
    return result
