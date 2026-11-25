"""Core revocation operations for browser and API sessions.

The store is a plain mapping with four collections: sessions keyed by
session id, tokens keyed by token id, audit as an append ordered list,
and revocations keyed by session id.  Validity is always evaluated
against the authoritative session/token records so that a revocation is
visible on the very next check; any stale cache entry is dropped when a
session is revoked.
"""

TARGET_KINDS = ("session", "device", "account")
_ID_FIELDS = ("session_id", "device_id", "account_id")


def resolve_targets(store, target, kind):
    """Resolve one revocation target into the session ids it covers.

    Every target is scoped to one tenant: device and account lookups only
    match sessions inside that tenant, and a session id from another
    tenant resolves to nothing.  The returned ids are sorted.
    """
    target = target or {}
    tenant_id = target.get("tenant_id")
    if not tenant_id:
        return []

    sessions = (store or {}).get("sessions", {}) or {}

    if kind == "session":
        session_id = target.get("session_id")
        if not session_id:
            return []
        session = sessions.get(session_id)
        if session is None or session.get("tenant_id") != tenant_id:
            return []
        return [session_id]

    if kind == "device":
        device_id = target.get("device_id")
        if not device_id:
            return []
        return sorted(
            session_id
            for session_id, session in sessions.items()
            if session is not None
            and session.get("tenant_id") == tenant_id
            and session.get("device_id") == device_id
        )

    if kind == "account":
        account_id = target.get("account_id")
        if not account_id:
            return []
        return sorted(
            session_id
            for session_id, session in sessions.items()
            if session is not None
            and session.get("tenant_id") == tenant_id
            and session.get("account_id") == account_id
        )

    return []


def cascade(store, session):
    """Return the ids of all tokens derived from a session.

    Both refresh and access tokens are included.  Store iteration order is
    preserved.
    """
    if not session:
        return []

    session_id = session.get("session_id")
    derived = []
    for token_id, token in ((store or {}).get("tokens", {}) or {}).items():
        if token is not None and token.get("session_id") == session_id:
            derived.append(token_id)
    return derived


def _already_revoked(session, session_id, revocations):
    """Whether a session should be treated as revoked already."""
    if session_id in revocations:
        return True
    if session.get("status") == "revoked":
        return True
    if session.get("revoked_at") is not None:
        return True
    return False


def revoke(store, session_ids, now, reason):
    """Revoke every listed session and report what happened.

    First revocation wins: the session is marked revoked with the given
    time and reason, every derived token is revoked, and exactly one audit
    record is appended.  Repeating a revocation only classifies the
    session as ``already_revoked`` and changes nothing.
    """
    sessions = store.setdefault("sessions", {})
    tokens = store.setdefault("tokens", {})
    audit_log = store.setdefault("audit", [])
    revocations = store.setdefault("revocations", {})

    revoked = []
    already_revoked = []
    skipped = []
    touched_tokens = []

    for session_id in session_ids or []:
        session = sessions.get(session_id)
        if session is None:
            skipped.append(session_id)
            continue

        # Drop any short lived validity entry so the next check reads the
        # authoritative (now revoked) session record.
        cache = store.get("cache")
        if isinstance(cache, dict):
            cache.pop(session_id, None)

        if _already_revoked(session, session_id, revocations):
            already_revoked.append(session_id)
            continue

        revocations[session_id] = {
            "session_id": session_id,
            "revoked_at": now,
            "reason": reason,
        }

        session["status"] = "revoked"
        session["revoked_at"] = now
        session["revoke_reason"] = reason
        revoked.append(session_id)

        for token_id in cascade(store, session):
            token = tokens.get(token_id)
            if token is None:
                continue
            if token.get("revoked_at") is None:
                token["revoked_at"] = now
                touched_tokens.append(token_id)

        audit_log.append(
            {
                "session_id": session_id,
                "tenant_id": session.get("tenant_id"),
                "action": "revoke",
                "at": now,
                "reason": reason,
            }
        )

    return {
        "revoked": revoked,
        "already_revoked": already_revoked,
        "skipped": skipped,
        "tokens": touched_tokens,
    }


def is_valid(store, session, now):
    """Return whether a session may still be accepted.

    The authoritative session record in the store is checked on every
    call so revocation and expiry take effect immediately.
    """
    if not session:
        return False

    session_id = session.get("session_id")
    sessions = (store or {}).get("sessions", {}) or {}
    record = sessions.get(session_id)
    if record is None:
        return False

    if record.get("status") == "revoked":
        return False
    if record.get("revoked_at") is not None:
        return False

    expires_at = record.get("expires_at")
    if expires_at is not None and now >= expires_at:
        return False

    return True


def audit(store, session_id):
    """Return the revocation audit records for one session.

    Records are returned in append (write) order and as shallow copies so
    caller mutations never reach the store.
    """
    return [
        dict(record)
        for record in ((store or {}).get("audit", []) or [])
        if record.get("session_id") == session_id
    ]


def check_refresh(store, session, now):
    """Return whether the session may exchange a refresh token."""
    if not session or not is_valid(store, session, now):
        return False

    session_id = session.get("session_id")
    if session_id is None:
        return False

    for token in ((store or {}).get("tokens", {}) or {}).values():
        if token is None:
            continue
        if token.get("session_id") != session_id:
            continue
        if token.get("kind") != "refresh":
            continue
        if token.get("revoked_at") is not None:
            continue

        expires_at = token.get("expires_at")
        if expires_at is not None and now >= expires_at:
            continue

        return True

    return False


def validate_targets(targets):
    """Return human readable problems found in a set of revocation targets."""
    problems = []
    if not targets:
        return ["targets are empty"]

    tenants = set()
    seen = set()

    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            problems.append(f"target {index} is not a mapping")
            continue

        tenant_id = target.get("tenant_id")
        if tenant_id:
            tenants.add(tenant_id)
        else:
            problems.append(f"target {index} has no tenant")

        present = [field for field in _ID_FIELDS if target.get(field)]
        if not present:
            problems.append(f"target {index} is empty")
            continue
        if len(present) > 1:
            problems.append(f"target {index} names several scopes")
            continue

        key = (tenant_id, present[0], target[present[0]])
        if key in seen:
            problems.append(f"target {index} repeats an earlier target")
        seen.add(key)

    if len(tenants) > 1:
        problems.append("targets cross tenants")

    return problems


def revoke_batch(requests, now):
    """Revoke several targets, one request at a time.

    Every request resolves its own target fresh against its own store; no
    resolved session list is carried between requests.
    """
    results = []

    for request in requests or []:
        store = request["store"]
        target = request.get("target") or {}
        kind = request.get("kind", "session")
        reason = request.get("reason", "batch")

        session_ids = resolve_targets(store, target, kind)
        results.append(revoke(store, session_ids, now, reason))

    return {"results": results}
