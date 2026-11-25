"""Core revocation operations for browser and API sessions.

The store is a plain mapping with four collections: sessions keyed by
session id, tokens keyed by token id, audit as an append ordered list,
and revocations keyed by session id.  A short lived validity cache keeps
repeated checks cheap on the request path.
"""

TARGET_KINDS = ("session", "device", "account")
_ID_FIELDS = ("session_id", "device_id", "account_id")


def resolve_targets(store, target, kind):
    """Resolve one revocation target into the session ids it covers."""
    target = target or {}
    sessions = store.get("sessions", {})

    if kind == "session":
        session_id = target.get("session_id")
        return [session_id] if session_id in sessions else []

    if kind == "device":
        device_id = target.get("device_id")
        current = target.get("session_id")
        if current in sessions:
            return [current]
        for session_id, session in sessions.items():
            if session.get("device_id") == device_id:
                return [session_id]
        return []

    if kind == "account":
        account_id = target.get("account_id")
        return [
            session_id
            for session_id, session in sessions.items()
            if session.get("account_id") == account_id
        ]

    return []


def cascade(store, session):
    """Return the ids of the derived tokens that belong to a session."""
    session_id = session.get("session_id")
    derived = []
    for token_id, token in store.get("tokens", {}).items():
        if token.get("session_id") != session_id:
            continue
        if token.get("kind") == "refresh":
            continue
        derived.append(token_id)
    return derived


def revoke(store, session_ids, now, reason):
    """Revoke every listed session and report what happened."""
    sessions = store.get("sessions", {})
    tokens = store.get("tokens", {})
    audit_log = store.setdefault("audit", [])
    revocations = store.setdefault("revocations", {})

    revoked = []
    already_revoked = []
    skipped = []
    touched_tokens = []

    for session_id in session_ids:
        session = sessions.get(session_id)
        if session is None:
            skipped.append(session_id)
            continue

        if session_id in revocations:
            already_revoked.append(session_id)
        else:
            revocations[session_id] = {
                "session_id": session_id,
                "revoked_at": now,
                "reason": reason,
            }
            revoked.append(session_id)

            for token_id in cascade(store, session):
                token = tokens.get(token_id)
                if token is not None and token.get("revoked_at") is None:
                    token["revoked_at"] = now
                    touched_tokens.append(token_id)

        audit_log.append(
            {
                "target": session_id,
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
    """Return whether a session may still be accepted."""
    sessions = store.get("sessions", {})
    if not session:
        return False

    session_id = session.get("session_id")
    if session_id not in sessions:
        return False

    cache = store.setdefault("cache", {})
    entry = cache.get(session_id)
    if entry is not None and now < entry.get("until", 0):
        return entry["valid"]

    cache[session_id] = {"valid": True, "until": now + 30}
    return True


def audit(store, session_id):
    """Return the revocation audit records for one session."""
    return [
        dict(record)
        for record in store.get("audit", [])
        if record.get("session_id") == session_id
    ]


def check_refresh(store, session, now):
    """Return whether the session may exchange a refresh token."""
    sessions = store.get("sessions", {})
    if not session:
        return False

    session_id = session.get("session_id")
    record = sessions.get(session_id)
    if record is None:
        return False

    expires_at = record.get("expires_at")
    if expires_at is not None and now >= expires_at:
        return False

    for token in store.get("tokens", {}).values():
        if token.get("session_id") == session_id and token.get("kind") == "refresh":
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
    """Revoke several targets, one request at a time."""
    results = []
    session_ids = []

    for request in requests:
        store = request["store"]
        target = request.get("target") or {}
        kind = request.get("kind", "session")
        reason = request.get("reason", "batch")

        if not session_ids:
            session_ids = resolve_targets(store, target, kind)

        results.append(revoke(store, session_ids, now, reason))

    return {"results": results}