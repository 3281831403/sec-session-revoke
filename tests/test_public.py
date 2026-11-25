"""Public contract tests for session revocation."""

from engine.revoke import audit, is_valid, revoke, revoke_batch

NOW = 1_000


def _session(session_id, device_id="d1"):
    return {
        "session_id": session_id,
        "tenant_id": "t1",
        "account_id": "a1",
        "device_id": device_id,
        "created_at": 0,
        "expires_at": 10_000,
        "revoked_at": None,
        "revoke_reason": None,
        "status": "active",
    }


def _token(token_id, session_id, kind):
    return {
        "token_id": token_id,
        "session_id": session_id,
        "tenant_id": "t1",
        "account_id": "a1",
        "device_id": "d1",
        "kind": kind,
        "issued_at": 0,
        "expires_at": 10_000,
        "revoked_at": None,
    }


def _store():
    return {
        "sessions": {
            "s1": _session("s1"),
            "s2": _session("s2"),
        },
        "tokens": {
            "rt1": _token("rt1", "s1", "refresh"),
            "at1": _token("at1", "s1", "access"),
            "rt2": _token("rt2", "s2", "refresh"),
        },
        "audit": [],
        "revocations": {},
        "cache": {},
    }


def test_single_session_revocation_takes_effect():
    store = _store()

    summary = revoke(store, ["s1"], NOW, "admin")

    assert summary["revoked"] == ["s1"]
    assert store["sessions"]["s1"]["revoked_at"] == NOW
    assert store["sessions"]["s1"]["status"] == "revoked"


def test_revoked_session_fails_validation():
    store = _store()
    session = store["sessions"]["s1"]
    assert is_valid(store, session, NOW - 1) is True

    revoke(store, ["s1"], NOW, "admin")

    assert is_valid(store, session, NOW + 1) is False


def test_cascade_covers_refresh_token():
    store = _store()

    summary = revoke(store, ["s1"], NOW, "admin")

    assert "rt1" in summary["tokens"]
    assert store["tokens"]["rt1"]["revoked_at"] == NOW


def test_revocation_writes_audit_record():
    store = _store()

    revoke(store, ["s1"], NOW, "admin")

    records = audit(store, "s1")
    assert len(records) == 1
    assert records[0]["reason"] == "admin"


def test_batch_requests_are_independent():
    store = _store()
    requests = [
        {
            "store": store,
            "kind": "session",
            "target": {"tenant_id": "t1", "session_id": "s1"},
            "reason": "first",
        },
        {
            "store": store,
            "kind": "session",
            "target": {"tenant_id": "t1", "session_id": "s2"},
            "reason": "second",
        },
    ]

    result = revoke_batch(requests, NOW)

    assert store["sessions"]["s1"]["revoked_at"] == NOW
    assert store["sessions"]["s2"]["revoked_at"] == NOW
    assert [item["revoked"] for item in result["results"]] == [["s1"], ["s2"]]