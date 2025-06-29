import pytest
from permission_storage_manager.utils.helpers import (
    normalize_session_id,
    normalize_permissions,
    merge_permissions,
    has_any_permission,
    has_all_permissions,
)


def test_normalize_session_id():
    assert normalize_session_id("session/with:bad*chars") == "session_with_bad_chars"
    assert len(normalize_session_id("x" * 300)) <= 255
    assert normalize_session_id("__abc__") == "abc"


def test_normalize_permissions():
    perms = ["read", "write", "read", "", "admin"]
    result = normalize_permissions(perms)
    assert set(result) == {"read", "write", "admin"}
    assert normalize_permissions([]) == []
    assert normalize_permissions([""]) == []


def test_merge_permissions():
    assert set(merge_permissions(["read"], ["write", "admin"], "add")) == {
        "read",
        "write",
        "admin",
    }
    assert set(merge_permissions(["read", "write"], ["read"], "remove")) == {"write"}
    assert set(merge_permissions(["read"], ["write"], "replace")) == {"write"}
    with pytest.raises(ValueError):
        merge_permissions(["read"], ["write"], "invalid")


def test_has_any_permission():
    assert has_any_permission(["read", "write"], ["admin", "write"]) is True
    assert has_any_permission(["read"], ["admin", "super_admin"]) is False


def test_has_all_permissions():
    assert has_all_permissions(["read", "write", "admin"], ["read", "write"]) is True
    assert has_all_permissions(["read"], ["read", "admin"]) is False
