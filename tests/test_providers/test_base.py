import pytest
from permission_storage_manager.core.base import BaseProvider


class DummyProvider(BaseProvider):
    def __init__(self):
        super().__init__()
        self._provider_name = "dummy"
        self._supports_ttl = False

    @property
    def provider_name(self) -> str:
        return self._provider_name

    @property
    def supports_ttl(self) -> bool:
        return self._supports_ttl

    async def initialize(self):
        self._initialized = True

    async def close(self):
        self._initialized = False

    async def store_permissions(
        self, session_id, user_id, permissions, ttl=None, metadata=None
    ):
        return True

    async def get_permissions(self, session_id):
        return {"user_id": "test", "permissions": ["read"]}

    async def check_permission(self, session_id, permission):
        return True

    async def check_permissions(self, session_id, permissions):
        return {p: True for p in permissions}

    async def invalidate_session(self, session_id):
        return True

    async def update_permissions(self, session_id, permissions, metadata=None):
        return True

    async def extend_session_ttl(self, session_id, ttl):
        return True

    async def list_sessions(self, user_id=None, limit=None, offset=0):
        return ["session1", "session2"]

    async def cleanup_expired_sessions(self):
        return 0

    async def get_session_info(self, session_id):
        return {"session_id": session_id, "user_id": "test"}


def test_base_provider_properties():
    p = DummyProvider()
    assert p.provider_name == "dummy"
    assert p.supports_ttl is False
    assert p.is_initialized is False
    # initialize çağrısı sonrası True olmalı
    import asyncio

    asyncio.run(p.initialize())
    assert p.is_initialized is True
    asyncio.run(p.close())
    assert p.is_initialized is False


@pytest.mark.asyncio
async def test_base_provider_not_implemented_methods():
    provider = DummyProvider()
    # Test that all abstract methods are implemented and work
    assert await provider.store_permissions("test", "user", ["read"]) is True
    assert await provider.get_permissions("test") is not None
    assert await provider.check_permission("test", "read") is True
    assert await provider.check_permissions("test", ["read"]) == {"read": True}
    assert await provider.invalidate_session("test") is True
    assert await provider.update_permissions("test", ["write"]) is True
    assert await provider.extend_session_ttl("test", 3600) is True
    assert await provider.list_sessions() == ["session1", "session2"]
    assert await provider.cleanup_expired_sessions() == 0
    assert await provider.get_session_info("test") is not None
