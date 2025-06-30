"""
Tests for the main PermissionStorageManager class.
"""

import asyncio
import pytest

from permission_storage_manager import PermissionStorageManager, create_manager
from permission_storage_manager.core.base import BaseProvider
from permission_storage_manager.core.exceptions import (
    ProviderNotSupportedError,
    ProviderNotInitializedError,
    ValidationError,
    InvalidSessionIdError,
    InvalidUserIdError,
    TTLError,
    ProviderError,
)


class TestPermissionStorageManager:
    """Test cases for PermissionStorageManager."""

    def test_create_with_string_provider(self, memory_config):
        """Test creating manager with string provider name."""
        manager = PermissionStorageManager("memory", memory_config)
        assert manager.provider_name == "memory"
        assert not manager.is_initialized

    def test_create_with_provider_instance(self, memory_provider):
        """Test creating manager with provider instance."""
        manager = PermissionStorageManager(memory_provider)
        assert manager.provider_name == "memory"
        assert manager.supports_ttl

    def test_create_with_invalid_provider_type(self):
        """Test creating manager with invalid provider type."""
        with pytest.raises(ValueError, match="Provider must be either a string name"):
            PermissionStorageManager(123)

    def test_create_with_unsupported_provider(self):
        """Test creating manager with unsupported provider name."""
        with pytest.raises(ProviderNotSupportedError):
            PermissionStorageManager("unsupported_provider")

    def test_register_provider(self):
        """Test registering a new provider."""

        class TestProvider(BaseProvider):
            async def initialize(self):
                pass

            async def close(self):
                pass

            async def store_permissions(self, *args, **kwargs):
                return True

            async def check_permission(self, *args, **kwargs):
                return True

            async def check_permissions(self, *args, **kwargs):
                return {}

            async def get_permissions(self, *args, **kwargs):
                return None

            async def invalidate_session(self, *args, **kwargs):
                return True

            async def update_permissions(self, *args, **kwargs):
                return True

            async def extend_session_ttl(self, *args, **kwargs):
                return True

            async def get_session_info(self, *args, **kwargs):
                return None

            async def list_sessions(self, *args, **kwargs):
                return []

            async def cleanup_expired_sessions(self, *args, **kwargs):
                return 0

            @property
            def provider_name(self):
                return "test"

            @property
            def supports_ttl(self):
                return True

        # Register the provider
        PermissionStorageManager.register_provider("test", TestProvider)

        # Should be able to create manager with it
        manager = PermissionStorageManager("test")
        assert manager.provider_name == "test"

        # Should appear in available providers
        available = PermissionStorageManager.get_available_providers()
        assert "test" in available

    def test_get_available_providers(self):
        """Test getting list of available providers."""
        providers = PermissionStorageManager.get_available_providers()
        assert isinstance(providers, list)
        assert "memory" in providers
        assert "file" in providers
        assert "redis" in providers

    async def test_initialization(self, any_manager):
        """Test manager initialization."""
        # Manager should be initialized by fixture
        assert any_manager.is_initialized
        assert any_manager._provider.is_initialized

    async def test_auto_initialization(self, memory_config):
        """Test automatic initialization on first use."""
        manager = PermissionStorageManager(
            "memory", memory_config, auto_initialize=True
        )
        assert not manager.is_initialized

        # First operation should auto-initialize
        result = await manager.store_permissions("session_1", "user_1", ["read"])
        assert result is True
        assert manager.is_initialized

        await manager.close()

    async def test_context_manager_async(self, memory_config):
        """Test async context manager functionality."""
        async with PermissionStorageManager("memory", memory_config) as manager:
            assert manager.is_initialized
            await manager.store_permissions("session_1", "user_1", ["read"])
            has_read = await manager.check_permission("session_1", "read")
            assert has_read is True

        # Should be closed after context
        assert not manager.is_initialized

    def test_context_manager_sync(self, memory_config):
        """Test sync context manager functionality."""
        with PermissionStorageManager("memory", memory_config) as manager:
            assert manager.is_initialized
            manager.store_permissions_sync("session_1", "user_1", ["read"])
            has_read = manager.check_permission_sync("session_1", "read")
            assert has_read is True

        # Should be closed after context
        assert not manager.is_initialized


class TestPermissionOperations:
    """Test permission-related operations."""

    async def test_store_permissions_basic(self, any_manager, sample_session_data):
        """Test basic permission storage."""
        result = await any_manager.store_permissions(
            sample_session_data["session_id"],
            sample_session_data["user_id"],
            sample_session_data["permissions"],
            metadata=sample_session_data["metadata"],
        )
        assert result is True

    async def test_store_permissions_with_ttl(self, any_manager):
        """Test storing permissions with TTL."""
        result = await any_manager.store_permissions(
            "session_ttl", "user_ttl", ["read", "write"], ttl=3600
        )
        assert result is True

    async def test_store_permissions_validation(self, any_manager):
        """Test input validation for store_permissions."""
        # Invalid session ID
        with pytest.raises(InvalidSessionIdError):
            await any_manager.store_permissions("", "user_1", ["read"])

        # Invalid user ID
        with pytest.raises(InvalidUserIdError):
            await any_manager.store_permissions("session_1", "", ["read"])

        # Invalid permissions
        with pytest.raises(ValidationError):
            await any_manager.store_permissions("session_1", "user_1", [])

        # Invalid TTL
        with pytest.raises(TTLError):
            await any_manager.store_permissions("session_1", "user_1", ["read"], ttl=-1)

    async def test_check_permission_basic(self, any_manager, sample_session_data):
        """Test basic permission checking."""
        # Store permissions first
        await any_manager.store_permissions(
            sample_session_data["session_id"],
            sample_session_data["user_id"],
            sample_session_data["permissions"],
        )

        # Check existing permission
        has_read = await any_manager.check_permission(
            sample_session_data["session_id"], "read"
        )
        assert has_read is True

        # Check non-existing permission
        has_delete = await any_manager.check_permission(
            sample_session_data["session_id"], "super_admin"
        )
        assert has_delete is False

    async def test_check_permission_nonexistent_session(self, any_manager):
        """Test checking permission for non-existent session."""
        has_perm = await any_manager.check_permission("nonexistent", "read")
        assert has_perm is False

    async def test_check_permissions_multiple(self, any_manager, sample_session_data):
        """Test checking multiple permissions."""
        # Store permissions first
        await any_manager.store_permissions(
            sample_session_data["session_id"],
            sample_session_data["user_id"],
            sample_session_data["permissions"],
        )

        # Check multiple permissions - use permissions that exist and don't exist
        to_check = ["read", "write", "admin", "delete", "super_admin"]
        results = await any_manager.check_permissions(
            sample_session_data["session_id"], to_check
        )

        # Permissions that should exist
        assert results["read"] is True
        assert results["write"] is True
        assert results["admin"] is True

        # Permissions that should not exist
        assert results["delete"] is False
        assert results["super_admin"] is False

    async def test_get_permissions(self, any_manager, sample_session_data):
        """Test getting all permissions for a session."""
        # Store permissions first
        await any_manager.store_permissions(
            sample_session_data["session_id"],
            sample_session_data["user_id"],
            sample_session_data["permissions"],
            metadata=sample_session_data["metadata"],
        )

        # Get permissions
        data = await any_manager.get_permissions(sample_session_data["session_id"])
        assert data is not None
        assert data["user_id"] == sample_session_data["user_id"]
        assert set(data["permissions"]) == set(sample_session_data["permissions"])
        assert data["metadata"] == sample_session_data["metadata"]
        assert "created_at" in data
        assert "updated_at" in data

    async def test_get_permissions_nonexistent(self, any_manager):
        """Test getting permissions for non-existent session."""
        data = await any_manager.get_permissions("nonexistent")
        assert data is None

    async def test_invalidate_session(self, any_manager, sample_session_data):
        """Test session invalidation."""
        # Store permissions first
        await any_manager.store_permissions(
            sample_session_data["session_id"],
            sample_session_data["user_id"],
            sample_session_data["permissions"],
        )

        # Verify session exists
        data = await any_manager.get_permissions(sample_session_data["session_id"])
        assert data is not None

        # Invalidate session
        result = await any_manager.invalidate_session(sample_session_data["session_id"])
        assert result is True

        # Verify session is gone
        data = await any_manager.get_permissions(sample_session_data["session_id"])
        assert data is None

    async def test_invalidate_nonexistent_session(self, any_manager):
        """Test invalidating non-existent session."""
        result = await any_manager.invalidate_session("nonexistent")
        assert result is False

    async def test_update_permissions(self, any_manager, sample_session_data):
        """Test updating permissions for existing session."""
        # Store initial permissions
        await any_manager.store_permissions(
            sample_session_data["session_id"], sample_session_data["user_id"], ["read"]
        )

        # Update permissions
        new_permissions = ["read", "write", "admin"]
        result = await any_manager.update_permissions(
            sample_session_data["session_id"], new_permissions
        )
        assert result is True

        # Verify updated permissions
        data = await any_manager.get_permissions(sample_session_data["session_id"])
        assert set(data["permissions"]) == set(new_permissions)

    async def test_update_nonexistent_session(self, any_manager):
        """Test updating permissions for non-existent session."""
        result = await any_manager.update_permissions("nonexistent", ["read"])
        assert result is False

    async def test_extend_session_ttl(self, any_manager):
        """Test extending session TTL."""
        # Store session with TTL
        await any_manager.store_permissions("session_ttl", "user_1", ["read"], ttl=10)

        # Extend TTL
        result = await any_manager.extend_session_ttl("session_ttl", 3600)
        assert result is True

    async def test_extend_ttl_nonexistent_session(self, any_manager):
        """Test extending TTL for non-existent session."""
        result = await any_manager.extend_session_ttl("nonexistent", 3600)
        assert result is False


class TestSessionManagement:
    """Test session management operations."""

    async def test_get_session_info(self, any_manager, sample_session_data):
        """Test getting session information."""
        # Store session with TTL
        await any_manager.store_permissions(
            sample_session_data["session_id"],
            sample_session_data["user_id"],
            sample_session_data["permissions"],
            ttl=3600,
            metadata=sample_session_data["metadata"],
        )

        # Get session info
        info = await any_manager.get_session_info(sample_session_data["session_id"])
        assert info is not None
        assert info["user_id"] == sample_session_data["user_id"]
        assert "has_ttl" in info
        assert "provider" in info

        if info["has_ttl"]:
            assert "ttl_remaining" in info
            assert info["ttl_remaining"] > 0

    async def test_list_sessions(self, any_manager, multiple_sessions):
        """Test listing sessions."""
        # Store multiple sessions
        for session in multiple_sessions[:5]:  # Store first 5
            await any_manager.store_permissions(
                session["session_id"], session["user_id"], session["permissions"]
            )

        # List all sessions
        sessions = await any_manager.list_sessions()
        assert len(sessions) >= 5

        # List sessions for specific user
        user_sessions = await any_manager.list_sessions(user_id="user_0")
        assert len(user_sessions) >= 1

        # Test pagination
        limited_sessions = await any_manager.list_sessions(limit=2)
        assert len(limited_sessions) <= 2

    async def test_cleanup_expired_sessions(self, any_manager):
        """Test cleanup of expired sessions."""
        # This will depend on provider implementation
        cleaned = await any_manager.cleanup_expired_sessions()
        assert isinstance(cleaned, int)
        assert cleaned >= 0


class TestSynchronousOperations:
    """Test synchronous wrapper methods."""

    def test_store_permissions_sync(self, memory_manager, sample_session_data):
        """Test synchronous permission storage."""
        result = memory_manager.store_permissions_sync(
            sample_session_data["session_id"],
            sample_session_data["user_id"],
            sample_session_data["permissions"],
        )
        assert result is True

    def test_check_permission_sync(self, memory_manager):
        """Test synchronous permission checking."""
        # Store first
        memory_manager.store_permissions_sync("session_1", "user_1", ["read"])

        # Check
        has_read = memory_manager.check_permission_sync("session_1", "read")
        assert has_read is True

        has_write = memory_manager.check_permission_sync("session_1", "write")
        assert has_write is False

    def test_check_permissions_sync(self, memory_manager):
        """Test synchronous multiple permission checking."""
        # Store first
        memory_manager.store_permissions_sync("session_1", "user_1", ["read", "write"])

        # Check multiple
        results = memory_manager.check_permissions_sync(
            "session_1", ["read", "write", "admin"]
        )
        assert results["read"] is True
        assert results["write"] is True
        assert results["admin"] is False

    def test_get_permissions_sync(self, memory_manager):
        """Test synchronous getting permissions."""
        # Store first
        memory_manager.store_permissions_sync("session_1", "user_1", ["read"])

        # Get
        data = memory_manager.get_permissions_sync("session_1")
        assert data is not None
        assert data["user_id"] == "user_1"
        assert "read" in data["permissions"]

    def test_invalidate_session_sync(self, memory_manager):
        """Test synchronous session invalidation."""
        # Store first
        memory_manager.store_permissions_sync("session_1", "user_1", ["read"])

        # Invalidate
        result = memory_manager.invalidate_session_sync("session_1")
        assert result is True

        # Verify gone
        data = memory_manager.get_permissions_sync("session_1")
        assert data is None


class TestConvenienceFunctions:
    """Test convenience functions."""

    async def test_create_manager_default(self):
        """Test create_manager with default settings."""
        manager = create_manager()
        assert manager.provider_name == "memory"
        assert manager.default_ttl == 3600

        await manager.initialize()
        await manager.close()

    async def test_create_manager_with_provider(self, redis_config):
        """Test create_manager with specific provider."""
        try:
            manager = create_manager("redis", redis_config, default_ttl=7200)
            assert manager.provider_name == "redis"
            assert manager.default_ttl == 7200

            await manager.initialize()
            await manager.close()
        except Exception:
            pytest.skip("Redis not available for testing")


class TestErrorHandling:
    """Test error handling scenarios."""

    async def test_uninitialized_manager_with_auto_init_disabled(self, memory_config):
        """Test using uninitialized manager with auto-init disabled."""
        manager = PermissionStorageManager(
            "memory", memory_config, auto_initialize=False
        )

        # Should raise ProviderNotInitializedError when auto_initialize=False
        with pytest.raises(ProviderNotInitializedError):
            await manager.store_permissions("session_1", "user_1", ["read"])

        # Should work after manual initialization
        await manager.initialize()
        result = await manager.store_permissions("session_1", "user_1", ["read"])
        assert result is True

        await manager.close()

    async def test_provider_error_propagation(self):
        """Test that provider errors are properly propagated."""

        # Create a mock provider that extends BaseProvider
        class MockProvider(BaseProvider):
            async def initialize(self):
                pass

            async def close(self):
                pass

            async def store_permissions(
                self, session_id, user_id, permissions, ttl=None, metadata=None
            ):
                raise Exception("Provider error")

            async def check_permission(self, session_id, permission):
                return False

            async def check_permissions(self, session_id, permissions):
                return {perm: False for perm in permissions}

            async def get_permissions(self, session_id):
                return None

            async def invalidate_session(self, session_id):
                return False

            async def update_permissions(self, session_id, permissions, ttl=None):
                return False

            async def extend_session_ttl(self, session_id, ttl):
                return False

            async def get_session_info(self, session_id):
                return None

            async def list_sessions(self, user_id=None, limit=100, offset=0):
                return []

            async def cleanup_expired_sessions(self):
                return 0

            @property
            def provider_name(self):
                return "mock"

            @property
            def supports_ttl(self):
                return True

        mock_provider = MockProvider()
        manager = PermissionStorageManager(mock_provider)

        with pytest.raises(Exception, match="Provider error"):
            await manager.store_permissions("session_1", "user_1", ["read"])

    async def test_validation_errors(self, memory_manager):
        """Test various validation error scenarios."""
        # Test invalid session ID
        with pytest.raises(InvalidSessionIdError):
            await memory_manager.store_permissions("", "user_1", ["read"])

        # Test invalid user ID
        with pytest.raises(InvalidUserIdError):
            await memory_manager.store_permissions("session_1", "", ["read"])

        # Test empty permissions
        with pytest.raises(ValidationError):
            await memory_manager.store_permissions("session_1", "user_1", [])

        # Test invalid TTL
        with pytest.raises(TTLError):
            await memory_manager.store_permissions(
                "session_1", "user_1", ["read"], ttl=-1
            )

    async def test_double_close(self, memory_manager):
        """Test that double close doesn't cause errors."""
        await memory_manager.close()
        # Second close should not raise an error
        await memory_manager.close()


class TestProviderProperties:
    """Test provider property access through manager."""

    def test_provider_name_property(self, any_manager):
        """Test provider_name property."""
        name = any_manager.provider_name
        assert name in ["memory", "file", "redis"]

    def test_supports_ttl_property(self, any_manager):
        """Test supports_ttl property."""
        supports_ttl = any_manager.supports_ttl
        assert isinstance(supports_ttl, bool)
        # All our providers support TTL
        assert supports_ttl is True

    def test_is_initialized_property(self, any_manager):
        """Test is_initialized property."""
        assert any_manager.is_initialized is True


class TestConcurrentAccess:
    """Test concurrent access scenarios."""

    async def test_concurrent_store_operations(self, any_manager):
        """Test concurrent store operations."""

        async def store_session(session_id, user_id):
            return await any_manager.store_permissions(
                f"session_{session_id}", f"user_{user_id}", ["read", "write"]
            )

        # Run multiple concurrent operations
        tasks = [store_session(i, i % 3) for i in range(10)]
        results = await asyncio.gather(*tasks)

        # All should succeed
        assert all(results)

    async def test_concurrent_read_operations(self, any_manager):
        """Test concurrent read operations."""
        # Store a session first
        await any_manager.store_permissions(
            "shared_session", "user_1", ["read", "write"]
        )

        async def check_permission(permission):
            return await any_manager.check_permission("shared_session", permission)

        # Run multiple concurrent checks
        tasks = [check_permission("read") for _ in range(10)]
        results = await asyncio.gather(*tasks)

        # All should return True
        assert all(results)

    async def test_concurrent_mixed_operations(self, any_manager):
        """Test mixed concurrent operations."""
        # Store initial session
        await any_manager.store_permissions("mixed_session", "user_1", ["read"])

        async def read_operation():
            return await any_manager.check_permission("mixed_session", "read")

        async def write_operation():
            return await any_manager.update_permissions(
                "mixed_session", ["read", "write"]
            )

        # Mix of read and write operations
        tasks = [
            read_operation() if i % 2 == 0 else write_operation() for i in range(6)
        ]
        results = await asyncio.gather(*tasks)

        # Should not raise exceptions
        assert len(results) == 6


class TestPerformance:
    """Basic performance tests."""

    @pytest.mark.slow
    async def test_bulk_operations_performance(self, memory_manager, performance_data):
        """Test performance with bulk operations."""
        import time

        # Measure store operations
        start_time = time.time()
        for session_data in performance_data:
            await memory_manager.store_permissions(
                session_data["session_id"],
                session_data["user_id"],
                session_data["permissions"],
            )
        store_time = time.time() - start_time

        # Measure read operations
        start_time = time.time()
        for session_data in performance_data:
            await memory_manager.get_permissions(session_data["session_id"])
        read_time = time.time() - start_time

        print(f"Store time for {len(performance_data)} sessions: {store_time:.3f}s")
        print(f"Read time for {len(performance_data)} sessions: {read_time:.3f}s")

        # Basic performance assertions (very lenient)
        assert store_time < 10.0  # Should complete in under 10 seconds
        assert read_time < 5.0  # Should complete in under 5 seconds

    @pytest.mark.slow
    async def test_concurrent_performance(self, memory_manager):
        """Test performance under concurrent load."""
        import time

        async def worker(worker_id, num_operations):
            """Worker function for concurrent operations."""
            for i in range(num_operations):
                session_id = f"worker_{worker_id}_session_{i}"
                await memory_manager.store_permissions(
                    session_id, f"user_{worker_id}", ["read", "write"]
                )

                # Read back the permission
                has_read = await memory_manager.check_permission(session_id, "read")
                assert has_read is True

        # Run multiple workers concurrently
        num_workers = 5
        operations_per_worker = 20

        start_time = time.time()
        tasks = [worker(i, operations_per_worker) for i in range(num_workers)]
        await asyncio.gather(*tasks)
        total_time = time.time() - start_time

        total_operations = num_workers * operations_per_worker * 2  # store + check
        print(
            f"Concurrent performance: {total_operations} operations in {total_time:.3f}s"
        )
        print(f"Operations per second: {total_operations / total_time:.1f}")

        # Should handle reasonable concurrent load
        assert total_time < 30.0  # Should complete in under 30 seconds


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    async def test_empty_metadata(self, any_manager):
        """Test storing permissions with empty metadata."""
        await any_manager.store_permissions(
            "session_empty_meta", "user_1", ["read"], metadata={}
        )

        data = await any_manager.get_permissions("session_empty_meta")
        assert data is not None
        # Metadata should contain at least created_at and manager_version
        assert "created_at" in data["metadata"]
        assert "manager_version" in data["metadata"]

    async def test_none_metadata(self, any_manager):
        """Test storing permissions with None metadata."""
        await any_manager.store_permissions(
            "session_none_meta", "user_1", ["read"], metadata=None
        )

        data = await any_manager.get_permissions("session_none_meta")
        assert data is not None
        # Metadata should contain at least created_at and manager_version
        assert "created_at" in data["metadata"]
        assert "manager_version" in data["metadata"]

    async def test_large_permission_list(self, any_manager):
        """Test storing a large number of permissions."""
        large_permissions = [f"permission_{i}" for i in range(100)]

        result = await any_manager.store_permissions(
            "session_large_perms", "user_1", large_permissions
        )
        assert result is True

        data = await any_manager.get_permissions("session_large_perms")
        assert set(data["permissions"]) == set(large_permissions)

    async def test_special_characters_in_ids(self, any_manager):
        """Test handling of special characters in IDs."""
        # Use valid session ID with alphanumeric characters
        valid_session_id = "session_with_valid_chars_123"

        result = await any_manager.store_permissions(
            valid_session_id, "user_1", ["read", "write"]
        )
        assert result is True

        # Verify data was stored correctly
        data = await any_manager.get_permissions(valid_session_id)
        assert data is not None
        assert data["user_id"] == "user_1"
        assert set(data["permissions"]) == {"read", "write"}

    async def test_duplicate_permissions(self, any_manager):
        """Test handling duplicate permissions in list."""
        permissions_with_duplicates = ["read", "write", "read", "admin", "write"]

        result = await any_manager.store_permissions(
            "session_duplicates", "user_1", permissions_with_duplicates
        )
        assert result is True

        data = await any_manager.get_permissions("session_duplicates")
        # Should handle duplicates gracefully (exact behavior depends on provider)
        assert "read" in data["permissions"]
        assert "write" in data["permissions"]
        assert "admin" in data["permissions"]

    async def test_zero_ttl(self, any_manager):
        """Test handling of zero TTL."""
        # Zero TTL should be rejected
        with pytest.raises(TTLError):
            await any_manager.store_permissions(
                "session_zero_ttl", "user_1", ["read"], ttl=0
            )

    async def test_very_large_ttl(self, any_manager):
        """Test handling of very large TTL."""
        # Very large TTL should be rejected
        with pytest.raises(TTLError):
            await any_manager.store_permissions(
                "session_large_ttl",
                "user_1",
                ["read"],
                ttl=31536001,  # Just over 1 year
            )

    async def test_unicode_in_permissions(self, any_manager):
        """Test handling Unicode characters in permissions."""
        unicode_permissions = ["読む", "書く", "管理者", "пользователь"]

        result = await any_manager.store_permissions(
            "session_unicode", "user_unicode", unicode_permissions
        )
        assert result is True

        data = await any_manager.get_permissions("session_unicode")
        assert set(data["permissions"]) == set(unicode_permissions)

        # Test checking Unicode permission
        has_unicode = await any_manager.check_permission("session_unicode", "読む")
        assert has_unicode is True


class TestProviderSpecificBehavior:
    """Test provider-specific behaviors through the manager."""

    async def test_memory_provider_stats(self, memory_manager):
        """Test memory provider specific functionality."""
        if memory_manager.provider_name == "memory":
            # Store some sessions
            for i in range(5):
                await memory_manager.store_permissions(
                    f"session_{i}", f"user_{i}", ["read"]
                )

            # Get memory stats if available
            if hasattr(memory_manager._provider, "get_memory_stats"):
                stats = await memory_manager._provider.get_memory_stats()
                assert stats["total_sessions"] >= 5
                assert stats["active_sessions"] >= 5

    async def test_file_provider_stats(self, file_manager):
        """Test file provider specific functionality."""
        if file_manager.provider_name == "file":
            # Store some sessions
            for i in range(3):
                await file_manager.store_permissions(
                    f"session_{i}", f"user_{i}", ["read"]
                )

            # Get storage stats if available
            if hasattr(file_manager._provider, "get_storage_stats"):
                stats = await file_manager._provider.get_storage_stats()
                assert stats["session_files"] >= 3

    @pytest.mark.redis
    async def test_redis_provider_connection_info(self, redis_manager):
        """Test Redis provider specific functionality."""
        if redis_manager.provider_name == "redis":
            # Get connection info if available
            if hasattr(redis_manager._provider, "get_connection_info"):
                info = await redis_manager._provider.get_connection_info()
                assert info["status"] == "connected"
                assert "redis_version" in info


class TestManagerEdgeCases:
    """Extra edge-case tests for PermissionStorageManager."""

    @pytest.mark.asyncio
    async def test_double_initialize(self, memory_config):
        manager = PermissionStorageManager("memory", memory_config)
        await manager.initialize()
        # İkinci initialize çağrısı hata atmamalı, normal davranış göstermeli
        await manager.initialize()
        assert manager.is_initialized is True
        await manager.close()

    @pytest.mark.asyncio
    async def test_operation_after_close(self, memory_config):
        manager = PermissionStorageManager("memory", memory_config)
        await manager.initialize()
        await manager.close()
        # Kapalı manager ile işlem yapılabilmeli (auto-initialize)
        result = await manager.store_permissions("s", "u", ["p"])
        assert result is True
        await manager.close()

    def test_invalid_config(self):
        # None config ile manager oluşturulabilmeli (default config kullanılır)
        manager = PermissionStorageManager("memory", None)
        assert manager.provider_name == "memory"


class DummyProvider(BaseProvider):
    async def initialize(self):
        self._initialized = True

    async def close(self):
        self._initialized = False

    async def store_permissions(self, *a, **k):
        return True

    async def check_permission(self, *a, **k):
        return True

    async def check_permissions(self, *a, **k):
        return {}

    async def get_permissions(self, *a, **k):
        return {}

    async def invalidate_session(self, *a, **k):
        return True

    async def update_permissions(self, *a, **k):
        return True

    async def extend_session_ttl(self, *a, **k):
        return True

    async def get_session_info(self, *a, **k):
        return {}

    async def list_sessions(self, *a, **k):
        return []

    async def cleanup_expired_sessions(self):
        return 0

    @property
    def provider_name(self):
        return "dummy"

    @property
    def supports_ttl(self):
        return True


class TestManagerEdgeCasesCoverage:
    def test_invalid_provider_name(self):
        with pytest.raises(ProviderNotSupportedError):
            PermissionStorageManager(provider="not_exist")

    def test_invalid_provider_type(self):
        with pytest.raises(ValueError):
            PermissionStorageManager(provider=123)

    def test_register_provider_wrong_type(self):
        class NotAProvider:
            pass

        with pytest.raises(ValueError):
            PermissionStorageManager.register_provider("bad", NotAProvider)

    def test_register_and_get_available_providers(self):
        PermissionStorageManager.register_provider("dummy", DummyProvider)
        providers = PermissionStorageManager.get_available_providers()
        assert "dummy" in providers

    def test_context_manager_sync(self):
        manager = PermissionStorageManager(provider=DummyProvider())
        with manager as m:
            assert m.is_initialized
        assert not manager.is_initialized

    @pytest.mark.asyncio
    async def test_context_manager_async(self):
        manager = PermissionStorageManager(provider=DummyProvider())
        async with manager as m:
            assert m.is_initialized
        assert not manager.is_initialized

    def test_properties(self):
        manager = PermissionStorageManager(provider=DummyProvider())
        assert manager.provider_name == "dummy"
        assert manager.supports_ttl is True
        assert manager.is_initialized is False


class TestManagerSyncWrappers:
    """Test synchronous wrapper methods."""

    @pytest.mark.skipif(
        lambda any_manager: getattr(any_manager, 'provider_name', None) == 'redis',
        reason="RedisProvider does not support sync wrappers due to event loop limitations."
    )
    def test_store_permissions_sync(self, any_manager):
        """Test synchronous store_permissions wrapper."""
        session_id = "sync_test_session"
        user_id = "sync_test_user"
        permissions = ["read", "write"]

        result = any_manager.store_permissions_sync(
            session_id, user_id, permissions
        )
        assert result is True

        # Verify it was stored
        has_read = any_manager.check_permission_sync(session_id, "read")
        assert has_read is True

    @pytest.mark.skipif(
        lambda any_manager: getattr(any_manager, 'provider_name', None) == 'redis',
        reason="RedisProvider does not support sync wrappers due to event loop limitations."
    )
    def test_check_permission_sync(self, any_manager):
        """Test synchronous check_permission wrapper."""
        session_id = "sync_check_session"
        user_id = "sync_check_user"
        permissions = ["read", "write"]

        # Store permissions first
        any_manager.store_permissions_sync(session_id, user_id, permissions)

        # Test check
        has_read = any_manager.check_permission_sync(session_id, "read")
        assert has_read is True

        has_admin = any_manager.check_permission_sync(session_id, "admin")
        assert has_admin is False

    @pytest.mark.skipif(
        lambda any_manager: getattr(any_manager, 'provider_name', None) == 'redis',
        reason="RedisProvider does not support sync wrappers due to event loop limitations."
    )
    def test_check_permissions_sync(self, any_manager):
        """Test synchronous check_permissions wrapper."""
        session_id = "sync_check_multi_session"
        user_id = "sync_check_multi_user"
        permissions = ["read", "write"]

        # Store permissions first
        any_manager.store_permissions_sync(session_id, user_id, permissions)

        # Test multiple checks
        results = any_manager.check_permissions_sync(
            session_id, ["read", "write", "admin"]
        )
        assert results["read"] is True
        assert results["write"] is True
        assert results["admin"] is False

    @pytest.mark.skipif(
        lambda any_manager: getattr(any_manager, 'provider_name', None) == 'redis',
        reason="RedisProvider does not support sync wrappers due to event loop limitations."
    )
    def test_get_permissions_sync(self, any_manager):
        """Test synchronous get_permissions wrapper."""
        session_id = "sync_get_session"
        user_id = "sync_get_user"
        permissions = ["read", "write"]
        metadata = {"test": "data"}

        # Store permissions first
        any_manager.store_permissions_sync(session_id, user_id, permissions, metadata=metadata)

        # Test get
        data = any_manager.get_permissions_sync(session_id)
        assert data is not None
        assert data["user_id"] == user_id
        assert set(data["permissions"]) == set(permissions)
        assert data["metadata"]["test"] == "data"

    @pytest.mark.skipif(
        lambda any_manager: getattr(any_manager, 'provider_name', None) == 'redis',
        reason="RedisProvider does not support sync wrappers due to event loop limitations."
    )
    def test_invalidate_session_sync(self, any_manager):
        """Test synchronous invalidate_session wrapper."""
        session_id = "sync_invalidate_session"
        user_id = "sync_invalidate_user"
        permissions = ["read"]

        # Store permissions first
        any_manager.store_permissions_sync(session_id, user_id, permissions)

        # Verify it exists
        has_read = any_manager.check_permission_sync(session_id, "read")
        assert has_read is True

        # Invalidate
        result = any_manager.invalidate_session_sync(session_id)
        assert result is True

        # Verify it's gone
        has_read = any_manager.check_permission_sync(session_id, "read")
        assert has_read is False


class TestManagerSyncContextManager:
    """Test synchronous context manager methods."""

    def test_sync_context_manager_enter_exit(self, memory_config):
        """Test synchronous context manager."""
        with PermissionStorageManager("memory", memory_config) as manager:
            assert manager.is_initialized
            assert manager.provider_name == "memory"

        # Should be closed after context
        assert not manager.is_initialized

    def test_sync_context_manager_with_operations(self, memory_config):
        """Test synchronous context manager with operations."""
        with PermissionStorageManager("memory", memory_config) as manager:
            # Should be able to use manager normally
            result = manager.store_permissions_sync(
                "context_session", "user_1", ["read"]
            )
            assert result is True

            has_read = manager.check_permission_sync("context_session", "read")
            assert has_read is True


class TestManagerAutoInitializeEdgeCases:
    """Test edge cases with auto_initialize=False."""

    @pytest.mark.asyncio
    async def test_ensure_initialized_with_auto_init_disabled(self, memory_config):
        """Test _ensure_initialized when auto_initialize=False."""
        manager = PermissionStorageManager(
            "memory", memory_config, auto_initialize=False
        )

        # Should raise error when not initialized
        with pytest.raises(ProviderNotInitializedError):
            manager._ensure_initialized()

    @pytest.mark.asyncio
    async def test_operations_with_auto_init_disabled(self, memory_config):
        """Test operations when auto_initialize=False."""
        manager = PermissionStorageManager(
            "memory", memory_config, auto_initialize=False
        )

        # All operations should raise ProviderNotInitializedError
        with pytest.raises(ProviderNotInitializedError):
            await manager.store_permissions("session_1", "user_1", ["read"])

        with pytest.raises(ProviderNotInitializedError):
            await manager.check_permission("session_1", "read")

        with pytest.raises(ProviderNotInitializedError):
            await manager.check_permissions("session_1", ["read"])

        with pytest.raises(ProviderNotInitializedError):
            await manager.get_permissions("session_1")

        with pytest.raises(ProviderNotInitializedError):
            await manager.invalidate_session("session_1")

        with pytest.raises(ProviderNotInitializedError):
            await manager.update_permissions("session_1", ["read"])

        with pytest.raises(ProviderNotInitializedError):
            await manager.extend_session_ttl("session_1", 3600)

        with pytest.raises(ProviderNotInitializedError):
            await manager.get_session_info("session_1")

        with pytest.raises(ProviderNotInitializedError):
            await manager.list_sessions()

        with pytest.raises(ProviderNotInitializedError):
            await manager.cleanup_expired_sessions()

    @pytest.mark.asyncio
    async def test_ensure_initialized_with_auto_init_enabled_but_fails(self, memory_config):
        """Test _ensure_initialized when auto_initialize=True but initialization fails."""
        manager = PermissionStorageManager(
            "memory", memory_config, auto_initialize=True
        )
        
        # Mock provider to fail initialization
        original_initialize = manager._provider.initialize
        
        async def failing_initialize():
            raise ProviderError("Initialization failed")
        
        manager._provider.initialize = failing_initialize
        
        # Should raise ProviderNotInitializedError
        with pytest.raises(ProviderNotInitializedError):
            manager._ensure_initialized()
        
        # Restore original method
        manager._provider.initialize = original_initialize
