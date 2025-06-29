"""
Tests for Memory provider implementation.
"""

import asyncio
import json
import tempfile
import time
from datetime import datetime, timezone
from typing import Dict, List

import pytest
from unittest.mock import AsyncMock, patch

from permission_storage_manager.providers.memory_provider import MemoryProvider
from permission_storage_manager.core.exceptions import ProviderError


class TestMemoryProviderInitialization:
    """Test Memory provider initialization and configuration."""

    def test_memory_provider_creation(self, memory_config):
        """Test creating Memory provider with configuration."""
        provider = MemoryProvider(memory_config)
        assert provider.provider_name == "memory"
        assert provider.supports_ttl is True
        assert not provider.is_initialized

    def test_memory_provider_default_config(self):
        """Test Memory provider with default configuration."""
        provider = MemoryProvider()
        expected_defaults = {
            "cleanup_interval": 60,
            "max_sessions": 10000,
            "enable_monitoring": True,
        }

        for key, expected_value in expected_defaults.items():
            assert provider._config[key] == expected_value

    async def test_memory_provider_initialization(self, memory_provider):
        """Test Memory provider initialization."""
        assert memory_provider.is_initialized
        assert memory_provider._cleanup_task is not None
        assert memory_provider._monitoring_task is not None

    async def test_memory_provider_close(self, memory_config):
        """Test Memory provider cleanup."""
        provider = MemoryProvider(memory_config)
        await provider.initialize()

        assert provider.is_initialized
        assert len(provider._sessions) == 0

        await provider.close()
        assert not provider.is_initialized
        assert len(provider._sessions) == 0


class TestMemoryProviderOperations:
    """Test Memory provider core operations."""

    async def test_store_permissions_basic(self, memory_provider, sample_session_data):
        """Test basic permission storage in memory."""
        result = await memory_provider.store_permissions(
            sample_session_data["session_id"],
            sample_session_data["user_id"],
            sample_session_data["permissions"],
            metadata=sample_session_data["metadata"],
        )
        assert result is True

        # Verify data was stored
        assert sample_session_data["session_id"] in memory_provider._sessions
        stored_data = memory_provider._sessions[sample_session_data["session_id"]]
        assert stored_data["user_id"] == sample_session_data["user_id"]
        assert stored_data["permissions"] == sample_session_data["permissions"]
        assert stored_data["metadata"] == sample_session_data["metadata"]

    async def test_store_permissions_with_ttl(self, memory_provider):
        """Test storing permissions with TTL in memory."""
        session_id = "session_with_ttl"
        ttl = 3600

        result = await memory_provider.store_permissions(
            session_id, "user_1", ["read", "write"], ttl=ttl
        )
        assert result is True

        # Check TTL was set
        assert session_id in memory_provider._session_expiry
        expiry_time = memory_provider._session_expiry[session_id]
        expected_expiry = time.time() + ttl
        assert abs(expiry_time - expected_expiry) < 1.0  # Allow 1 second tolerance

    async def test_store_permissions_overwrite(self, memory_provider):
        """Test overwriting existing session data."""
        session_id = "overwrite_session"

        # Store initial data
        await memory_provider.store_permissions(session_id, "user_1", ["read"])
        assert memory_provider._sessions[session_id]["permissions"] == ["read"]

        # Overwrite with new data
        await memory_provider.store_permissions(
            session_id, "user_2", ["write", "admin"]
        )
        stored_data = memory_provider._sessions[session_id]
        assert stored_data["user_id"] == "user_2"
        assert stored_data["permissions"] == ["write", "admin"]

    async def test_check_permission_existing(
        self, memory_provider, sample_session_data
    ):
        """Test checking existing permission in memory."""
        # Store permissions first
        await memory_provider.store_permissions(
            sample_session_data["session_id"],
            sample_session_data["user_id"],
            sample_session_data["permissions"],
        )

        # Check existing permission
        has_read = await memory_provider.check_permission(
            sample_session_data["session_id"], "read"
        )
        assert has_read is True

        # Check non-existing permission
        has_super_admin = await memory_provider.check_permission(
            sample_session_data["session_id"], "super_admin"
        )
        assert has_super_admin is False

    async def test_check_permission_nonexistent_session(self, memory_provider):
        """Test checking permission for non-existent session."""
        has_perm = await memory_provider.check_permission("nonexistent", "read")
        assert has_perm is False

    async def test_check_permission_expired_session(self, memory_provider):
        """Test checking permission for expired session."""
        session_id = "expired_session"

        # Store session with very short TTL
        await memory_provider.store_permissions(session_id, "user_1", ["read"], ttl=1)

        # Should exist immediately
        has_read = await memory_provider.check_permission(session_id, "read")
        assert has_read is True

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Should be expired now
        has_read = await memory_provider.check_permission(session_id, "read")
        assert has_read is False

    async def test_check_permissions_multiple(
        self, memory_provider, sample_session_data
    ):
        """Test checking multiple permissions in memory."""
        # Store permissions first
        await memory_provider.store_permissions(
            sample_session_data["session_id"],
            sample_session_data["user_id"],
            sample_session_data["permissions"],
        )

        # Check multiple permissions
        to_check = ["read", "write", "admin", "delete", "super_admin"]
        results = await memory_provider.check_permissions(
            sample_session_data["session_id"], to_check
        )

        # Permissions that should exist
        assert results["read"] is True
        assert results["write"] is True
        assert results["admin"] is True
        # Permissions that should not exist
        assert results["delete"] is False
        assert results["super_admin"] is False

    async def test_get_permissions(self, memory_provider, sample_session_data):
        """Test getting all permissions from memory."""
        # Store permissions first
        await memory_provider.store_permissions(
            sample_session_data["session_id"],
            sample_session_data["user_id"],
            sample_session_data["permissions"],
            metadata=sample_session_data["metadata"],
        )

        # Get permissions
        data = await memory_provider.get_permissions(sample_session_data["session_id"])
        assert data is not None
        assert data["user_id"] == sample_session_data["user_id"]
        assert set(data["permissions"]) == set(sample_session_data["permissions"])
        assert data["metadata"] == sample_session_data["metadata"]
        assert "created_at" in data
        assert "updated_at" in data

    async def test_get_permissions_nonexistent(self, memory_provider):
        """Test getting permissions for non-existent session."""
        data = await memory_provider.get_permissions("nonexistent")
        assert data is None

    async def test_get_permissions_expired(self, memory_provider):
        """Test getting permissions for expired session."""
        session_id = "expired_get_session"

        # Store session with very short TTL
        await memory_provider.store_permissions(session_id, "user_1", ["read"], ttl=1)

        # Should exist immediately
        data = await memory_provider.get_permissions(session_id)
        assert data is not None

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Should be expired now
        data = await memory_provider.get_permissions(session_id)
        assert data is None

    async def test_invalidate_session(self, memory_provider, sample_session_data):
        """Test session invalidation in memory."""
        user_id = sample_session_data["user_id"]
        session_id = sample_session_data["session_id"]

        # Store permissions first
        await memory_provider.store_permissions(
            session_id, user_id, sample_session_data["permissions"]
        )

        # Verify session exists in both main storage and user index
        assert session_id in memory_provider._sessions
        assert session_id in memory_provider._user_sessions[user_id]

        # Invalidate session
        result = await memory_provider.invalidate_session(session_id)
        assert result is True

        # Verify session is gone from both places
        assert session_id not in memory_provider._sessions
        assert session_id not in memory_provider._user_sessions[user_id]

    async def test_invalidate_nonexistent_session(self, memory_provider):
        """Test invalidating non-existent session."""
        result = await memory_provider.invalidate_session("nonexistent")
        assert result is False

    async def test_update_permissions(self, memory_provider, sample_session_data):
        """Test updating permissions in memory."""
        # Store initial permissions
        await memory_provider.store_permissions(
            sample_session_data["session_id"], sample_session_data["user_id"], ["read"]
        )

        original_created_at = memory_provider._sessions[
            sample_session_data["session_id"]
        ]["created_at"]

        # Update permissions
        new_permissions = ["read", "write", "admin"]
        result = await memory_provider.update_permissions(
            sample_session_data["session_id"], new_permissions
        )
        assert result is True

        # Verify updated permissions
        stored_data = memory_provider._sessions[sample_session_data["session_id"]]
        assert stored_data["permissions"] == new_permissions
        assert stored_data["created_at"] == original_created_at  # Should not change
        assert "updated_at" in stored_data  # Should be updated

    async def test_update_nonexistent_session(self, memory_provider):
        """Test updating permissions for non-existent session."""
        result = await memory_provider.update_permissions("nonexistent", ["read"])
        assert result is False

    async def test_update_expired_session(self, memory_provider):
        """Test updating permissions for expired session."""
        session_id = "expired_update_session"

        # Store session with very short TTL
        await memory_provider.store_permissions(session_id, "user_1", ["read"], ttl=1)

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Try to update expired session
        result = await memory_provider.update_permissions(session_id, ["write"])
        assert result is False

    async def test_extend_session_ttl(self, memory_provider):
        """Test extending session TTL in memory."""
        session_id = "extend_ttl_session"

        # Store session with TTL
        await memory_provider.store_permissions(session_id, "user_1", ["read"], ttl=10)

        original_expiry = memory_provider._session_expiry[session_id]

        # Extend TTL
        new_ttl = 3600
        result = await memory_provider.extend_session_ttl(session_id, new_ttl)
        assert result is True

        # Check TTL was extended
        new_expiry = memory_provider._session_expiry[session_id]
        assert new_expiry > original_expiry
        expected_expiry = time.time() + new_ttl
        assert abs(new_expiry - expected_expiry) < 1.0  # Allow 1 second tolerance

    async def test_extend_ttl_nonexistent_session(self, memory_provider):
        """Test extending TTL for non-existent session."""
        result = await memory_provider.extend_session_ttl("nonexistent", 3600)
        assert result is False

    async def test_extend_ttl_expired_session(self, memory_provider):
        """Test extending TTL for expired session."""
        session_id = "expired_extend_session"

        # Store session with very short TTL
        await memory_provider.store_permissions(session_id, "user_1", ["read"], ttl=1)

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Try to extend TTL of expired session
        result = await memory_provider.extend_session_ttl(session_id, 3600)
        assert result is False


class TestMemoryProviderSessionManagement:
    """Test Memory provider session management features."""

    async def test_get_session_info(self, memory_provider, sample_session_data):
        """Test getting session information from memory."""
        # Store session with TTL
        await memory_provider.store_permissions(
            sample_session_data["session_id"],
            sample_session_data["user_id"],
            sample_session_data["permissions"],
            ttl=3600,
            metadata=sample_session_data["metadata"],
        )

        # Get session info
        info = await memory_provider.get_session_info(sample_session_data["session_id"])
        assert info is not None
        assert info["user_id"] == sample_session_data["user_id"]
        assert info["has_ttl"] is True
        assert info["ttl_remaining"] > 0
        assert info["ttl_remaining"] <= 3600
        assert info["provider"] == "memory"

    async def test_get_session_info_no_ttl(self, memory_provider):
        """Test getting session info for session without TTL."""
        session_id = "session_no_ttl"

        # Store session without TTL
        await memory_provider.store_permissions(session_id, "user_1", ["read"])

        # Get session info
        info = await memory_provider.get_session_info(session_id)
        assert info is not None
        assert info["has_ttl"] is False
        assert info["ttl_remaining"] is None

    async def test_list_sessions_all(self, memory_provider, multiple_sessions):
        """Test listing all sessions from memory."""
        # Store multiple sessions
        for session in multiple_sessions[:5]:
            await memory_provider.store_permissions(
                session["session_id"], session["user_id"], session["permissions"]
            )

        # List all sessions
        sessions = await memory_provider.list_sessions()
        assert len(sessions) >= 5

        # Verify session IDs are returned
        stored_session_ids = [s["session_id"] for s in multiple_sessions[:5]]
        for session_id in stored_session_ids:
            assert session_id in sessions

    async def test_list_sessions_by_user(self, memory_provider, multiple_sessions):
        """Test listing sessions by user ID from memory."""
        # Store sessions for multiple users
        for session in multiple_sessions[:6]:
            await memory_provider.store_permissions(
                session["session_id"], session["user_id"], session["permissions"]
            )

        # List sessions for specific user
        user_sessions = await memory_provider.list_sessions(user_id="user_0")

        # Should contain sessions for user_0 (sessions 0 and 3 based on modulo logic)
        assert len(user_sessions) >= 1

        # Verify sessions belong to correct user
        for session_id in user_sessions:
            assert session_id in memory_provider._user_sessions["user_0"]

    async def test_list_sessions_pagination(self, memory_provider, multiple_sessions):
        """Test session listing pagination."""
        # Store multiple sessions
        for session in multiple_sessions:
            await memory_provider.store_permissions(
                session["session_id"], session["user_id"], session["permissions"]
            )

        # Test limit
        limited_sessions = await memory_provider.list_sessions(limit=3)
        assert len(limited_sessions) <= 3

        # Test offset
        all_sessions = await memory_provider.list_sessions()
        offset_sessions = await memory_provider.list_sessions(limit=3, offset=2)
        assert len(offset_sessions) <= 3

        # Offset sessions should be different from first 3
        first_three = all_sessions[:3]
        assert set(offset_sessions) != set(first_three)

    async def test_list_sessions_excludes_expired(self, memory_provider):
        """Test that list_sessions excludes expired sessions."""
        # Store some sessions, some with very short TTL
        await memory_provider.store_permissions("session_1", "user_1", ["read"])
        await memory_provider.store_permissions("session_2", "user_2", ["read"], ttl=1)
        await memory_provider.store_permissions("session_3", "user_3", ["read"])

        # Initially all should be listed
        sessions = await memory_provider.list_sessions()
        assert len(sessions) >= 3

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Expired session should not be listed
        sessions = await memory_provider.list_sessions()
        assert "session_1" in sessions
        assert "session_2" not in sessions  # Expired
        assert "session_3" in sessions

    async def test_cleanup_expired_sessions(self, memory_provider):
        """Test cleanup of expired sessions."""
        import time

        # Store sessions with different TTLs
        await memory_provider.store_permissions("session_permanent", "user_1", ["read"])
        await memory_provider.store_permissions(
            "session_short", "user_2", ["read"], ttl=0.5
        )
        await memory_provider.store_permissions(
            "session_medium", "user_3", ["read"], ttl=10
        )

        # Debug: Check expiry time
        current_time = time.time()
        expiry_time = memory_provider._session_expiry.get("session_short")
        print(f"DEBUG: Current time: {current_time}")
        print(f"DEBUG: Session short expiry time: {expiry_time}")
        print(
            f"DEBUG: Time until expiry: {expiry_time - current_time if expiry_time else 'N/A'}"
        )

        # Assert session_short is in expiry dict
        assert "session_short" in memory_provider._session_expiry

        # Wait for some to expire
        await asyncio.sleep(1.2)

        # Debug: Check if expired
        current_time = time.time()
        is_expired = memory_provider._is_expired("session_short")
        print(f"DEBUG: After sleep - Current time: {current_time}")
        print(
            f"DEBUG: Session short expiry time: {memory_provider._session_expiry.get('session_short')}"
        )
        print(f"DEBUG: Is expired: {is_expired}")

        # Retry cleanup up to 3 times (race condition toleransı)
        cleaned = 0
        for i in range(3):
            cleaned = await memory_provider.cleanup_expired_sessions()
            print(f"DEBUG: Cleanup attempt {i+1}, cleaned: {cleaned}")
            if cleaned >= 1:
                break
            await asyncio.sleep(0.2)
        assert cleaned >= 1  # At least the short TTL session

        # Verify expired session is gone
        data = await memory_provider.get_permissions("session_short")
        assert data is None

        # Verify non-expired sessions remain
        data = await memory_provider.get_permissions("session_permanent")
        assert data is not None
        data = await memory_provider.get_permissions("session_medium")
        assert data is not None


class TestMemoryProviderAdvancedFeatures:
    """Test Memory provider advanced features."""

    async def test_user_session_indexing(self, memory_provider):
        """Test user session indexing functionality."""
        user_id = "indexed_user"
        session_ids = ["session_1", "session_2", "session_3"]

        # Store multiple sessions for the same user
        for session_id in session_ids:
            await memory_provider.store_permissions(session_id, user_id, ["read"])

        # Check user index
        assert user_id in memory_provider._user_sessions
        indexed_sessions = memory_provider._user_sessions[user_id]

        # All sessions should be indexed
        for session_id in session_ids:
            assert session_id in indexed_sessions

        # Invalidate one session
        await memory_provider.invalidate_session("session_1")

        # Check index was updated
        indexed_sessions = memory_provider._user_sessions[user_id]
        assert "session_1" not in indexed_sessions
        assert "session_2" in indexed_sessions
        assert "session_3" in indexed_sessions

    async def test_storage_limits(self, memory_config):
        """Test storage limit enforcement."""
        # Create provider with low session limit
        config = {**memory_config, "max_sessions": 3}
        provider = MemoryProvider(config)
        await provider.initialize()

        try:
            # Store up to the limit
            for i in range(3):
                result = await provider.store_permissions(
                    f"session_{i}", f"user_{i}", ["read"]
                )
                assert result is True

            # Exceeding limit should raise error
            with pytest.raises(ProviderError, match="Maximum session limit reached"):
                await provider.store_permissions(
                    "session_overflow", "user_overflow", ["read"]
                )

        finally:
            await provider.close()

    async def test_storage_limits_overwrite_allowed(self, memory_config):
        """Test that overwriting existing sessions doesn't count against limit."""
        # Create provider with low session limit
        config = {**memory_config, "max_sessions": 2}
        provider = MemoryProvider(config)
        await provider.initialize()

        try:
            # Store up to the limit
            await provider.store_permissions("session_1", "user_1", ["read"])
            await provider.store_permissions("session_2", "user_2", ["read"])

            # Overwriting existing session should work
            result = await provider.store_permissions("session_1", "user_1", ["write"])
            assert result is True

        finally:
            await provider.close()

    async def test_memory_stats(self, memory_provider):
        """Test getting memory provider statistics."""
        # Store some test data
        for i in range(5):
            await memory_provider.store_permissions(
                f"stats_session_{i}", f"user_{i}", ["read"]
            )

        # Get stats
        stats = await memory_provider.get_memory_stats()

        assert stats["provider"] == "memory"
        assert stats["total_sessions"] >= 5
        assert stats["active_sessions"] >= 5
        assert stats["unique_users"] >= 5
        assert stats["total_sessions_created"] >= 5
        assert "uptime_seconds" in stats
        assert "total_operations" in stats

    async def test_thread_safety(self, memory_provider):
        """Test thread safety of memory provider operations."""
        import threading
        import queue

        results = queue.Queue()

        def worker(worker_id):
            """Worker function to test concurrent access."""
            try:
                # Use sync methods to test from threads
                for i in range(10):
                    session_id = f"thread_{worker_id}_session_{i}"
                    result = memory_provider.store_permissions_sync(
                        session_id, f"user_{worker_id}", ["read"]
                    )
                    results.put(("store", result))

                    has_read = memory_provider.check_permission_sync(session_id, "read")
                    results.put(("check", has_read))
            except Exception as e:
                results.put(("error", str(e)))

        # Start multiple threads
        threads = []
        for i in range(3):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Check results
        success_count = 0
        error_count = 0

        while not results.empty():
            operation, result = results.get()
            if operation == "error":
                error_count += 1
                print(f"Thread error: {result}")
            else:
                if result:
                    success_count += 1

        # Should have mostly successful operations
        assert error_count == 0  # No errors expected
        assert success_count >= 30  # 3 threads * 10 operations * 2 operations each

    async def test_clear_all_sessions(self, memory_provider):
        """Test clearing all sessions from memory."""
        # Store some test sessions
        session_ids = ["clear_session_1", "clear_session_2", "clear_session_3"]
        for session_id in session_ids:
            await memory_provider.store_permissions(session_id, "user_1", ["read"])

        # Verify sessions exist
        assert len(memory_provider._sessions) >= 3

        # Clear all sessions
        count = await memory_provider.clear_all_sessions()
        assert count >= 3

        # Verify sessions are gone
        assert len(memory_provider._sessions) == 0
        assert len(memory_provider._user_sessions) == 0
        assert len(memory_provider._session_expiry) == 0

        for session_id in session_ids:
            data = await memory_provider.get_permissions(session_id)
            assert data is None


class TestMemoryProviderBackgroundTasks:
    """Test Memory provider background task functionality."""

    async def test_background_cleanup_task(self, memory_config):
        """Test background cleanup task functionality."""
        # Create provider with fast cleanup interval
        config = {**memory_config, "cleanup_interval": 0.5}
        provider = MemoryProvider(config)
        await provider.initialize()

        try:
            # Store session with short TTL
            await provider.store_permissions(
                "auto_cleanup_session", "user_1", ["read"], ttl=1
            )

            # Session should exist initially
            data = await provider.get_permissions("auto_cleanup_session")
            assert data is not None

            # Wait for expiration and cleanup
            await asyncio.sleep(1.5)  # Wait for expiration + cleanup cycle

            # Session should be automatically cleaned up
            data = await provider.get_permissions("auto_cleanup_session")
            assert data is None

            # Check that session was removed from internal storage
            assert "auto_cleanup_session" not in provider._sessions

        finally:
            await provider.close()

    async def test_monitoring_task(self, memory_config):
        """Test monitoring task functionality."""
        # Create provider with monitoring enabled
        config = {**memory_config, "enable_monitoring": True}
        provider = MemoryProvider(config)
        await provider.initialize()

        try:
            # Store some sessions to trigger monitoring
            for i in range(10):
                await provider.store_permissions(
                    f"monitor_session_{i}", "user_1", ["read"]
                )

            # Get initial stats
            initial_stats = await provider.get_memory_stats()
            initial_peak = initial_stats["peak_session_count"]

            # Add more sessions
            for i in range(10, 20):
                await provider.store_permissions(
                    f"monitor_session_{i}", "user_1", ["read"]
                )

            # Wait a bit for monitoring to update
            await asyncio.sleep(0.1)

            # Check that peak was updated
            updated_stats = await provider.get_memory_stats()
            assert updated_stats["peak_session_count"] >= initial_peak

        finally:
            await provider.close()

    async def test_monitoring_disabled(self, memory_config):
        """Test provider with monitoring disabled."""
        # Create provider with monitoring disabled
        config = {**memory_config, "enable_monitoring": False}
        provider = MemoryProvider(config)
        await provider.initialize()

        try:
            # Should not have monitoring task
            assert provider._monitoring_task is None

            # But should still be able to get stats
            stats = await provider.get_memory_stats()
            assert stats["provider"] == "memory"

        finally:
            await provider.close()


class TestMemoryProviderErrorHandling:
    """Test Memory provider error handling scenarios."""

    async def test_operation_after_close(self, memory_config):
        """Test operations after provider is closed."""
        provider = MemoryProvider(memory_config)
        await provider.initialize()
        await provider.close()

        # Operations should raise errors or return appropriate values
        with pytest.raises(Exception):
            await provider.store_permissions("session_1", "user_1", ["read"])

    async def test_double_initialization(self, memory_config):
        """Test double initialization handling."""
        provider = MemoryProvider(memory_config)
        await provider.initialize()

        try:
            # Second initialization should be safe
            await provider.initialize()
            assert provider.is_initialized

        finally:
            await provider.close()

    async def test_double_close(self, memory_config):
        """Test double close handling."""
        provider = MemoryProvider(memory_config)
        await provider.initialize()

        # First close
        await provider.close()
        assert not provider.is_initialized

        # Second close should be safe
        await provider.close()
        assert not provider.is_initialized

    async def test_concurrent_cleanup_operations(self, memory_provider):
        """Test concurrent cleanup operations."""
        # Store sessions with various TTLs
        await memory_provider.store_permissions(
            "concurrent_1", "user_1", ["read"], ttl=1
        )
        await memory_provider.store_permissions(
            "concurrent_2", "user_2", ["read"], ttl=2
        )
        await memory_provider.store_permissions("concurrent_3", "user_3", ["read"])

        # Run multiple cleanup operations concurrently
        cleanup_tasks = [
            memory_provider.cleanup_expired_sessions(),
            memory_provider.cleanup_expired_sessions(),
            memory_provider.cleanup_expired_sessions(),
        ]

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Run concurrent cleanups
        results = await asyncio.gather(*cleanup_tasks, return_exceptions=True)

        # Should not raise exceptions
        for result in results:
            assert not isinstance(result, Exception)
            assert isinstance(result, int)


class TestMemoryProviderPerformance:
    """Test Memory provider performance characteristics."""

    @pytest.mark.slow
    async def test_bulk_operations_performance(self, memory_provider, performance_data):
        """Test Memory provider performance with bulk operations."""
        import time

        # Measure store operations
        start_time = time.time()
        for session_data in performance_data:
            await memory_provider.store_permissions(
                session_data["session_id"],
                session_data["user_id"],
                session_data["permissions"],
            )
        store_time = time.time() - start_time

        # Measure read operations
        start_time = time.time()
        for session_data in performance_data:
            await memory_provider.get_permissions(session_data["session_id"])
        read_time = time.time() - start_time

        print(
            f"Memory store time for {len(performance_data)} sessions: {store_time:.3f}s"
        )
        print(
            f"Memory read time for {len(performance_data)} sessions: {read_time:.3f}s"
        )

        # Memory should be very fast
        assert store_time < 1.0  # Should complete in under 1 second
        assert read_time < 0.5  # Should complete in under 0.5 seconds

    @pytest.mark.slow
    async def test_memory_usage_growth(self, memory_provider):
        """Test memory usage growth characteristics."""
        import sys

        # Get initial memory usage
        initial_sessions = len(memory_provider._sessions)

        # Store many sessions
        num_sessions = 1000
        for i in range(num_sessions):
            await memory_provider.store_permissions(
                f"mem_test_session_{i}",
                f"user_{i % 10}",
                [f"permission_{j}" for j in range(5)],
            )

        # Check session count
        final_sessions = len(memory_provider._sessions)
        assert final_sessions == initial_sessions + num_sessions

        # Get memory stats
        stats = await memory_provider.get_memory_stats()
        assert stats["total_sessions"] >= num_sessions
        assert stats["unique_users"] >= 10

    @pytest.mark.slow
    async def test_cleanup_performance(self, memory_provider):
        """Test cleanup performance with many expired sessions."""
        import time

        # Store many sessions with short TTL
        num_sessions = 500
        for i in range(num_sessions):
            await memory_provider.store_permissions(
                f"cleanup_perf_session_{i}", f"user_{i}", ["read"], ttl=1
            )

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Measure cleanup time
        start_time = time.time()
        cleaned = await memory_provider.cleanup_expired_sessions()
        cleanup_time = time.time() - start_time

        print(f"Cleanup time for {cleaned} expired sessions: {cleanup_time:.3f}s")

        # Should be reasonably fast
        assert cleanup_time < 5.0
        assert cleaned >= num_sessions


class TestMemoryProviderEdgeCases:
    """Test Memory provider edge cases and boundary conditions."""

    async def test_session_data_isolation(self, memory_provider):
        """Test that session data is properly isolated."""
        # Store session with mutable data
        permissions = ["read", "write"]
        metadata = {"list": [1, 2, 3], "dict": {"a": 1}}

        await memory_provider.store_permissions(
            "isolation_session", "user_1", permissions, metadata=metadata
        )

        # Modify original data
        permissions.append("admin")
        metadata["list"].append(4)
        metadata["dict"]["b"] = 2

        # Retrieved data should not be affected
        data = await memory_provider.get_permissions("isolation_session")
        assert data["permissions"] == ["read", "write"]  # Original data
        assert data["metadata"]["list"] == [1, 2, 3]  # Original data
        assert "b" not in data["metadata"]["dict"]  # Original data

    async def test_zero_cleanup_interval(self, memory_config):
        """Test behavior with zero cleanup interval."""
        # This should be handled gracefully (probably disable background cleanup)
        config = {**memory_config, "cleanup_interval": 0}
        provider = MemoryProvider(config)

        # Should initialize without error
        await provider.initialize()

        try:
            # Should still work for basic operations
            await provider.store_permissions("zero_cleanup", "user_1", ["read"])
            data = await provider.get_permissions("zero_cleanup")
            assert data is not None

        finally:
            await provider.close()

    async def test_very_large_permission_list(self, memory_provider):
        """Test storing very large permission lists."""
        # Create a large permission list
        large_permissions = [f"permission_{i}" for i in range(10000)]

        result = await memory_provider.store_permissions(
            "large_perms_session", "user_1", large_permissions
        )
        assert result is True

        # Retrieve and verify
        data = await memory_provider.get_permissions("large_perms_session")
        assert set(data["permissions"]) == set(large_permissions)

    async def test_unicode_handling(self, memory_provider):
        """Test Unicode character handling."""
        unicode_session_id = "unicode_测试_session"
        unicode_user_id = "user_пользователь"
        unicode_permissions = ["读取", "写入", "管理员", "пользователь"]
        unicode_metadata = {
            "description": "Unicode test with 中文 and русский",
            "location": "東京",
        }

        result = await memory_provider.store_permissions(
            unicode_session_id,
            unicode_user_id,
            unicode_permissions,
            metadata=unicode_metadata,
        )
        assert result is True

        # Retrieve and verify Unicode handling
        data = await memory_provider.get_permissions(unicode_session_id)
        assert data["user_id"] == unicode_user_id
        assert set(data["permissions"]) == set(unicode_permissions)
        assert data["metadata"] == unicode_metadata

    async def test_concurrent_session_access(self, memory_provider):
        """Test concurrent access to the same session."""
        session_id = "concurrent_access_session"

        # Store initial session
        await memory_provider.store_permissions(session_id, "user_1", ["read"])

        async def update_permissions():
            return await memory_provider.update_permissions(
                session_id, ["read", "write"]
            )

        async def check_permissions():
            return await memory_provider.check_permission(session_id, "read")

        async def get_permissions():
            return await memory_provider.get_permissions(session_id)

        # Run concurrent operations
        tasks = [
            update_permissions(),
            check_permissions(),
            get_permissions(),
            check_permissions(),
            update_permissions(),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Should not raise exceptions due to thread safety
        for result in results:
            assert not isinstance(result, Exception)


class TestMemoryProviderContextManager:
    """Test Memory provider context manager functionality."""

    async def test_async_context_manager(self, memory_config):
        """Test Memory provider as async context manager."""
        async with MemoryProvider(memory_config) as provider:
            assert provider.is_initialized

            # Should be able to use provider normally
            await provider.store_permissions("context_session", "user_1", ["read"])
            has_read = await provider.check_permission("context_session", "read")
            assert has_read is True

        # Should be closed after context
        assert not provider.is_initialized

    def test_sync_context_manager(self, memory_config):
        """Test Memory provider as sync context manager."""
        with MemoryProvider(memory_config) as provider:
            assert provider.is_initialized

            # Should be able to use provider normally
            result = provider.store_permissions_sync(
                "sync_context_session", "user_1", ["read"]
            )
            assert result is True

            has_read = provider.check_permission_sync("sync_context_session", "read")
            assert has_read is True

        # Should be closed after context
        assert not provider.is_initialized
