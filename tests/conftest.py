"""
Pytest configuration and shared fixtures for Permission Storage Manager tests.
"""

import asyncio
import json
import os
import tempfile
import shutil
from typing import List

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

try:
    import redis.asyncio as redis
except ImportError:
    redis = None

# Import the package components
from permission_storage_manager import (
    PermissionStorageManager,
    RedisProvider,
    MemoryProvider,
    FileProvider,
    create_manager,
)


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "redis: marks tests that require Redis")
    config.addinivalue_line("markers", "file: marks tests that require file system")


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# Test data fixtures
@pytest.fixture
def sample_permissions():
    """Sample permissions for testing."""
    return ["read", "write", "delete", "admin", "user:create", "post:edit"]


@pytest.fixture
def sample_session_data():
    """Sample session data for testing."""
    return {
        "session_id": "test_session_123",
        "user_id": "test_user_456",
        "permissions": ["read", "write", "admin"],
        "metadata": {
            "ip_address": "192.168.1.100",
            "user_agent": "test-agent",
            "login_time": "2024-01-01T10:00:00Z",
        },
    }


@pytest.fixture
def multiple_sessions():
    """Multiple sample sessions for testing."""
    return [
        {
            "session_id": f"session_{i}",
            "user_id": f"user_{i % 3}",  # 3 different users
            "permissions": ["read", "write"] if i % 2 == 0 else ["read"],
            "metadata": {"test_index": i},
        }
        for i in range(10)
    ]


# Provider configuration fixtures
@pytest.fixture
def memory_config():
    """Configuration for memory provider testing."""
    return {
        "cleanup_interval": 60,  # Disable background cleanup during tests
        "max_sessions": 1000,
        "enable_monitoring": True,
    }


@pytest.fixture
def file_config():
    """Configuration for file provider testing."""
    temp_dir = tempfile.mkdtemp(prefix="psm_test_")
    config = {
        "storage_dir": temp_dir,
        "cleanup_interval": 60,  # High interval for testing to avoid interference
        "enable_backup": True,
        "max_backup_files": 3,
        "atomic_writes": True,
    }

    yield config

    # Teardown
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)


@pytest.fixture
def redis_config():
    """Configuration for Redis provider testing."""
    return {
        "url": "redis://localhost:6379/15",  # Use DB 15 for testing
        "socket_timeout": 2.0,
        "health_check_interval": 5,
        "key_prefix": "test_psm:",
    }


# Provider instance fixtures
@pytest.fixture
async def memory_provider(memory_config):
    """Create and initialize memory provider for testing."""
    provider = MemoryProvider(memory_config)
    await provider.initialize()
    yield provider
    await provider.close()


@pytest.fixture
async def file_provider(file_config):
    """Create and initialize file provider for testing."""
    provider = FileProvider(file_config)
    await provider.initialize()
    yield provider
    await provider.close()


@pytest.fixture
async def redis_provider(redis_config):
    """Create and initialize Redis provider for testing."""
    # Check if Redis is available
    try:
        test_redis = redis.from_url(redis_config["url"])
        await test_redis.ping()
        await test_redis.aclose()
    except Exception:
        pytest.skip("Redis not available for testing")

    provider = RedisProvider(redis_config)
    await provider.initialize()

    # Clean up any existing test data
    await provider.flush_all_sessions()

    yield provider

    # Cleanup after test
    try:
        await provider.flush_all_sessions()
        await provider.close()
    except Exception:
        pass  # Ignore cleanup errors


# Manager instance fixtures
@pytest.fixture
async def memory_manager(memory_config):
    """Create memory-based manager for testing."""
    manager = PermissionStorageManager("memory", memory_config)
    await manager.initialize()
    yield manager
    await manager.close()


@pytest.fixture
async def file_manager(file_config):
    """Create file-based manager for testing."""
    manager = PermissionStorageManager("file", file_config)
    await manager.initialize()
    yield manager
    await manager.close()


@pytest.fixture
async def redis_manager(redis_config):
    """Create Redis-based manager for testing."""
    # Check if Redis is available
    try:
        test_redis = redis.from_url(redis_config["url"])
        await test_redis.ping()
        await test_redis.aclose()
    except Exception:
        pytest.skip("Redis not available for testing")

    manager = PermissionStorageManager("redis", redis_config)
    await manager.initialize()

    # Clean up any existing test data
    if hasattr(manager._provider, "flush_all_sessions"):
        await manager._provider.flush_all_sessions()

    yield manager

    # Cleanup after test
    try:
        if hasattr(manager._provider, "flush_all_sessions"):
            await manager._provider.flush_all_sessions()
        await manager.close()
    except Exception:
        pass


# Parametrized fixtures for testing all providers
@pytest.fixture(params=["memory", "file", "redis"])
async def any_provider(request, memory_provider, file_provider, redis_provider):
    """Parametrized fixture to test all providers."""
    provider_map = {
        "memory": memory_provider,
        "file": file_provider,
        "redis": redis_provider,
    }
    return provider_map[request.param]


@pytest.fixture(params=["memory", "file", "redis"])
async def any_manager(request, memory_manager, file_manager, redis_manager):
    """Parametrized fixture to test all managers."""
    manager_map = {
        "memory": memory_manager,
        "file": file_manager,
        "redis": redis_manager,
    }
    return manager_map[request.param]


# Mock fixtures
@pytest.fixture
def mock_provider():
    """Create a mock provider for testing."""
    mock = AsyncMock()
    mock.provider_name = "mock"
    mock.supports_ttl = True
    mock.is_initialized = True

    # Configure common return values
    mock.store_permissions.return_value = True
    mock.check_permission.return_value = True
    mock.check_permissions.return_value = {"read": True, "write": False}
    mock.get_permissions.return_value = {
        "user_id": "test_user",
        "permissions": ["read", "write"],
        "created_at": "2024-01-01T10:00:00Z",
        "metadata": {},
    }
    mock.invalidate_session.return_value = True
    mock.update_permissions.return_value = True
    mock.extend_session_ttl.return_value = True
    mock.list_sessions.return_value = ["session_1", "session_2"]
    mock.cleanup_expired_sessions.return_value = 0

    return mock


@pytest.fixture
def mock_redis():
    """Create a mock Redis client for testing."""
    mock = AsyncMock()

    # Configure Redis-like behavior
    mock.ping.return_value = True
    mock.set.return_value = True
    mock.setex.return_value = True
    mock.get.return_value = '{"test": "data"}'
    mock.delete.return_value = 1
    mock.expire.return_value = True
    mock.ttl.return_value = 3600
    mock.keys.return_value = ["test:session:1", "test:session:2"]
    mock.sadd.return_value = 1
    mock.srem.return_value = 1
    mock.smembers.return_value = {"session_1", "session_2"}

    return mock


# Performance testing fixtures
@pytest.fixture
def performance_config():
    """Configuration for performance testing."""
    return {
        "num_sessions": 100,
        "num_permissions": 10,
        "num_operations": 1000,
        "concurrent_operations": 10,
    }


@pytest.fixture
async def performance_data(performance_config):
    """Generate performance test data."""
    sessions = []
    for i in range(performance_config["num_sessions"]):
        permissions = [
            f"perm_{j}" for j in range(performance_config["num_permissions"])
        ]
        session_data = {
            "session_id": f"perf_session_{i}",
            "user_id": f"perf_user_{i % 10}",  # 10 different users
            "permissions": permissions,
            "metadata": {"test_type": "performance", "index": i},
        }
        sessions.append(session_data)

    return sessions


# Integration test fixtures
@pytest.fixture
async def integration_setup():
    """Setup for integration tests."""
    # Create multiple managers with different providers
    managers = {}

    # Memory manager (always available)
    memory_manager = create_manager("memory", {"max_sessions": 1000})
    await memory_manager.initialize()
    managers["memory"] = memory_manager

    # File manager
    temp_dir = tempfile.mkdtemp(prefix="psm_integration_")
    file_manager = create_manager("file", {"storage_dir": temp_dir})
    await file_manager.initialize()
    managers["file"] = file_manager

    # Redis manager (if available)
    try:
        test_redis = redis.from_url("redis://localhost:6379/14")
        await test_redis.ping()
        await test_redis.aclose()

        redis_manager = create_manager(
            "redis",
            {"url": "redis://localhost:6379/14", "key_prefix": "integration_test:"},
        )
        await redis_manager.initialize()
        managers["redis"] = redis_manager
    except Exception:
        pass  # Redis not available

    yield managers

    # Cleanup
    for manager in managers.values():
        try:
            if hasattr(manager._provider, "flush_all_sessions"):
                await manager._provider.flush_all_sessions()
            await manager.close()
        except Exception:
            pass

    # Cleanup file directory
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)


# Utility functions for tests
@pytest.fixture
def assert_helpers():
    """Helper functions for assertions in tests."""

    class AssertHelpers:
        @staticmethod
        def assert_session_data_equal(actual, expected, ignore_timestamps=True):
            """Assert that session data matches expected values."""
            assert actual["user_id"] == expected["user_id"]
            assert set(actual["permissions"]) == set(expected["permissions"])
            assert actual["metadata"] == expected.get("metadata", {})

            if not ignore_timestamps:
                assert "created_at" in actual
                assert "updated_at" in actual

        @staticmethod
        def assert_permissions_result(result, expected_permissions):
            """Assert that permissions check result is correct."""
            assert isinstance(result, dict)
            for perm, expected in expected_permissions.items():
                assert result[perm] == expected

        @staticmethod
        async def assert_session_not_found(provider, session_id):
            """Assert that a session is not found."""
            data = await provider.get_permissions(session_id)
            assert data is None

            has_perm = await provider.check_permission(session_id, "any_permission")
            assert has_perm is False

    return AssertHelpers()


# Error injection fixtures for testing error handling
@pytest.fixture
def error_injector():
    """Helper for injecting errors during testing."""

    class ErrorInjector:
        def __init__(self):
            self.should_fail = False
            self.failure_count = 0
            self.max_failures = 1

        def enable_failures(self, max_failures=1):
            """Enable error injection."""
            self.should_fail = True
            self.failure_count = 0
            self.max_failures = max_failures

        def disable_failures(self):
            """Disable error injection."""
            self.should_fail = False
            self.failure_count = 0

        def maybe_fail(self, exception_class=Exception, message="Injected error"):
            """Raise an exception if failures are enabled."""
            if self.should_fail and self.failure_count < self.max_failures:
                self.failure_count += 1
                raise exception_class(message)

    return ErrorInjector()


# Cleanup fixture
@pytest.fixture(autouse=True)
async def cleanup_after_test():
    """Automatic cleanup after each test."""
    yield

    # Force garbage collection to help with resource cleanup
    import gc

    gc.collect()

    # Small delay to allow async cleanup to complete
    await asyncio.sleep(0.01)
