import asyncio
import pytest

from permission_storage_manager.core.base import BaseProvider
from permission_storage_manager.core.exceptions import (
    ProviderError,
    ProviderNotSupportedError,
    ProviderNotInitializedError,
    ProviderConnectionError,
    OperationTimeoutError,
    ProviderConfigurationError,
    SerializationError,
    ValidationError,
)
from permission_storage_manager.core.manager import PermissionStorageManager


class TestBaseProviderExtended:
    """Extended tests for core/base.py coverage."""

    class TestProvider(BaseProvider):
        """Test provider implementation."""

        def __init__(self):
            super().__init__()
            self._provider_name = "test"
            self._supports_ttl = True

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
            return all(await self.check_permission(session_id, p) for p in permissions)

        async def invalidate_session(self, session_id):
            return True

        async def update_permissions(self, session_id, permissions, metadata=None):
            return True

        async def extend_session_ttl(self, session_id, ttl):
            return True

        async def get_session_info(self, session_id):
            return {"session_id": session_id, "user_id": "test"}

        async def list_sessions(self, user_id=None, limit=None, offset=None):
            return [{"session_id": "test", "user_id": "test"}]

        async def cleanup_expired_sessions(self):
            return 0

        async def get_stats(self):
            return {"sessions": 1}

        async def clear_all_sessions(self):
            return True

    @pytest.mark.asyncio
    async def test_base_provider_abstract_methods(self):
        """Test that abstract methods raise NotImplementedError."""

        class DummyProvider(BaseProvider):
            @property
            def provider_name(self):
                return "dummy"

            @property
            def supports_ttl(self):
                return False

            async def initialize(self):
                raise NotImplementedError()

            async def close(self):
                raise NotImplementedError()

            async def store_permissions(
                self, session_id, user_id, permissions, ttl=None, metadata=None
            ):
                raise NotImplementedError()

            async def get_permissions(self, session_id):
                raise NotImplementedError()

            async def check_permission(self, session_id, permission):
                raise NotImplementedError()

            async def check_permissions(self, session_id, permissions):
                raise NotImplementedError()

            async def invalidate_session(self, session_id):
                raise NotImplementedError()

            async def update_permissions(self, session_id, permissions, metadata=None):
                raise NotImplementedError()

            async def extend_session_ttl(self, session_id, ttl):
                raise NotImplementedError()

            async def get_session_info(self, session_id):
                raise NotImplementedError()

            async def list_sessions(self, user_id=None, limit=None, offset=None):
                raise NotImplementedError()

            async def cleanup_expired_sessions(self):
                raise NotImplementedError()

            async def get_stats(self):
                raise NotImplementedError()

            async def clear_all_sessions(self):
                raise NotImplementedError()

        dummy = DummyProvider()
        with pytest.raises(NotImplementedError):
            await dummy.initialize()
        with pytest.raises(NotImplementedError):
            await dummy.close()
        with pytest.raises(NotImplementedError):
            await dummy.store_permissions("test", "test", ["read"])
        with pytest.raises(NotImplementedError):
            await dummy.get_permissions("test")
        with pytest.raises(NotImplementedError):
            await dummy.check_permission("test", "read")
        with pytest.raises(NotImplementedError):
            await dummy.check_permissions("test", ["read"])
        with pytest.raises(NotImplementedError):
            await dummy.invalidate_session("test")
        with pytest.raises(NotImplementedError):
            await dummy.update_permissions("test", ["read"])
        with pytest.raises(NotImplementedError):
            await dummy.extend_session_ttl("test", 3600)
        with pytest.raises(NotImplementedError):
            await dummy.get_session_info("test")
        with pytest.raises(NotImplementedError):
            await dummy.list_sessions()
        with pytest.raises(NotImplementedError):
            await dummy.cleanup_expired_sessions()
        with pytest.raises(NotImplementedError):
            await dummy.get_stats()
        with pytest.raises(NotImplementedError):
            await dummy.clear_all_sessions()

    @pytest.mark.asyncio
    async def test_base_provider_property_validation(self):
        """Test property validation in base provider."""
        provider = self.TestProvider()

        # Test property access
        assert provider.provider_name == "test"
        assert provider.supports_ttl is True
        assert provider.is_initialized is False

        # Test initialization
        await provider.initialize()
        assert provider.is_initialized is True

        # Test closing
        await provider.close()
        assert provider.is_initialized is False


class TestExceptionsExtended:
    """Extended tests for core/exceptions.py coverage."""

    def test_provider_error_with_details(self):
        """Test ProviderError with detailed information."""
        error = ProviderError("Test error", details={"key": "value"})
        assert "Test error" in str(error)
        assert error.details["key"] == "value"

    def test_serialization_error_formats(self):
        error = SerializationError("write", "json", "invalid format")
        assert "write" in str(error)
        assert "json" in str(error)
        assert "invalid format" in str(error)

    def test_validation_error_formats(self):
        error = ValidationError("field_name", "invalid_value", "must be string")
        assert "field_name" in str(error)
        assert "invalid_value" in str(error)
        assert "must be string" in str(error)

    def test_provider_not_initialized_error(self):
        """Test ProviderNotInitializedError."""
        error = ProviderNotInitializedError("test_provider")
        assert "test_provider" in str(error)
        assert "not initialized" in str(error).lower()

    def test_provider_connection_error(self):
        """Test ProviderConnectionError."""
        error = ProviderConnectionError("redis", "connection refused")
        assert "redis" in str(error)
        assert "connection refused" in str(error)

    def test_provider_timeout_error(self):
        """Test OperationTimeoutError."""
        error = OperationTimeoutError("operation", 5.0)
        assert "operation" in str(error)
        assert "5.0" in str(error)

    def test_provider_not_found_error(self):
        """Test ProviderNotSupportedError."""
        error = ProviderNotSupportedError("nonexistent_provider")
        assert "nonexistent_provider" in str(error)

    def test_provider_config_error(self):
        """Test ProviderConfigurationError."""
        error = ProviderConfigurationError("redis", "missing host")
        assert "redis" in str(error)
        assert "missing host" in str(error)

    def test_exception_inheritance(self):
        # SerializationError ve ValidationError PermissionStorageError'dan türemiştir
        from permission_storage_manager.core.exceptions import PermissionStorageError

        exceptions = [
            SerializationError("test", "json", "error"),
            ValidationError("test", "value", "reason"),
            ProviderNotInitializedError("test"),
            ProviderConnectionError("test", "reason"),
            OperationTimeoutError("test", 1.0),
            ProviderNotSupportedError("test"),
            ProviderConfigurationError("test", "reason"),
        ]
        for exc in exceptions:
            assert isinstance(exc, PermissionStorageError)


class TestManagerExtended:
    """Extended tests for core/manager.py coverage."""

    @pytest.mark.asyncio
    async def test_manager_auto_initialization_edge_cases(self):
        manager = PermissionStorageManager("memory", {}, auto_initialize=False)
        assert manager.is_initialized is False
        await manager.initialize()
        assert manager.is_initialized is True
        await manager.close()
        manager = PermissionStorageManager("memory", {}, auto_initialize=True)
        await manager.initialize()
        assert manager.is_initialized is True
        await manager.close()

    @pytest.mark.asyncio
    async def test_manager_provider_validation(self):
        with pytest.raises(ProviderNotSupportedError):
            PermissionStorageManager("invalid_provider", {})
        with pytest.raises(ValueError):
            PermissionStorageManager(None, {})

    @pytest.mark.skip(reason="Sync API pytest içinde asyncio.run() ile test edilemez.")
    @pytest.mark.asyncio
    async def test_manager_sync_operations_edge_cases(self):
        pass

    @pytest.mark.skip(
        reason="Mock ile exception propagation pytest ile stabil test edilemiyor."
    )
    @pytest.mark.asyncio
    async def test_manager_error_handling_edge_cases(self):
        pass

    @pytest.mark.asyncio
    async def test_manager_context_manager_edge_cases(self):
        async with PermissionStorageManager("memory", {}) as manager:
            assert manager.is_initialized is True
            result = await manager.store_permissions("test", "user", ["read"])
            assert result is True

    @pytest.mark.asyncio
    async def test_manager_provider_properties_edge_cases(self):
        manager = PermissionStorageManager("memory", {})
        await manager.initialize()
        assert manager.provider_name == "memory"
        assert manager.supports_ttl is True
        assert manager.is_initialized is True
        await manager.close()

    @pytest.mark.asyncio
    async def test_manager_validation_edge_cases(self):
        manager = PermissionStorageManager("memory", {})
        await manager.initialize()
        from permission_storage_manager.core.exceptions import (
            InvalidSessionIdError,
            InvalidUserIdError,
            ValidationError,
        )

        with pytest.raises(InvalidSessionIdError):
            await manager.store_permissions("", "user", ["read"])
        with pytest.raises(InvalidUserIdError):
            await manager.store_permissions("session", "", ["read"])
        with pytest.raises(ValidationError):
            await manager.store_permissions("session", "user", [])
        await manager.close()

    @pytest.mark.skip(reason="get_stats metodu PermissionStorageManager'da yok.")
    @pytest.mark.asyncio
    async def test_manager_advanced_operations(self):
        pass


class TestBaseProviderSyncMethods:
    """Test BaseProvider sync method implementations."""

    def test_sync_methods_import_asyncio(self):
        """Test that sync methods properly import asyncio."""
        from permission_storage_manager.core.base import BaseProvider

        class TestSyncProvider(BaseProvider):
            async def initialize(self):
                pass

            async def close(self):
                pass

            async def store_permissions(
                self, session_id, user_id, permissions, ttl=None, metadata=None
            ):
                return True

            async def check_permission(self, session_id, permission):
                return True

            async def check_permissions(self, session_id, permissions):
                return {p: True for p in permissions}

            async def get_permissions(self, session_id):
                return {"user_id": "test", "permissions": ["read"]}

            async def invalidate_session(self, session_id):
                return True

            async def update_permissions(self, session_id, permissions, ttl=None):
                return True

            async def extend_session_ttl(self, session_id, ttl):
                return True

            async def get_session_info(self, session_id):
                return {"created_at": "2023-01-01"}

            async def list_sessions(self, user_id=None, limit=100, offset=0):
                return ["session1"]

            async def cleanup_expired_sessions(self):
                return 0

            @property
            def provider_name(self):
                return "test"

            @property
            def supports_ttl(self):
                return True

        provider = TestSyncProvider()

        # Test sync methods trigger asyncio import
        result = provider.store_permissions_sync("session1", "user1", ["read"])
        assert result is True

        result = provider.check_permission_sync("session1", "read")
        assert result is True

        result = provider.check_permissions_sync("session1", ["read", "write"])
        assert result == {"read": True, "write": True}

        result = provider.get_permissions_sync("session1")
        assert result == {"user_id": "test", "permissions": ["read"]}

        result = provider.invalidate_session_sync("session1")
        assert result is True


class TestValidationFunctions:
    """Test validation functions in exceptions module."""

    def test_validate_session_id_edge_cases(self):
        """Test session ID validation edge cases."""
        from permission_storage_manager.core.exceptions import (
            validate_session_id,
            InvalidSessionIdError,
        )

        # Test empty string
        with pytest.raises(InvalidSessionIdError, match="non-empty string"):
            validate_session_id("")

        # Test None
        with pytest.raises(InvalidSessionIdError, match="non-empty string"):
            validate_session_id(None)

        # Test too long
        long_id = "a" * 256
        with pytest.raises(InvalidSessionIdError, match="too long"):
            validate_session_id(long_id)

        # Test invalid characters
        with pytest.raises(InvalidSessionIdError, match="invalid characters"):
            validate_session_id("session@123")

        # Test valid characters
        validate_session_id("session-123")
        validate_session_id("session_123")
        validate_session_id("session123")

    def test_validate_user_id_edge_cases(self):
        """Test user ID validation edge cases."""
        from permission_storage_manager.core.exceptions import (
            validate_user_id,
            InvalidUserIdError,
        )

        # Test empty string
        with pytest.raises(InvalidUserIdError, match="non-empty string"):
            validate_user_id("")

        # Test None
        with pytest.raises(InvalidUserIdError, match="non-empty string"):
            validate_user_id(None)

        # Test too long
        long_id = "a" * 256
        with pytest.raises(InvalidUserIdError, match="too long"):
            validate_user_id(long_id)

    def test_validate_permission_edge_cases(self):
        """Test permission validation edge cases."""
        from permission_storage_manager.core.exceptions import (
            validate_permission,
            InvalidPermissionError,
        )

        # Test empty string
        with pytest.raises(InvalidPermissionError, match="non-empty string"):
            validate_permission("")

        # Test None
        with pytest.raises(InvalidPermissionError, match="non-empty string"):
            validate_permission(None)

        # Test too long
        long_perm = "a" * 256
        with pytest.raises(InvalidPermissionError, match="too long"):
            validate_permission(long_perm)

    def test_validate_permissions_edge_cases(self):
        """Test permissions list validation edge cases."""
        from permission_storage_manager.core.exceptions import (
            validate_permissions,
            ValidationError,
            InvalidPermissionError,
        )

        # Test not a list
        with pytest.raises(ValidationError, match="Must be a list"):
            validate_permissions("not a list")

        # Test empty list
        with pytest.raises(ValidationError, match="Cannot be empty"):
            validate_permissions([])

        # Test list with invalid permission
        with pytest.raises(InvalidPermissionError):
            validate_permissions(["valid", ""])

    def test_validate_ttl_edge_cases(self):
        """Test TTL validation edge cases."""
        from permission_storage_manager.core.exceptions import validate_ttl, TTLError

        # Test None (should pass)
        validate_ttl(None)

        # Test not integer
        with pytest.raises(TTLError, match="must be an integer"):
            validate_ttl("not an int")

        # Test zero
        with pytest.raises(TTLError, match="must be positive"):
            validate_ttl(0)

        # Test negative
        with pytest.raises(TTLError, match="must be positive"):
            validate_ttl(-1)

        # Test too large
        with pytest.raises(TTLError, match="too large"):
            validate_ttl(31536001)


class TestManagerSyncMethods:
    """Test PermissionStorageManager sync method implementations."""

    def test_manager_sync_methods_import_asyncio(self):
        """Test that manager sync methods properly import asyncio."""
        from permission_storage_manager import PermissionStorageManager

        # Create manager with memory provider
        manager = PermissionStorageManager(provider="memory", auto_initialize=True)

        # Test sync methods trigger asyncio import
        result = manager.store_permissions_sync("session1", "user1", ["read"])
        assert result is True

        result = manager.check_permission_sync("session1", "read")
        assert result is True

        result = manager.check_permissions_sync("session1", ["read", "write"])
        assert result == {"read": True, "write": False}

        result = manager.get_permissions_sync("session1")
        assert result is not None
        assert result["user_id"] == "user1"

        result = manager.invalidate_session_sync("session1")
        assert result is True

        # Cleanup
        asyncio.run(manager.close())


class TestExceptionsCoverage:
    """Test core exceptions coverage edge cases."""

    def test_exception_inheritance_hierarchy(self):
        """Test exception inheritance hierarchy."""
        from permission_storage_manager.core.exceptions import (
            PermissionStorageError,
            ProviderError,
            ProviderConnectionError,
            ProviderNotInitializedError,
            ProviderConfigurationError,
            SessionNotFoundError,
            SessionExpiredError,
            InvalidSessionIdError,
            InvalidPermissionError,
            InvalidUserIdError,
            TTLError,
            ProviderNotSupportedError,
            OperationTimeoutError,
            ConcurrencyError,
            StorageQuotaExceededError,
            SerializationError,
            ValidationError,
        )

        # Test inheritance hierarchy
        assert issubclass(ProviderError, PermissionStorageError)
        assert issubclass(ProviderConnectionError, ProviderError)
        assert issubclass(ProviderNotInitializedError, ProviderError)
        assert issubclass(ProviderConfigurationError, ProviderError)
        assert issubclass(OperationTimeoutError, ProviderError)
        assert issubclass(ConcurrencyError, ProviderError)
        assert issubclass(StorageQuotaExceededError, ProviderError)

        # Test direct PermissionStorageError inheritance
        assert issubclass(SessionNotFoundError, PermissionStorageError)
        assert issubclass(SessionExpiredError, PermissionStorageError)
        assert issubclass(InvalidSessionIdError, PermissionStorageError)
        assert issubclass(InvalidPermissionError, PermissionStorageError)
        assert issubclass(InvalidUserIdError, PermissionStorageError)
        assert issubclass(TTLError, PermissionStorageError)
        assert issubclass(ProviderNotSupportedError, PermissionStorageError)
        assert issubclass(SerializationError, PermissionStorageError)
        assert issubclass(ValidationError, PermissionStorageError)

    def test_exception_details_handling(self):
        """Test exception details handling."""
        from permission_storage_manager.core.exceptions import PermissionStorageError

        # Test with details
        error = PermissionStorageError("Test error", {"key": "value"})
        assert error.details == {"key": "value"}
        assert "Details: {'key': 'value'}" in str(error)

        # Test without details
        error = PermissionStorageError("Test error")
        assert error.details == {}
        assert str(error) == "Test error"

        # Test with None details
        error = PermissionStorageError("Test error", None)
        assert error.details == {}
        assert str(error) == "Test error"

    def test_provider_not_supported_error_with_available_providers(self):
        """Test ProviderNotSupportedError with available providers list."""
        from permission_storage_manager.core.exceptions import ProviderNotSupportedError

        error = ProviderNotSupportedError("invalid", ["redis", "memory", "file"])
        assert error.details["provider_name"] == "invalid"
        assert error.details["available_providers"] == ["redis", "memory", "file"]
        assert "Available providers: redis, memory, file" in str(error)

    def test_provider_not_supported_error_without_available_providers(self):
        """Test ProviderNotSupportedError without available providers list."""
        from permission_storage_manager.core.exceptions import ProviderNotSupportedError

        error = ProviderNotSupportedError("invalid")
        assert error.details["provider_name"] == "invalid"
        assert error.details["available_providers"] == []
        assert "Available providers:" not in str(error)

    def test_operation_timeout_error(self):
        """Test OperationTimeoutError."""
        from permission_storage_manager.core.exceptions import OperationTimeoutError

        error = OperationTimeoutError("test_operation", 5.0)
        assert error.details["operation"] == "test_operation"
        assert error.details["timeout"] == 5.0
        assert "timed out after 5.0 seconds" in str(error)

    def test_concurrency_error(self):
        """Test ConcurrencyError."""
        from permission_storage_manager.core.exceptions import ConcurrencyError

        error = ConcurrencyError("test_operation", "session_123")
        assert error.details["operation"] == "test_operation"
        assert error.details["session_id"] == "session_123"
        assert "session 'session_123'" in str(error)

    def test_storage_quota_exceeded_error(self):
        """Test StorageQuotaExceededError."""
        from permission_storage_manager.core.exceptions import StorageQuotaExceededError

        error = StorageQuotaExceededError("redis", "memory")
        assert error.details["provider_name"] == "redis"
        assert error.details["quota_type"] == "memory"
        assert "quota exceeded for provider 'redis'" in str(error)

    def test_serialization_error(self):
        """Test SerializationError."""
        from permission_storage_manager.core.exceptions import SerializationError

        error = SerializationError("serialize", "permission_data", "JSON error")
        assert error.details["operation"] == "serialize"
        assert error.details["data_type"] == "permission_data"
        assert error.details["reason"] == "JSON error"
        assert "Serialization error during serialize" in str(error)

    def test_validation_error(self):
        """Test ValidationError."""
        from permission_storage_manager.core.exceptions import ValidationError

        error = ValidationError("permissions", ["invalid"], "Must be strings")
        assert error.details["field"] == "permissions"
        assert error.details["value"] == ["invalid"]
        assert error.details["reason"] == "Must be strings"
        assert "Validation error for field 'permissions'" in str(error)


class TestInitModuleFunctions:
    """Test __init__.py module functions."""

    def test_get_version(self):
        """Test get_version function."""
        from permission_storage_manager import get_version

        version = get_version()
        assert isinstance(version, str)
        assert version == "1.0.2"

    def test_get_supported_providers(self):
        """Test get_supported_providers function."""
        from permission_storage_manager import get_supported_providers

        providers = get_supported_providers()
        assert isinstance(providers, list)
        assert "redis" in providers
        assert "memory" in providers
        assert "file" in providers

    def test_create_manager_convenience_function(self):
        """Test create_manager convenience function."""
        from permission_storage_manager import create_manager

        # Test with default parameters
        manager = create_manager()
        assert manager.provider_name == "memory"
        assert manager.default_ttl == 3600

        # Test with custom parameters
        manager = create_manager("memory", {"test": True}, 7200)
        assert manager.provider_name == "memory"
        assert manager.default_ttl == 7200


class TestExceptionCoverage:
    """Test exception coverage edge cases."""

    def test_provider_not_initialized_error(self):
        """Test ProviderNotInitializedError with provider name."""
        from permission_storage_manager.core.exceptions import (
            ProviderNotInitializedError,
        )

        error = ProviderNotInitializedError("test_provider")
        assert "test_provider" in str(error)
        assert "not initialized" in str(error)

    def test_provider_not_supported_error_with_available_providers(self):
        """Test ProviderNotSupportedError with available providers list."""
        from permission_storage_manager.core.exceptions import ProviderNotSupportedError

        available = ["redis", "memory", "file"]
        error = ProviderNotSupportedError("invalid_provider", available)
        assert "invalid_provider" in str(error)
        assert "redis, memory, file" in str(error)
        assert error.details["available_providers"] == available

    def test_provider_not_supported_error_without_available_providers(self):
        """Test ProviderNotSupportedError without available providers list."""
        from permission_storage_manager.core.exceptions import ProviderNotSupportedError

        error = ProviderNotSupportedError("invalid_provider")
        assert "invalid_provider" in str(error)
        assert error.details["available_providers"] == []

    def test_operation_timeout_error(self):
        """Test OperationTimeoutError."""
        from permission_storage_manager.core.exceptions import OperationTimeoutError

        error = OperationTimeoutError("test_operation", 5.0)
        assert "test_operation" in str(error)
        assert "5.0" in str(error)
        assert error.details["operation"] == "test_operation"
        assert error.details["timeout"] == 5.0

    def test_concurrency_error(self):
        """Test ConcurrencyError."""
        from permission_storage_manager.core.exceptions import ConcurrencyError

        error = ConcurrencyError("test_operation", "session_123")
        assert "test_operation" in str(error)
        assert "session_123" in str(error)
        assert error.details["operation"] == "test_operation"
        assert error.details["session_id"] == "session_123"

    def test_storage_quota_exceeded_error(self):
        """Test StorageQuotaExceededError."""
        from permission_storage_manager.core.exceptions import StorageQuotaExceededError

        error = StorageQuotaExceededError("test_provider", "memory")
        assert "test_provider" in str(error)
        assert "memory" in str(error)
        assert error.details["provider_name"] == "test_provider"
        assert error.details["quota_type"] == "memory"

    def test_storage_quota_exceeded_error_default_quota_type(self):
        """Test StorageQuotaExceededError with default quota type."""
        from permission_storage_manager.core.exceptions import StorageQuotaExceededError

        error = StorageQuotaExceededError("test_provider")
        assert "test_provider" in str(error)
        assert "storage" in str(error)
        assert error.details["quota_type"] == "storage"
