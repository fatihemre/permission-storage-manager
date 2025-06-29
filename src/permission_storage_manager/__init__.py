"""
Permission Storage Manager - A flexible permission storage system for Python.

This package provides a unified interface for storing and managing user permissions
across different storage backends (Redis, Memory, File, etc.).

Features:
- Multiple storage providers (Redis, Memory, File)
- Async/sync support
- TTL (Time-To-Live) support
- Session management
- Type safety with full type hints
- Extensible architecture for custom providers

Quick Start:
    >>> from permission_storage_manager import PermissionStorageManager
    >>>
    >>> # Initialize with Redis provider
    >>> manager = PermissionStorageManager(
    ...     provider="redis",
    ...     config={"url": "redis://localhost:6379"}
    ... )
    >>>
    >>> # Store permissions
    >>> await manager.store_permissions(
    ...     session_id="session_123",
    ...     user_id="user_456",
    ...     permissions=["read", "write", "admin"]
    ... )
    >>>
    >>> # Check permission
    >>> has_read = await manager.check_permission("session_123", "read")
    >>> print(has_read)  # True
    >>>
    >>> # Check multiple permissions
    >>> perms = await manager.check_permissions("session_123", ["read", "delete"])
    >>> print(perms)  # {"read": True, "delete": False}

Providers:
    - RedisProvider: High-performance Redis-based storage
    - MemoryProvider: In-memory storage for development/testing
    - FileProvider: File-based storage for simple deployments

For more information, visit: https://github.com/fatihemre/permission-storage-manager
"""

# Import core components
from .core import (
    BaseProvider,
    PermissionStorageManager,
    # Exceptions
    PermissionStorageError,
    ProviderError,
    ProviderConnectionError,
    ProviderNotInitializedError,
    ProviderConfigurationError,
    ProviderNotSupportedError,
    SessionNotFoundError,
    SessionExpiredError,
    InvalidSessionIdError,
    InvalidPermissionError,
    InvalidUserIdError,
    TTLError,
    OperationTimeoutError,
    ConcurrencyError,
    StorageQuotaExceededError,
    SerializationError,
    ValidationError,
    # Validation functions
    validate_session_id,
    validate_user_id,
    validate_permission,
    validate_permissions,
    validate_ttl,
)

# Import providers for easier access
from .providers import (
    RedisProvider,
    MemoryProvider,
    FileProvider,
    get_provider_info,
    list_available_providers,
    get_provider_class,
    compare_providers,
    get_recommended_provider,
    AVAILABLE_PROVIDERS,
)


# Auto-register built-in providers
def _register_builtin_providers():
    """Register built-in providers with the manager."""
    PermissionStorageManager.register_provider("redis", RedisProvider)
    PermissionStorageManager.register_provider("memory", MemoryProvider)
    PermissionStorageManager.register_provider("file", FileProvider)


# Register providers on import
_register_builtin_providers()

# Package metadata
__version__ = "1.0.0"
__author__ = "Fatih Emre"
__email__ = "info@fatihemre.net"
__license__ = "MIT"
__description__ = "A flexible permission storage system for Python"
__url__ = "https://github.com/fatihemre/permission-storage-manager"

# Public API
__all__ = [
    # Main classes
    "BaseProvider",
    "PermissionStorageManager",
    # Provider classes
    "RedisProvider",
    "MemoryProvider",
    "FileProvider",
    # Exceptions
    "PermissionStorageError",
    "ProviderError",
    "ProviderConnectionError",
    "ProviderNotInitializedError",
    "ProviderConfigurationError",
    "ProviderNotSupportedError",
    "SessionNotFoundError",
    "SessionExpiredError",
    "InvalidSessionIdError",
    "InvalidPermissionError",
    "InvalidUserIdError",
    "TTLError",
    "OperationTimeoutError",
    "ConcurrencyError",
    "StorageQuotaExceededError",
    "SerializationError",
    "ValidationError",
    # Validation functions
    "validate_session_id",
    "validate_user_id",
    "validate_permission",
    "validate_permissions",
    "validate_ttl",
    # Provider utilities
    "get_provider_info",
    "list_available_providers",
    "get_provider_class",
    "compare_providers",
    "get_recommended_provider",
    "AVAILABLE_PROVIDERS",
    # Convenience functions
    "create_manager",
    # Metadata
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "__description__",
    "__url__",
]


# Convenience function for quick setup
def create_manager(
    provider: str = "memory", config: dict = None, default_ttl: int = 3600
) -> PermissionStorageManager:
    """
    Convenience function to create a PermissionStorageManager instance.

    Args:
        provider: Provider name (default: "memory")
        config: Provider configuration (default: None)
        default_ttl: Default TTL in seconds (default: 3600)

    Returns:
        Configured PermissionStorageManager instance

    Example:
        >>> manager = create_manager("redis", {"url": "redis://localhost:6379"})
        >>> await manager.store_permissions("session_1", "user_1", ["read"])

        >>> # Quick memory setup for testing
        >>> manager = create_manager()  # Uses memory provider by default
        >>> manager.store_permissions_sync("session_1", "user_1", ["read"])
    """
    return PermissionStorageManager(
        provider=provider, config=config or {}, default_ttl=default_ttl
    )


def get_version() -> str:
    """
    Get the current version of Permission Storage Manager.

    Returns:
        Version string

    Example:
        >>> from permission_storage_manager import get_version
        >>> print(get_version())
        "1.0.0"
    """
    return __version__


def get_supported_providers() -> list:
    """
    Get list of supported provider names.

    Returns:
        List of provider names

    Example:
        >>> from permission_storage_manager import get_supported_providers
        >>> print(get_supported_providers())
        ["redis", "memory", "file"]
    """
    return list_available_providers()


# Add utility functions to public API
__all__.extend(["get_version", "get_supported_providers"])
