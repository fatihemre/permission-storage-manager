"""
Main Permission Storage Manager class.
"""

import asyncio
from typing import List, Optional, Dict, Any, Union, Type
from datetime import datetime

from .base import BaseProvider
from .exceptions import (
    ProviderNotSupportedError,
    ProviderNotInitializedError,
    validate_permissions,
    validate_session_id,
    validate_user_id,
    validate_ttl,
)


class PermissionStorageManager:
    """
    Main manager class for handling permission storage across different providers.

    This class provides a unified interface for storing and retrieving user permissions
    regardless of the underlying storage provider (Redis, Memory, File, etc.).

    Example:
        >>> manager = PermissionStorageManager(
        ...     provider="redis",
        ...     config={"url": "redis://localhost:6379"}
        ... )
        >>> await manager.initialize()
        >>> await manager.store_permissions("session_123", "user_456", ["read", "write"])
        >>> has_permission = await manager.check_permission("session_123", "read")
        >>> await manager.close()
    """

    # Registry of available providers
    _providers: Dict[str, Type[BaseProvider]] = {}

    def __init__(
        self,
        provider: Union[str, BaseProvider],
        config: Optional[Dict[str, Any]] = None,
        default_ttl: Optional[int] = 3600,
        auto_initialize: bool = True,
    ):
        """
        Initialize the Permission Storage Manager.

        Args:
            provider: Provider name (string) or provider instance
            config: Provider-specific configuration
            default_ttl: Default TTL in seconds for stored permissions
            auto_initialize: Whether to automatically initialize the provider
        """
        self.default_ttl = default_ttl
        self._auto_initialize = auto_initialize
        self._initialized = False

        if isinstance(provider, str):
            self._provider = self._create_provider(provider, config or {})
        elif isinstance(provider, BaseProvider):
            self._provider = provider
        else:
            raise ValueError(
                "Provider must be either a string name or BaseProvider instance"
            )

    @classmethod
    def register_provider(cls, name: str, provider_class: Type[BaseProvider]) -> None:
        """
        Register a new provider class.

        Args:
            name: Provider name
            provider_class: Provider class that extends BaseProvider
        """
        if not issubclass(provider_class, BaseProvider):
            raise ValueError("Provider class must extend BaseProvider")

        cls._providers[name] = provider_class

    @classmethod
    def get_available_providers(cls) -> List[str]:
        """
        Get list of available provider names.

        Returns:
            List of registered provider names
        """
        return list(cls._providers.keys())

    def _create_provider(
        self, provider_name: str, config: Dict[str, Any]
    ) -> BaseProvider:
        """
        Create provider instance from name and config.

        Args:
            provider_name: Provider name
            config: Provider configuration

        Returns:
            Provider instance

        Raises:
            ProviderNotSupportedError: If provider is not registered
        """
        if provider_name not in self._providers:
            raise ProviderNotSupportedError(provider_name, list(self._providers.keys()))

        provider_class = self._providers[provider_name]
        return provider_class(config)

    async def initialize(self) -> None:
        """
        Initialize the storage provider.

        Raises:
            ProviderError: If initialization fails
        """
        if not self._initialized:
            await self._provider.initialize()
            self._initialized = True

    async def close(self) -> None:
        """
        Close the storage provider and cleanup resources.
        """
        if self._initialized:
            await self._provider.close()
            self._initialized = False

    def _ensure_initialized(self) -> None:
        """
        Ensure provider is initialized.

        Raises:
            ProviderNotInitializedError: If provider is not initialized
        """
        if not self._initialized:
            if self._auto_initialize:
                # Try to initialize synchronously
                try:
                    asyncio.run(self.initialize())
                except Exception as e:
                    raise ProviderNotInitializedError(
                        self._provider.provider_name
                    ) from e
            else:
                raise ProviderNotInitializedError(self._provider.provider_name)

    async def store_permissions(
        self,
        session_id: str,
        user_id: str,
        permissions: List[str],
        ttl: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Store user permissions for a session.

        Args:
            session_id: Unique session identifier
            user_id: User identifier
            permissions: List of permission strings
            ttl: Time-to-live in seconds (uses default_ttl if None)
            metadata: Additional metadata to store

        Returns:
            True if stored successfully

        Raises:
            ValidationError: If input validation fails
            ProviderError: If storage operation fails
        """
        # Validate inputs
        validate_session_id(session_id)
        validate_user_id(user_id)
        validate_permissions(permissions)

        effective_ttl = ttl if ttl is not None else self.default_ttl
        validate_ttl(effective_ttl)

        # Ensure provider is initialized
        if not self._initialized:
            if self._auto_initialize:
                await self.initialize()
            else:
                self._ensure_initialized()

        # Add standard metadata
        if metadata is None:
            metadata = {}

        metadata.update(
            {
                "created_at": datetime.utcnow().isoformat(),
                "manager_version": "1.0.2",  # Will be dynamic in real implementation
            }
        )

        return await self._provider.store_permissions(
            session_id, user_id, permissions, effective_ttl, metadata
        )

    async def check_permission(self, session_id: str, permission: str) -> bool:
        """
        Check if a session has a specific permission.

        Args:
            session_id: Session identifier
            permission: Permission string to check

        Returns:
            True if permission exists

        Raises:
            ValidationError: If input validation fails
            ProviderError: If check operation fails
        """
        validate_session_id(session_id)

        if not self._initialized:
            if self._auto_initialize:
                await self.initialize()
            else:
                self._ensure_initialized()

        return await self._provider.check_permission(session_id, permission)

    async def check_permissions(
        self, session_id: str, permissions: List[str]
    ) -> Dict[str, bool]:
        """
        Check multiple permissions for a session.

        Args:
            session_id: Session identifier
            permissions: List of permission strings to check

        Returns:
            Dictionary mapping permission strings to boolean results

        Raises:
            ValidationError: If input validation fails
            ProviderError: If check operation fails
        """
        validate_session_id(session_id)
        validate_permissions(permissions)

        if not self._initialized:
            if self._auto_initialize:
                await self.initialize()
            else:
                self._ensure_initialized()

        return await self._provider.check_permissions(session_id, permissions)

    async def get_permissions(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get all permissions and metadata for a session.

        Args:
            session_id: Session identifier

        Returns:
            Dictionary containing permissions data or None if not found

        Raises:
            ValidationError: If input validation fails
            ProviderError: If operation fails
        """
        validate_session_id(session_id)

        if not self._initialized:
            if self._auto_initialize:
                await self.initialize()
            else:
                self._ensure_initialized()

        return await self._provider.get_permissions(session_id)

    async def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate/delete a session and its permissions.

        Args:
            session_id: Session identifier to invalidate

        Returns:
            True if session was invalidated

        Raises:
            ValidationError: If input validation fails
            ProviderError: If operation fails
        """
        validate_session_id(session_id)

        if not self._initialized:
            if self._auto_initialize:
                await self.initialize()
            else:
                self._ensure_initialized()

        return await self._provider.invalidate_session(session_id)

    async def update_permissions(
        self, session_id: str, permissions: List[str], ttl: Optional[int] = None
    ) -> bool:
        """
        Update permissions for an existing session.

        Args:
            session_id: Session identifier
            permissions: New list of permission strings
            ttl: Optional new TTL in seconds

        Returns:
            True if updated successfully

        Raises:
            ValidationError: If input validation fails
            ProviderError: If operation fails
        """
        validate_session_id(session_id)
        validate_permissions(permissions)
        validate_ttl(ttl)

        if not self._initialized:
            if self._auto_initialize:
                await self.initialize()
            else:
                self._ensure_initialized()

        return await self._provider.update_permissions(session_id, permissions, ttl)

    async def extend_session_ttl(self, session_id: str, ttl: int) -> bool:
        """
        Extend the TTL of an existing session.

        Args:
            session_id: Session identifier
            ttl: New TTL in seconds

        Returns:
            True if TTL was extended

        Raises:
            ValidationError: If input validation fails
            ProviderError: If operation fails
        """
        validate_session_id(session_id)
        validate_ttl(ttl)

        if not self._initialized:
            if self._auto_initialize:
                await self.initialize()
            else:
                self._ensure_initialized()

        return await self._provider.extend_session_ttl(session_id, ttl)

    async def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session metadata and statistics.

        Args:
            session_id: Session identifier

        Returns:
            Dictionary containing session info or None if not found
        """
        validate_session_id(session_id)

        if not self._initialized:
            if self._auto_initialize:
                await self.initialize()
            else:
                self._ensure_initialized()

        return await self._provider.get_session_info(session_id)

    async def list_sessions(
        self, user_id: Optional[str] = None, limit: int = 100, offset: int = 0
    ) -> List[str]:
        """
        List active sessions.

        Args:
            user_id: Optional user ID to filter sessions
            limit: Maximum number of sessions to return
            offset: Number of sessions to skip

        Returns:
            List of session IDs
        """
        if user_id:
            validate_user_id(user_id)

        if not self._initialized:
            if self._auto_initialize:
                await self.initialize()
            else:
                self._ensure_initialized()

        return await self._provider.list_sessions(user_id, limit, offset)

    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        if not self._initialized:
            if self._auto_initialize:
                await self.initialize()
            else:
                self._ensure_initialized()

        return await self._provider.cleanup_expired_sessions()

    # Synchronous wrappers
    def store_permissions_sync(self, *args, **kwargs) -> bool:
        """Synchronous version of store_permissions."""
        return asyncio.run(self.store_permissions(*args, **kwargs))

    def check_permission_sync(self, *args, **kwargs) -> bool:
        """Synchronous version of check_permission."""
        return asyncio.run(self.check_permission(*args, **kwargs))

    def check_permissions_sync(self, *args, **kwargs) -> Dict[str, bool]:
        """Synchronous version of check_permissions."""
        return asyncio.run(self.check_permissions(*args, **kwargs))

    def get_permissions_sync(self, *args, **kwargs) -> Optional[Dict[str, Any]]:
        """Synchronous version of get_permissions."""
        return asyncio.run(self.get_permissions(*args, **kwargs))

    def invalidate_session_sync(self, *args, **kwargs) -> bool:
        """Synchronous version of invalidate_session."""
        return asyncio.run(self.invalidate_session(*args, **kwargs))

    # Properties
    @property
    def provider_name(self) -> str:
        """Get the name of the current provider."""
        return self._provider.provider_name

    @property
    def is_initialized(self) -> bool:
        """Check if the manager is initialized."""
        return self._initialized

    @property
    def supports_ttl(self) -> bool:
        """Check if the current provider supports TTL natively."""
        return self._provider.supports_ttl

    # Context manager support
    async def __aenter__(self):
        """Async context manager entry."""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    def __enter__(self):
        """Sync context manager entry."""
        self._ensure_initialized()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Sync context manager exit."""
        asyncio.run(self.close())
