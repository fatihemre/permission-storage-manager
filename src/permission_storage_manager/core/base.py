"""
Abstract base class for permission storage providers.
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseProvider(ABC):
    """
    Abstract base class that all permission storage providers must implement.

    This class defines the interface that all storage providers (Redis, Memory, File, etc.)
    must implement to ensure consistent behavior across different storage backends.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the provider with configuration.

        Args:
            config: Provider-specific configuration dictionary
        """
        self.config = config or {}
        self._initialized = False

    @abstractmethod
    async def initialize(self) -> None:
        """
        Initialize the provider connection/resources.
        This method should be called before using any other methods.
        """
        pass

    @abstractmethod
    async def close(self) -> None:
        """
        Close provider connections and cleanup resources.
        """
        pass

    @abstractmethod
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
            ttl: Time-to-live in seconds (None for no expiration)
            metadata: Additional metadata to store with permissions

        Returns:
            True if stored successfully, False otherwise

        Raises:
            ProviderError: If storage operation fails
        """
        pass

    @abstractmethod
    async def check_permission(self, session_id: str, permission: str) -> bool:
        """
        Check if a session has a specific permission.

        Args:
            session_id: Session identifier
            permission: Permission string to check

        Returns:
            True if permission exists, False otherwise

        Raises:
            ProviderError: If check operation fails
        """
        pass

    @abstractmethod
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
            ProviderError: If check operation fails
        """
        pass

    @abstractmethod
    async def get_permissions(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get all permissions and metadata for a session.

        Args:
            session_id: Session identifier

        Returns:
            Dictionary containing user_id, permissions list, metadata, and timestamps
            None if session not found

        Raises:
            ProviderError: If retrieval operation fails
        """
        pass

    @abstractmethod
    async def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate/delete a session and its permissions.

        Args:
            session_id: Session identifier to invalidate

        Returns:
            True if session was invalidated, False if session didn't exist

        Raises:
            ProviderError: If invalidation operation fails
        """
        pass

    @abstractmethod
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
            True if updated successfully, False if session doesn't exist

        Raises:
            ProviderError: If update operation fails
        """
        pass

    @abstractmethod
    async def extend_session_ttl(self, session_id: str, ttl: int) -> bool:
        """
        Extend the TTL of an existing session.

        Args:
            session_id: Session identifier
            ttl: New TTL in seconds

        Returns:
            True if TTL was extended, False if session doesn't exist

        Raises:
            ProviderError: If operation fails
        """
        pass

    @abstractmethod
    async def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session metadata and statistics.

        Args:
            session_id: Session identifier

        Returns:
            Dictionary containing session info (created_at, updated_at, ttl_remaining, etc.)
            None if session not found

        Raises:
            ProviderError: If operation fails
        """
        pass

    @abstractmethod
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

        Raises:
            ProviderError: If operation fails
        """
        pass

    @abstractmethod
    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions (for providers that don't auto-expire).

        Returns:
            Number of sessions cleaned up

        Raises:
            ProviderError: If cleanup operation fails
        """
        pass

    # Synchronous versions for compatibility
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

    # Provider metadata
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the name of this provider."""
        pass

    @property
    @abstractmethod
    def supports_ttl(self) -> bool:
        """Return whether this provider supports TTL natively."""
        pass

    @property
    def is_initialized(self) -> bool:
        """Return whether the provider is initialized."""
        return self._initialized

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
        asyncio.run(self.initialize())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Sync context manager exit."""
        asyncio.run(self.close())
