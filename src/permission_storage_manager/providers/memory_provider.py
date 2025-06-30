"""
In-memory permission storage provider.
"""

import asyncio
import logging
import threading
import time
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from collections import defaultdict
import copy

from ..core.base import BaseProvider
from ..core.exceptions import (
    ProviderError,
)

logger = logging.getLogger(__name__)


class MemoryProvider(BaseProvider):
    """
    In-memory storage provider for permissions.

    This provider stores all data in memory using Python dictionaries.
    Ideal for development, testing, and applications that don't require persistence.

    Features:
    - Zero external dependencies
    - Fast read/write operations
    - TTL support with background cleanup
    - Thread-safe operations
    - Session indexing by user
    - Memory usage monitoring

    Configuration:
        cleanup_interval: Background cleanup interval in seconds (default: 60)
        max_sessions: Maximum number of sessions to store (default: 10000)
        enable_monitoring: Enable memory usage monitoring (default: True)

    Example:
        >>> config = {
        ...     "cleanup_interval": 30,
        ...     "max_sessions": 5000,
        ...     "enable_monitoring": True
        ... }
        >>> provider = MemoryProvider(config)
        >>> await provider.initialize()

    Note:
        This provider is NOT suitable for production use with multiple processes
        or when data persistence is required. Use Redis or File provider instead.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize memory provider with configuration.

        Args:
            config: Memory provider configuration dictionary
        """
        super().__init__(config)

        # Default configuration
        self._config = {
            "cleanup_interval": 60,  # Background cleanup interval
            "max_sessions": 10000,  # Maximum sessions to store
            "enable_monitoring": True,  # Enable memory monitoring
            **self.config,
        }

        # Storage structures
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._user_sessions: Dict[str, set] = defaultdict(set)
        self._session_expiry: Dict[str, float] = {}

        # Thread safety
        self._lock = threading.RLock()

        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._monitoring_task: Optional[asyncio.Task] = None

        # Statistics
        self._stats = {
            "created_at": time.time(),
            "total_sessions_created": 0,
            "total_sessions_expired": 0,
            "total_operations": 0,
            "peak_session_count": 0,
        }

    async def initialize(self) -> None:
        """
        Initialize the memory provider and start background tasks.
        """
        try:
            # Start background cleanup task
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

            # Start monitoring task if enabled
            if self._config["enable_monitoring"]:
                self._monitoring_task = asyncio.create_task(self._monitoring_loop())

            self._initialized = True
            logger.info("Memory provider initialized successfully")

        except Exception as e:
            raise ProviderError(f"Failed to initialize memory provider: {e}") from e

    async def close(self) -> None:
        """Close the provider and cleanup resources."""
        # Cancel background tasks
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass

        # Clear all data
        with self._lock:
            self._sessions.clear()
            self._user_sessions.clear()
            self._session_expiry.clear()

        self._initialized = False
        logger.info("Memory provider closed")

    async def _cleanup_loop(self) -> None:
        """Background task to clean up expired sessions."""
        while True:
            try:
                await asyncio.sleep(self._config["cleanup_interval"])
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Error in cleanup loop: {e}")

    async def _monitoring_loop(self) -> None:
        """Background task for monitoring memory usage."""
        while True:
            try:
                await asyncio.sleep(60)  # Monitor every minute
                self._update_stats()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Error in monitoring loop: {e}")

    def _update_stats(self) -> None:
        """Update internal statistics."""
        with self._lock:
            current_count = len(self._sessions)
            if current_count > self._stats["peak_session_count"]:
                self._stats["peak_session_count"] = current_count

    def _is_expired(self, session_id: str) -> bool:
        """Check if a session is expired."""
        if session_id not in self._session_expiry:
            return False

        return time.time() > self._session_expiry[session_id]

    async def _cleanup_expired(self) -> int:
        """Remove expired sessions and return count of cleaned sessions."""
        current_time = time.time()
        expired_sessions = set()

        with self._lock:
            # Find expired sessions by expiry dict
            for session_id, expiry_time in list(self._session_expiry.items()):
                if current_time > expiry_time:
                    expired_sessions.add(session_id)

            # Extra safety: check all sessions for expiry (covers edge cases)
            for session_id in list(self._sessions.keys()):
                if self._is_expired(session_id):
                    expired_sessions.add(session_id)

            # Remove expired sessions
            for session_id in expired_sessions:
                self._remove_session_internal(session_id)

            # Update stats
            self._stats["total_sessions_expired"] += len(expired_sessions)

        if expired_sessions:
            logger.debug(f"Cleaned up {len(expired_sessions)} expired sessions")

        return len(expired_sessions)

    def _remove_session_internal(self, session_id: str) -> None:
        """Internal method to remove session (assumes lock is held)."""
        if session_id in self._sessions:
            # Get user_id before removing
            session_data = self._sessions[session_id]
            user_id = session_data.get("user_id")

            # Remove from main storage
            del self._sessions[session_id]

            # Remove from user index
            if user_id and user_id in self._user_sessions:
                self._user_sessions[user_id].discard(session_id)
                if not self._user_sessions[user_id]:
                    del self._user_sessions[user_id]

            # Remove from expiry tracking
            self._session_expiry.pop(session_id, None)

    def _check_storage_limits(self) -> None:
        """Check if storage limits are exceeded."""
        if len(self._sessions) >= self._config["max_sessions"]:
            raise ProviderError(
                f"Maximum session limit reached ({self._config['max_sessions']}). "
                "Consider increasing max_sessions or using a persistent provider."
            )

    def _ensure_open(self):
        if not self._initialized:
            raise ProviderError("MemoryProvider is closed.")

    async def store_permissions(
        self,
        session_id: str,
        user_id: str,
        permissions: List[str],
        ttl: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        self._ensure_open()
        try:
            with self._lock:
                is_new = session_id not in self._sessions
                # Check storage limits
                if is_new:
                    self._check_storage_limits()

                # Prepare session data
                session_data = {
                    "user_id": user_id,
                    "permissions": copy.deepcopy(permissions),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "metadata": copy.deepcopy(metadata or {}),
                }

                # Store session
                self._sessions[session_id] = session_data

                # Add to user index
                self._user_sessions[user_id].add(session_id)

                # Set TTL if specified
                if ttl:
                    self._session_expiry[session_id] = time.time() + ttl
                else:
                    # Remove from expiry tracking if no TTL
                    self._session_expiry.pop(session_id, None)

                # Update statistics
                self._stats["total_operations"] += 1
                if is_new:
                    self._stats["total_sessions_created"] += 1

            logger.debug(f"Stored permissions for session {session_id}")
            return True

        except Exception as e:
            raise ProviderError(f"Failed to store permissions: {e}") from e

    async def check_permission(self, session_id: str, permission: str) -> bool:
        """
        Check if session has specific permission.

        Args:
            session_id: Session identifier
            permission: Permission to check

        Returns:
            True if permission exists
        """
        self._ensure_open()
        try:
            with self._lock:
                # Check if session exists and not expired
                if session_id not in self._sessions or self._is_expired(session_id):
                    return False

                session_data = self._sessions[session_id]
                result = permission in session_data.get("permissions", [])

                self._stats["total_operations"] += 1
                return result

        except Exception as e:
            raise ProviderError(f"Failed to check permission: {e}") from e

    async def check_permissions(
        self, session_id: str, permissions: List[str]
    ) -> Dict[str, bool]:
        """
        Check multiple permissions for session.

        Args:
            session_id: Session identifier
            permissions: List of permissions to check

        Returns:
            Dictionary mapping permissions to boolean results
        """
        self._ensure_open()
        try:
            with self._lock:
                # Check if session exists and not expired
                if session_id not in self._sessions or self._is_expired(session_id):
                    return {perm: False for perm in permissions}

                session_data = self._sessions[session_id]
                user_permissions = set(session_data.get("permissions", []))

                result = {perm: perm in user_permissions for perm in permissions}

                self._stats["total_operations"] += 1
                return result

        except Exception as e:
            raise ProviderError(f"Failed to check permissions: {e}") from e

    async def get_permissions(self, session_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_open()
        try:
            with self._lock:
                # Check if session exists and not expired
                if session_id not in self._sessions or self._is_expired(session_id):
                    return None

                # Return a deep copy to prevent external mutations
                session_data = self._sessions[session_id]
                result = {
                    "user_id": session_data["user_id"],
                    "permissions": copy.deepcopy(session_data["permissions"]),
                    "created_at": session_data["created_at"],
                    "updated_at": session_data["updated_at"],
                    "metadata": copy.deepcopy(session_data["metadata"]),
                }

                self._stats["total_operations"] += 1
                return result

        except Exception as e:
            raise ProviderError(f"Failed to get permissions: {e}") from e

    async def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate session and remove all data.

        Args:
            session_id: Session identifier

        Returns:
            True if session was invalidated
        """
        self._ensure_open()
        try:
            with self._lock:
                if session_id not in self._sessions:
                    return False

                self._remove_session_internal(session_id)
                self._stats["total_operations"] += 1
                return True

        except Exception as e:
            raise ProviderError(f"Failed to invalidate session: {e}") from e

    async def update_permissions(
        self, session_id: str, permissions: List[str], ttl: Optional[int] = None
    ) -> bool:
        """
        Update permissions for existing session.

        Args:
            session_id: Session identifier
            permissions: New permissions list
            ttl: Optional new TTL

        Returns:
            True if updated successfully
        """
        self._ensure_open()
        try:
            with self._lock:
                # Check if session exists and not expired
                if session_id not in self._sessions or self._is_expired(session_id):
                    return False

                # Update permissions
                session_data = self._sessions[session_id]
                session_data["permissions"] = permissions.copy()
                session_data["updated_at"] = datetime.now(timezone.utc).isoformat()

                # Update TTL if specified
                if ttl:
                    self._session_expiry[session_id] = time.time() + ttl

                self._stats["total_operations"] += 1
                return True

        except Exception as e:
            raise ProviderError(f"Failed to update permissions: {e}") from e

    async def extend_session_ttl(self, session_id: str, ttl: int) -> bool:
        """
        Extend TTL for existing session.

        Args:
            session_id: Session identifier
            ttl: New TTL in seconds

        Returns:
            True if TTL was extended
        """
        self._ensure_open()
        try:
            with self._lock:
                # Check if session exists and not expired
                if session_id not in self._sessions or self._is_expired(session_id):
                    return False

                # Set new expiry time
                self._session_expiry[session_id] = time.time() + ttl

                self._stats["total_operations"] += 1
                return True

        except Exception as e:
            raise ProviderError(f"Failed to extend session TTL: {e}") from e

    async def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session metadata and statistics.

        Args:
            session_id: Session identifier

        Returns:
            Dictionary containing session info
        """
        self._ensure_open()
        try:
            with self._lock:
                # Check if session exists and not expired
                if session_id not in self._sessions or self._is_expired(session_id):
                    return None

                session_data = self._sessions[session_id]

                # Calculate TTL remaining
                ttl_remaining = None
                if session_id in self._session_expiry:
                    remaining = self._session_expiry[session_id] - time.time()
                    ttl_remaining = max(0, int(remaining))

                info = {
                    **session_data,
                    "ttl_remaining": ttl_remaining,
                    "has_ttl": session_id in self._session_expiry,
                    "provider": "memory",
                }

                self._stats["total_operations"] += 1
                return info

        except Exception as e:
            raise ProviderError(f"Failed to get session info: {e}") from e

    async def list_sessions(
        self, user_id: Optional[str] = None, limit: int = 100, offset: int = 0
    ) -> List[str]:
        """
        List active sessions.

        Args:
            user_id: Optional user ID filter
            limit: Maximum sessions to return
            offset: Number of sessions to skip

        Returns:
            List of session IDs
        """
        self._ensure_open()
        try:
            with self._lock:
                if user_id:
                    # Get sessions for specific user
                    if user_id not in self._user_sessions:
                        return []

                    session_list = list(self._user_sessions[user_id])
                else:
                    # Get all sessions
                    session_list = list(self._sessions.keys())

                # Filter out expired sessions
                active_sessions = [
                    sid for sid in session_list if not self._is_expired(sid)
                ]

                # Apply pagination
                start_idx = offset
                end_idx = offset + limit
                result = active_sessions[start_idx:end_idx]

                self._stats["total_operations"] += 1
                return result

        except Exception as e:
            raise ProviderError(f"Failed to list sessions: {e}") from e

    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions manually.

        Returns:
            Number of sessions cleaned up
        """
        return await self._cleanup_expired()

    # Provider metadata
    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "memory"

    @property
    def supports_ttl(self) -> bool:
        """Return whether provider supports TTL natively."""
        return True

    # Memory-specific methods
    async def get_memory_stats(self) -> Dict[str, Any]:
        """
        Get memory provider statistics.

        Returns:
            Dictionary containing memory usage and performance stats
        """
        with self._lock:
            current_time = time.time()
            uptime = current_time - self._stats["created_at"]

            # Count active sessions (non-expired)
            active_sessions = sum(
                1 for sid in self._sessions.keys() if not self._is_expired(sid)
            )

            # Count sessions with TTL
            sessions_with_ttl = len(self._session_expiry)

            return {
                "provider": "memory",
                "uptime_seconds": int(uptime),
                "total_sessions": len(self._sessions),
                "active_sessions": active_sessions,
                "sessions_with_ttl": sessions_with_ttl,
                "unique_users": len(self._user_sessions),
                "peak_session_count": self._stats["peak_session_count"],
                "total_sessions_created": self._stats["total_sessions_created"],
                "total_sessions_expired": self._stats["total_sessions_expired"],
                "total_operations": self._stats["total_operations"],
                "storage_limit": self._config["max_sessions"],
                "cleanup_interval": self._config["cleanup_interval"],
            }

    async def clear_all_sessions(self) -> int:
        """
        WARNING: Remove ALL sessions from memory.

        Returns:
            Number of sessions removed
        """
        self._ensure_open()
        try:
            with self._lock:
                count = len(self._sessions)
                self._sessions.clear()
                self._user_sessions.clear()
                self._session_expiry.clear()

                logger.warning(f"Cleared all {count} sessions from memory")
                return count

        except Exception as e:
            raise ProviderError(f"Failed to clear sessions: {e}") from e
