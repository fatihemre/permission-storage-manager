"""
Redis-based permission storage provider.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

import redis.asyncio as redis
from redis.exceptions import RedisError, ConnectionError as RedisConnectionError

from ..core.base import BaseProvider
from ..core.exceptions import (
    ProviderError,
    ProviderConnectionError,
    ProviderConfigurationError,
    SerializationError,
)

logger = logging.getLogger(__name__)


class RedisProvider(BaseProvider):
    """
    Redis-based storage provider for permissions.

    This provider uses Redis as the backend storage with native TTL support,
    JSON serialization, and connection pooling for optimal performance.

    Features:
    - Native Redis TTL support
    - Connection pooling
    - Automatic serialization/deserialization
    - Pipeline operations for batch processing
    - Connection health monitoring
    - Configurable key prefixes

    Configuration:
        url: Redis connection URL (default: "redis://localhost:6379")
        host: Redis host (alternative to url)
        port: Redis port (default: 6379)
        db: Redis database number (default: 0)
        password: Redis password
        username: Redis username
        ssl: Enable SSL connection
        ssl_cert_reqs: SSL certificate requirements
        ssl_ca_certs: SSL CA certificates file
        socket_timeout: Socket timeout in seconds
        socket_connect_timeout: Socket connection timeout
        health_check_interval: Health check interval in seconds
        retry_on_timeout: Retry operations on timeout
        decode_responses: Decode responses to strings
        max_connections: Maximum connections in pool
        key_prefix: Prefix for all Redis keys (default: "psm:")

    Example:
        >>> config = {
        ...     "url": "redis://localhost:6379/0",
        ...     "socket_timeout": 5.0,
        ...     "health_check_interval": 30,
        ...     "key_prefix": "myapp_perms:"
        ... }
        >>> provider = RedisProvider(config)
        >>> await provider.initialize()
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize Redis provider with configuration.

        Args:
            config: Redis configuration dictionary

        Raises:
            ProviderConfigurationError: If Redis is not available or config is invalid
        """
        super().__init__(config)

        # Check if redis is available
        try:
            import redis.asyncio as redis
        except ImportError:
            raise ProviderConfigurationError("Redis is not available")

        # Default configuration
        self._config = {
            "url": "redis://localhost:6379/0",
            "socket_timeout": 5.0,
            "socket_connect_timeout": 5.0,
            "health_check_interval": 30,
            "retry_on_timeout": True,
            "decode_responses": True,
            "max_connections": 50,
            "key_prefix": "psm:",
            **self.config,
        }

        self._redis: Optional[redis.Redis] = None
        self._connection_pool: Optional[redis.ConnectionPool] = None
        self._health_check_task: Optional[asyncio.Task] = None

        # Validate configuration
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate Redis configuration."""
        required_types = {
            "socket_timeout": (int, float),
            "socket_connect_timeout": (int, float),
            "health_check_interval": (int, float),
            "retry_on_timeout": bool,
            "decode_responses": bool,
            "max_connections": int,
            "key_prefix": str,
        }

        for key, expected_type in required_types.items():
            if key in self._config:
                value = self._config[key]
                if not isinstance(value, expected_type):
                    raise ProviderConfigurationError(
                        f"Config key '{key}' must be of type {expected_type}, got {type(value)}"
                    )

    async def initialize(self) -> None:
        """
        Initialize Redis connection and start health monitoring.

        Raises:
            ProviderConnectionError: If connection fails
            ProviderConfigurationError: If configuration is invalid
        """
        try:
            # Create connection pool
            if "url" in self._config and self._config["url"]:
                self._connection_pool = redis.ConnectionPool.from_url(
                    self._config["url"],
                    socket_timeout=self._config["socket_timeout"],
                    socket_connect_timeout=self._config["socket_connect_timeout"],
                    health_check_interval=self._config["health_check_interval"],
                    retry_on_timeout=self._config["retry_on_timeout"],
                    decode_responses=self._config["decode_responses"],
                    max_connections=self._config["max_connections"],
                )
            else:
                # Manual connection configuration
                pool_config = {
                    "host": self._config.get("host", "localhost"),
                    "port": self._config.get("port", 6379),
                    "db": self._config.get("db", 0),
                    "socket_timeout": self._config["socket_timeout"],
                    "socket_connect_timeout": self._config["socket_connect_timeout"],
                    "health_check_interval": self._config["health_check_interval"],
                    "retry_on_timeout": self._config["retry_on_timeout"],
                    "decode_responses": self._config["decode_responses"],
                    "max_connections": self._config["max_connections"],
                }

                if "password" in self._config:
                    pool_config["password"] = self._config["password"]
                if "username" in self._config:
                    pool_config["username"] = self._config["username"]

                self._connection_pool = redis.ConnectionPool(**pool_config)

            # Create Redis client
            self._redis = redis.Redis(connection_pool=self._connection_pool)

            # Test connection
            await self._redis.ping()

            # Start health check task
            self._health_check_task = asyncio.create_task(self._health_check_loop())

            self._initialized = True
            logger.info("Redis provider initialized successfully")

        except RedisConnectionError as e:
            raise ProviderConnectionError(f"Failed to connect to Redis: {e}") from e
        except Exception as e:
            raise ProviderError(f"Failed to initialize Redis provider: {e}") from e

    async def close(self) -> None:
        """Close Redis connection and cleanup resources."""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass

        if self._redis:
            await self._redis.aclose()
            self._redis = None

        if self._connection_pool:
            await self._connection_pool.aclose()
            self._connection_pool = None

        self._initialized = False
        logger.info("Redis provider closed")

    async def _health_check_loop(self) -> None:
        """Background health check task."""
        while True:
            try:
                await asyncio.sleep(self._config["health_check_interval"])
                if self._redis:
                    await self._redis.ping()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Redis health check failed: {e}")

    def _make_key(self, session_id: str) -> str:
        """Create Redis key for session."""
        return f"{self._config['key_prefix']}session:{session_id}"

    def _make_user_index_key(self, user_id: str) -> str:
        """Create Redis key for user session index."""
        return f"{self._config['key_prefix']}user_sessions:{user_id}"

    def _serialize_data(self, data: Dict[str, Any]) -> str:
        """Serialize data to JSON string."""
        try:
            return json.dumps(data, default=str, ensure_ascii=False)
        except (TypeError, ValueError) as e:
            raise SerializationError("serialize", "permission_data", str(e)) from e

    def _deserialize_data(self, data: str) -> Dict[str, Any]:
        """Deserialize JSON string to data."""
        try:
            return json.loads(data)
        except (TypeError, ValueError) as e:
            raise SerializationError("deserialize", "permission_data", str(e)) from e

    async def store_permissions(
        self,
        session_id: str,
        user_id: str,
        permissions: List[str],
        ttl: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Store user permissions in Redis.

        Args:
            session_id: Unique session identifier
            user_id: User identifier
            permissions: List of permission strings
            ttl: Time-to-live in seconds
            metadata: Additional metadata

        Returns:
            True if stored successfully

        Raises:
            ProviderError: If storage operation fails
        """
        try:
            session_key = self._make_key(session_id)
            user_index_key = self._make_user_index_key(user_id)

            # Prepare data
            data = {
                "user_id": user_id,
                "permissions": permissions,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "metadata": metadata or {},
            }

            serialized_data = self._serialize_data(data)

            # Use pipeline for atomic operations
            async with self._redis.pipeline(transaction=True) as pipe:
                # Store session data
                if ttl:
                    pipe.setex(session_key, ttl, serialized_data)
                    # Add to user index with same TTL
                    pipe.sadd(user_index_key, session_id)
                    pipe.expire(user_index_key, ttl)
                else:
                    pipe.set(session_key, serialized_data)
                    pipe.sadd(user_index_key, session_id)

                await pipe.execute()

            logger.debug(f"Stored permissions for session {session_id}")
            return True

        except RedisError as e:
            raise ProviderError(f"Failed to store permissions: {e}") from e
        except Exception as e:
            raise ProviderError(f"Unexpected error storing permissions: {e}") from e

    async def check_permission(self, session_id: str, permission: str) -> bool:
        """
        Check if session has specific permission.

        Args:
            session_id: Session identifier
            permission: Permission to check

        Returns:
            True if permission exists
        """
        try:
            session_key = self._make_key(session_id)
            data = await self._redis.get(session_key)

            if not data:
                return False

            session_data = self._deserialize_data(data)
            return permission in session_data.get("permissions", [])

        except RedisError as e:
            raise ProviderError(f"Failed to check permission: {e}") from e
        except Exception as e:
            raise ProviderError(f"Unexpected error checking permission: {e}") from e

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
        try:
            session_key = self._make_key(session_id)
            data = await self._redis.get(session_key)

            if not data:
                return {perm: False for perm in permissions}

            session_data = self._deserialize_data(data)
            user_permissions = set(session_data.get("permissions", []))

            return {perm: perm in user_permissions for perm in permissions}

        except RedisError as e:
            raise ProviderError(f"Failed to check permissions: {e}") from e
        except Exception as e:
            raise ProviderError(f"Unexpected error checking permissions: {e}") from e

    async def get_permissions(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get all permissions and metadata for session.

        Args:
            session_id: Session identifier

        Returns:
            Dictionary containing session data or None if not found
        """
        try:
            session_key = self._make_key(session_id)
            data = await self._redis.get(session_key)

            if not data:
                return None

            return self._deserialize_data(data)

        except RedisError as e:
            raise ProviderError(f"Failed to get permissions: {e}") from e
        except Exception as e:
            raise ProviderError(f"Unexpected error getting permissions: {e}") from e

    async def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate session and remove from user index.

        Args:
            session_id: Session identifier

        Returns:
            True if session was invalidated
        """
        try:
            session_key = self._make_key(session_id)

            # Get session data to find user_id
            data = await self._redis.get(session_key)
            if not data:
                return False

            session_data = self._deserialize_data(data)
            user_id = session_data.get("user_id")

            # Use pipeline for atomic operations
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.delete(session_key)
                if user_id:
                    user_index_key = self._make_user_index_key(user_id)
                    pipe.srem(user_index_key, session_id)

                results = await pipe.execute()

            # First result is from DELETE command (1 if key existed, 0 if not)
            return bool(results[0])

        except RedisError as e:
            raise ProviderError(f"Failed to invalidate session: {e}") from e
        except Exception as e:
            raise ProviderError(f"Unexpected error invalidating session: {e}") from e

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
        try:
            session_key = self._make_key(session_id)

            # Get existing data
            data = await self._redis.get(session_key)
            if not data:
                return False

            session_data = self._deserialize_data(data)

            # Update data
            session_data["permissions"] = permissions
            session_data["updated_at"] = datetime.now(timezone.utc).isoformat()

            serialized_data = self._serialize_data(session_data)

            # Update with optional TTL
            if ttl:
                await self._redis.setex(session_key, ttl, serialized_data)
            else:
                await self._redis.set(session_key, serialized_data)

            return True

        except RedisError as e:
            raise ProviderError(f"Failed to update permissions: {e}") from e
        except Exception as e:
            raise ProviderError(f"Unexpected error updating permissions: {e}") from e

    async def extend_session_ttl(self, session_id: str, ttl: int) -> bool:
        """
        Extend TTL for existing session.

        Args:
            session_id: Session identifier
            ttl: New TTL in seconds

        Returns:
            True if TTL was extended
        """
        try:
            session_key = self._make_key(session_id)
            result = await self._redis.expire(session_key, ttl)
            return bool(result)

        except RedisError as e:
            raise ProviderError(f"Failed to extend session TTL: {e}") from e
        except Exception as e:
            raise ProviderError(f"Unexpected error extending TTL: {e}") from e

    async def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session metadata and statistics.

        Args:
            session_id: Session identifier

        Returns:
            Dictionary containing session info
        """
        try:
            session_key = self._make_key(session_id)

            # Use pipeline to get data and TTL atomically
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.get(session_key)
                pipe.ttl(session_key)
                results = await pipe.execute()

            data, ttl_remaining = results

            if not data:
                return None

            session_data = self._deserialize_data(data)

            # Add Redis-specific info
            info = {
                **session_data,
                "ttl_remaining": ttl_remaining if ttl_remaining > 0 else None,
                "has_ttl": ttl_remaining > 0,
                "provider": "redis",
            }

            return info

        except RedisError as e:
            raise ProviderError(f"Failed to get session info: {e}") from e
        except Exception as e:
            raise ProviderError(f"Unexpected error getting session info: {e}") from e

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
        try:
            if user_id:
                # Get sessions for specific user
                user_index_key = self._make_user_index_key(user_id)
                sessions = await self._redis.smembers(user_index_key)
                session_list = list(sessions)
            else:
                # Get all sessions using key pattern
                pattern = f"{self._config['key_prefix']}session:*"
                keys = await self._redis.keys(pattern)
                # Extract session IDs from keys
                prefix_len = len(f"{self._config['key_prefix']}session:")
                session_list = [key[prefix_len:] for key in keys]

            # Apply pagination
            start_idx = offset
            end_idx = offset + limit
            return session_list[start_idx:end_idx]

        except RedisError as e:
            raise ProviderError(f"Failed to list sessions: {e}") from e
        except Exception as e:
            raise ProviderError(f"Unexpected error listing sessions: {e}") from e

    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions (Redis handles this automatically).

        Returns:
            Number of sessions cleaned up (always 0 for Redis)
        """
        # Redis automatically removes expired keys, so no manual cleanup needed
        # We could scan for orphaned user index entries, but that's rarely necessary
        return 0

    # Provider metadata
    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "redis"

    @property
    def supports_ttl(self) -> bool:
        """Return whether provider supports TTL natively."""
        return True

    # Additional Redis-specific methods
    async def get_connection_info(self) -> Dict[str, Any]:
        """
        Get Redis connection information.

        Returns:
            Dictionary containing connection details
        """
        if not self._redis:
            return {"status": "not_connected"}

        try:
            info = await self._redis.info()
            return {
                "status": "connected",
                "redis_version": info.get("redis_version"),
                "connected_clients": info.get("connected_clients"),
                "used_memory_human": info.get("used_memory_human"),
                "uptime_in_seconds": info.get("uptime_in_seconds"),
                "keyspace": {k: v for k, v in info.items() if k.startswith("db")},
                "key_prefix": self._config["key_prefix"],
            }
        except RedisError as e:
            return {"status": "error", "error": str(e)}

    async def flush_all_sessions(self) -> int:
        """
        WARNING: Remove ALL sessions managed by this provider.

        Returns:
            Number of keys removed
        """
        try:
            pattern = f"{self._config['key_prefix']}*"
            keys = await self._redis.keys(pattern)

            if keys:
                await self._redis.delete(*keys)
                return len(keys)

            return 0

        except RedisError as e:
            raise ProviderError(f"Failed to flush sessions: {e}") from e
