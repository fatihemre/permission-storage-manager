"""
File-based permission storage provider.
"""

import asyncio
import json
import logging
import os
import time
import fcntl
import uuid
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import threading
import shutil

from ..core.base import BaseProvider
from ..core.exceptions import (
    ProviderError,
    ProviderConfigurationError,
    SerializationError,
)

logger = logging.getLogger(__name__)


class FileProvider(BaseProvider):
    """
    File-based storage provider for permissions.

    This provider stores permissions data in JSON files on the filesystem.
    Suitable for small to medium applications that need data persistence
    without external dependencies.

    Features:
    - Zero external dependencies
    - Data persistence across restarts
    - File locking for concurrent access
    - TTL support with background cleanup
    - Configurable storage directory
    - Backup and rotation support
    - Atomic write operations

    Configuration:
        storage_dir: Directory to store session files (default: "./permission_storage")
        cleanup_interval: Background cleanup interval in seconds (default: 300)
        enable_backup: Enable backup creation before updates (default: True)
        max_backup_files: Maximum backup files to keep (default: 5)
        file_permissions: File permissions in octal (default: 0o600)
        atomic_writes: Use atomic writes for safety (default: True)
        compress_files: Compress stored files (default: False)

    Example:
        >>> config = {
        ...     "storage_dir": "/var/lib/myapp/permissions",
        ...     "cleanup_interval": 600,
        ...     "enable_backup": True,
        ...     "max_backup_files": 10
        ... }
        >>> provider = FileProvider(config)
        >>> await provider.initialize()

    File Structure:
        storage_dir/
        ├── sessions/
        │   ├── session_123.json
        │   └── session_456.json
        ├── user_index/
        │   ├── user_789.json
        │   └── user_012.json
        ├── metadata.json
        └── backups/ (if enabled)
            ├── session_123.json.bak.1
            └── session_123.json.bak.2
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize file provider with configuration.

        Args:
            config: File provider configuration dictionary
        """
        super().__init__(config)

        # Default configuration
        self._config = {
            "storage_dir": "./permission_storage",
            "cleanup_interval": 300,  # 5 minutes
            "enable_backup": True,
            "max_backup_files": 5,
            "file_permissions": 0o600,  # Read/write for owner only
            "atomic_writes": True,
            "compress_files": False,
            **self.config,
        }

        # Storage paths
        self._storage_dir = Path(self._config["storage_dir"])
        self._sessions_dir = self._storage_dir / "sessions"
        self._user_index_dir = self._storage_dir / "user_index"
        self._backups_dir = self._storage_dir / "backups"
        self._metadata_file = self._storage_dir / "metadata.json"

        # File locking
        self._locks: Dict[str, threading.RLock] = {}
        self._locks_lock = threading.RLock()

        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None

        # Statistics
        self._stats = {
            "created_at": time.time(),
            "total_sessions_created": 0,
            "total_sessions_expired": 0,
            "total_file_operations": 0,
            "total_cleanup_runs": 0,
        }

        self._validate_config()

    def _validate_config(self) -> None:
        """Validate file provider configuration."""
        storage_dir = self._config["storage_dir"]
        if not isinstance(storage_dir, (str, Path)):
            raise ProviderConfigurationError("storage_dir must be a string or Path")

        if self._config["cleanup_interval"] <= 0:
            raise ProviderConfigurationError("cleanup_interval must be positive")

        if self._config["max_backup_files"] < 0:
            raise ProviderConfigurationError("max_backup_files must be non-negative")

    def _get_file_lock(self, identifier: str) -> threading.RLock:
        """Get or create a file lock for the given identifier."""
        with self._locks_lock:
            if identifier not in self._locks:
                self._locks[identifier] = threading.RLock()
            return self._locks[identifier]

    async def initialize(self) -> None:
        """
        Initialize the file provider and create directory structure.

        Raises:
            ProviderError: If initialization fails
        """
        try:
            # Create directory structure
            self._storage_dir.mkdir(parents=True, exist_ok=True)
            self._sessions_dir.mkdir(exist_ok=True)
            self._user_index_dir.mkdir(exist_ok=True)

            if self._config["enable_backup"]:
                self._backups_dir.mkdir(exist_ok=True)

            # Set directory permissions
            os.chmod(self._storage_dir, 0o700)  # rwx for owner only
            os.chmod(self._sessions_dir, 0o700)
            os.chmod(self._user_index_dir, 0o700)

            # Initialize metadata file if it doesn't exist
            if not self._metadata_file.exists():
                metadata = {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "provider": "file",
                    "version": "1.0.2",
                }
                await self._write_file(self._metadata_file, metadata)

            # Start background cleanup task
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

            self._initialized = True
            logger.info(f"File provider initialized with storage: {self._storage_dir}")

        except Exception as e:
            raise ProviderError(f"Failed to initialize file provider: {e}") from e

    async def close(self) -> None:
        """Close the provider and cleanup resources."""
        # Cancel background tasks
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Clear locks
        with self._locks_lock:
            self._locks.clear()

        self._initialized = False
        logger.info("File provider closed")

    async def _cleanup_loop(self) -> None:
        """Background task to clean up expired sessions."""
        while True:
            try:
                await asyncio.sleep(self._config["cleanup_interval"])
                await self.cleanup_expired_sessions()
                self._stats["total_cleanup_runs"] += 1
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Error in cleanup loop: {e}")

    def _get_session_file(self, session_id: str) -> Path:
        """Get file path for session."""
        return self._sessions_dir / f"{session_id}.json"

    def _get_user_index_file(self, user_id: str) -> Path:
        """Get file path for user session index."""
        return self._user_index_dir / f"{user_id}.json"

    async def _read_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Read and parse JSON file."""
        try:
            if not file_path.exists():
                return None

            def _read_sync():
                with open(file_path, "r", encoding="utf-8") as f:
                    # Use file locking for concurrent access
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # Shared lock for reading
                    try:
                        return json.load(f)
                    finally:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)  # Unlock

            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, _read_sync)

            self._stats["total_file_operations"] += 1
            return data

        except (json.JSONDecodeError, IOError) as e:
            raise SerializationError("read", str(file_path), str(e)) from e

    async def _write_file(self, file_path: Path, data: Dict[str, Any]) -> None:
        """Write data to JSON file with optional backup."""
        try:

            def _write_sync():
                # Ensure directory exists
                file_path.parent.mkdir(parents=True, exist_ok=True)

                # Create backup if enabled and file exists
                if self._config["enable_backup"] and file_path.exists():
                    self._create_backup(file_path)

                # Atomic write using temporary file
                if self._config["atomic_writes"]:
                    temp_file = file_path.with_suffix(
                        f".tmp.{os.getpid()}.{uuid.uuid4().hex}"
                    )
                    temp_file_created = False

                    try:
                        # Create temp file with exclusive access
                        with open(temp_file, "w", encoding="utf-8") as f:
                            fcntl.flock(f.fileno(), fcntl.LOCK_EX)  # Exclusive lock
                            try:
                                json.dump(data, f, indent=2, ensure_ascii=False)
                                f.flush()
                                os.fsync(f.fileno())  # Force write to disk
                                temp_file_created = True
                            finally:
                                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

                        # Set file permissions only if temp file was created successfully
                        if temp_file_created and temp_file.exists():
                            os.chmod(temp_file, self._config["file_permissions"])

                            # Atomic move - ensure temp file still exists
                            if temp_file.exists():
                                temp_file.replace(file_path)
                            else:
                                raise IOError(
                                    f"Temporary file {temp_file} was deleted during write operation"
                                )
                        else:
                            raise IOError(
                                f"Failed to create temporary file {temp_file}"
                            )

                    except Exception:
                        # Cleanup temp file on error
                        if temp_file.exists():
                            temp_file.unlink()
                        raise
                else:
                    # Direct write
                    with open(file_path, "w", encoding="utf-8") as f:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)  # Exclusive lock
                        try:
                            json.dump(data, f, indent=2, ensure_ascii=False)
                            f.flush()
                            os.fsync(f.fileno())
                        finally:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

                    # Set file permissions
                    os.chmod(file_path, self._config["file_permissions"])

            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _write_sync)

            self._stats["total_file_operations"] += 1

        except (TypeError, IOError) as e:
            raise SerializationError("write", str(file_path), str(e)) from e

    def _create_backup(self, file_path: Path) -> None:
        """Create backup of existing file."""
        if not self._config["enable_backup"] or not file_path.exists():
            return

        try:
            backup_base = self._backups_dir / f"{file_path.name}.bak"

            # Find next backup number
            backup_num = 1
            while (backup_file := Path(f"{backup_base}.{backup_num}")).exists():
                backup_num += 1

            # Copy file to backup
            shutil.copy2(file_path, backup_file)

            # Cleanup old backups
            self._cleanup_old_backups(file_path.name)

        except Exception as e:
            logger.warning(f"Failed to create backup for {file_path}: {e}")

    def _cleanup_old_backups(self, filename: str) -> None:
        """Remove old backup files beyond the limit."""
        try:
            backup_pattern = f"{filename}.bak.*"
            backup_files = list(self._backups_dir.glob(backup_pattern))

            if len(backup_files) > self._config["max_backup_files"]:
                # Sort by modification time (oldest first)
                backup_files.sort(key=lambda p: p.stat().st_mtime)

                # Remove oldest files
                excess_count = len(backup_files) - self._config["max_backup_files"]
                for backup_file in backup_files[:excess_count]:
                    backup_file.unlink()

        except Exception as e:
            logger.warning(f"Failed to cleanup old backups for {filename}: {e}")

    async def _delete_file(self, file_path: Path) -> bool:
        """Delete file safely."""
        try:
            if not file_path.exists():
                return False

            def _delete_sync():
                file_path.unlink()
                return True

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, _delete_sync)

            self._stats["total_file_operations"] += 1
            return result

        except Exception as e:
            logger.warning(f"Failed to delete file {file_path}: {e}")
            return False

    def _is_expired(self, session_data: Dict[str, Any]) -> bool:
        """Check if session data indicates expiration."""
        if "expires_at" not in session_data:
            return False

        expires_at = datetime.fromisoformat(
            session_data["expires_at"].replace("Z", "+00:00")
        )
        return datetime.now(timezone.utc) > expires_at

    async def store_permissions(
        self,
        session_id: str,
        user_id: str,
        permissions: List[str],
        ttl: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Store user permissions in file.

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
            session_lock = self._get_file_lock(f"session_{session_id}")
            user_lock = self._get_file_lock(f"user_{user_id}")

            with session_lock, user_lock:
                # Prepare session data
                now = datetime.now(timezone.utc)
                session_data = {
                    "user_id": user_id,
                    "permissions": permissions,
                    "created_at": now.isoformat(),
                    "updated_at": now.isoformat(),
                    "metadata": metadata or {},
                }

                # Add expiration if TTL specified
                if ttl:
                    expires_at = datetime.fromtimestamp(time.time() + ttl, timezone.utc)
                    session_data["expires_at"] = expires_at.isoformat()

                # Write session file
                session_file = self._get_session_file(session_id)
                await self._write_file(session_file, session_data)

                # Update user index
                user_index_file = self._get_user_index_file(user_id)
                user_index = await self._read_file(user_index_file) or {"sessions": []}

                if session_id not in user_index["sessions"]:
                    user_index["sessions"].append(session_id)
                    user_index["updated_at"] = now.isoformat()
                    await self._write_file(user_index_file, user_index)

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
        try:
            session_lock = self._get_file_lock(f"session_{session_id}")

            with session_lock:
                session_file = self._get_session_file(session_id)
                session_data = await self._read_file(session_file)

                if not session_data or self._is_expired(session_data):
                    return False

                return permission in session_data.get("permissions", [])

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
        try:
            session_lock = self._get_file_lock(f"session_{session_id}")

            with session_lock:
                session_file = self._get_session_file(session_id)
                session_data = await self._read_file(session_file)

                if not session_data or self._is_expired(session_data):
                    return {perm: False for perm in permissions}

                user_permissions = set(session_data.get("permissions", []))
                return {perm: perm in user_permissions for perm in permissions}

        except Exception as e:
            raise ProviderError(f"Failed to check permissions: {e}") from e

    async def get_permissions(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get all permissions and metadata for session.

        Args:
            session_id: Session identifier

        Returns:
            Dictionary containing session data or None if not found
        """
        try:
            session_lock = self._get_file_lock(f"session_{session_id}")

            with session_lock:
                session_file = self._get_session_file(session_id)
                session_data = await self._read_file(session_file)

                if not session_data or self._is_expired(session_data):
                    return None

                # Remove internal fields
                result = session_data.copy()
                result.pop("expires_at", None)

                return result

        except Exception as e:
            raise ProviderError(f"Failed to get permissions: {e}") from e

    async def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate session and remove files.

        Args:
            session_id: Session identifier

        Returns:
            True if session was invalidated
        """
        try:
            session_lock = self._get_file_lock(f"session_{session_id}")

            with session_lock:
                session_file = self._get_session_file(session_id)
                session_data = await self._read_file(session_file)

                if not session_data:
                    return False

                user_id = session_data.get("user_id")

                # Remove session file
                deleted = await self._delete_file(session_file)

                # Update user index
                if user_id and deleted:
                    user_lock = self._get_file_lock(f"user_{user_id}")
                    with user_lock:
                        user_index_file = self._get_user_index_file(user_id)
                        user_index = await self._read_file(user_index_file)

                        if user_index and session_id in user_index.get("sessions", []):
                            user_index["sessions"].remove(session_id)
                            user_index["updated_at"] = datetime.now(
                                timezone.utc
                            ).isoformat()

                            if user_index["sessions"]:
                                await self._write_file(user_index_file, user_index)
                            else:
                                # Remove empty user index
                                await self._delete_file(user_index_file)

                return deleted

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
        try:
            session_lock = self._get_file_lock(f"session_{session_id}")

            with session_lock:
                session_file = self._get_session_file(session_id)
                session_data = await self._read_file(session_file)

                if not session_data or self._is_expired(session_data):
                    return False

                # Update permissions and timestamp
                session_data["permissions"] = permissions
                session_data["updated_at"] = datetime.now(timezone.utc).isoformat()

                # Update TTL if specified
                if ttl:
                    expires_at = datetime.fromtimestamp(time.time() + ttl, timezone.utc)
                    session_data["expires_at"] = expires_at.isoformat()

                await self._write_file(session_file, session_data)
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
        try:
            session_lock = self._get_file_lock(f"session_{session_id}")

            with session_lock:
                session_file = self._get_session_file(session_id)
                session_data = await self._read_file(session_file)

                if not session_data or self._is_expired(session_data):
                    return False

                # Set new expiration
                expires_at = datetime.fromtimestamp(time.time() + ttl, timezone.utc)
                session_data["expires_at"] = expires_at.isoformat()
                session_data["updated_at"] = datetime.now(timezone.utc).isoformat()

                await self._write_file(session_file, session_data)
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
        try:
            session_lock = self._get_file_lock(f"session_{session_id}")

            with session_lock:
                session_file = self._get_session_file(session_id)
                session_data = await self._read_file(session_file)

                if not session_data or self._is_expired(session_data):
                    return None

                # Calculate TTL remaining
                ttl_remaining = None
                has_ttl = False

                if "expires_at" in session_data:
                    has_ttl = True
                    expires_at = datetime.fromisoformat(
                        session_data["expires_at"].replace("Z", "+00:00")
                    )
                    remaining = expires_at - datetime.now(timezone.utc)
                    ttl_remaining = max(0, int(remaining.total_seconds()))

                info = {
                    **session_data,
                    "ttl_remaining": ttl_remaining,
                    "has_ttl": has_ttl,
                    "provider": "file",
                    "file_path": str(session_file),
                }

                # Remove internal fields
                info.pop("expires_at", None)

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
        try:
            if user_id:
                # Get sessions from user index
                user_lock = self._get_file_lock(f"user_{user_id}")
                with user_lock:
                    user_index_file = self._get_user_index_file(user_id)
                    user_index = await self._read_file(user_index_file)

                    if not user_index:
                        return []

                    session_list = user_index.get("sessions", [])
            else:
                # Scan all session files
                def _scan_sessions():
                    return [f.stem for f in self._sessions_dir.glob("*.json")]

                loop = asyncio.get_event_loop()
                session_list = await loop.run_in_executor(None, _scan_sessions)

            # Filter out expired sessions
            active_sessions = []
            for session_id in session_list:
                session_lock = self._get_file_lock(f"session_{session_id}")
                with session_lock:
                    session_file = self._get_session_file(session_id)
                    session_data = await self._read_file(session_file)

                    if session_data and not self._is_expired(session_data):
                        active_sessions.append(session_id)

            # Apply pagination
            start_idx = offset
            end_idx = offset + limit
            return active_sessions[start_idx:end_idx]

        except Exception as e:
            raise ProviderError(f"Failed to list sessions: {e}") from e

    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired session files.

        Returns:
            Number of sessions cleaned up
        """
        try:

            def _scan_all_sessions():
                return list(self._sessions_dir.glob("*.json"))

            loop = asyncio.get_event_loop()
            session_files = await loop.run_in_executor(None, _scan_all_sessions)

            cleaned_count = 0

            for session_file in session_files:
                session_id = session_file.stem
                session_lock = self._get_file_lock(f"session_{session_id}")

                with session_lock:
                    session_data = await self._read_file(session_file)

                    if session_data and self._is_expired(session_data):
                        # Remove expired session
                        user_id = session_data.get("user_id")
                        await self._delete_file(session_file)

                        # Update user index
                        if user_id:
                            user_lock = self._get_file_lock(f"user_{user_id}")
                            with user_lock:
                                user_index_file = self._get_user_index_file(user_id)
                                user_index = await self._read_file(user_index_file)

                                if user_index and session_id in user_index.get(
                                    "sessions", []
                                ):
                                    user_index["sessions"].remove(session_id)

                                    if user_index["sessions"]:
                                        await self._write_file(
                                            user_index_file, user_index
                                        )
                                    else:
                                        await self._delete_file(user_index_file)

                        cleaned_count += 1

            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired sessions")
                self._stats["total_sessions_expired"] += cleaned_count

            return cleaned_count

        except Exception as e:
            raise ProviderError(f"Failed to cleanup expired sessions: {e}") from e

    # Provider metadata
    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "file"

    @property
    def supports_ttl(self) -> bool:
        """Return whether provider supports TTL natively."""
        return True

    # File-specific methods
    async def get_storage_stats(self) -> Dict[str, Any]:
        """
        Get file storage statistics.

        Returns:
            Dictionary containing storage usage and performance stats
        """
        try:

            def _calculate_stats():
                # Count files and calculate sizes
                session_files = list(self._sessions_dir.glob("*.json"))
                user_index_files = list(self._user_index_dir.glob("*.json"))
                backup_files = (
                    list(self._backups_dir.glob("*"))
                    if self._backups_dir.exists()
                    else []
                )

                total_size = sum(
                    f.stat().st_size for f in session_files + user_index_files
                )
                backup_size = sum(f.stat().st_size for f in backup_files)

                return {
                    "session_files": len(session_files),
                    "user_index_files": len(user_index_files),
                    "backup_files": len(backup_files),
                    "total_size_bytes": total_size,
                    "backup_size_bytes": backup_size,
                    "storage_directory": str(self._storage_dir),
                }

            loop = asyncio.get_event_loop()
            file_stats = await loop.run_in_executor(None, _calculate_stats)

            return {
                "provider": "file",
                "uptime_seconds": int(time.time() - self._stats["created_at"]),
                "total_sessions_created": self._stats["total_sessions_created"],
                "total_sessions_expired": self._stats["total_sessions_expired"],
                "total_file_operations": self._stats["total_file_operations"],
                "total_cleanup_runs": self._stats["total_cleanup_runs"],
                "cleanup_interval": self._config["cleanup_interval"],
                "enable_backup": self._config["enable_backup"],
                "max_backup_files": self._config["max_backup_files"],
                **file_stats,
            }

        except Exception as e:
            raise ProviderError(f"Failed to get storage stats: {e}") from e

    async def clear_all_sessions(self) -> int:
        """
        WARNING: Remove ALL session files.

        Returns:
            Number of sessions removed
        """
        try:

            def _clear_all():
                # Remove all session files
                session_files = list(self._sessions_dir.glob("*.json"))
                for f in session_files:
                    f.unlink()

                # Remove all user index files
                user_files = list(self._user_index_dir.glob("*.json"))
                for f in user_files:
                    f.unlink()

                return len(session_files)

            loop = asyncio.get_event_loop()
            count = await loop.run_in_executor(None, _clear_all)

            logger.warning(f"Cleared all {count} session files")
            return count

        except Exception as e:
            raise ProviderError(f"Failed to clear sessions: {e}") from e
