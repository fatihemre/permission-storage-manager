# API Documentation

Complete API reference for Permission Storage Manager.

## Table of Contents

- [Core Classes](#core-classes)
  - [PermissionStorageManager](#permissionstoragemanager)
  - [BaseProvider](#baseprovider)
- [Providers](#providers)
  - [RedisProvider](#redisprovider)
  - [MemoryProvider](#memoryprovider)
  - [FileProvider](#fileprovider)
- [Exceptions](#exceptions)
- [Utility Functions](#utility-functions)
- [Type Definitions](#type-definitions)

---

## Core Classes

### PermissionStorageManager

Main manager class for handling permission storage across different providers.

#### Constructor

```python
PermissionStorageManager(
    provider: Union[str, BaseProvider],
    config: Optional[Dict[str, Any]] = None,
    default_ttl: Optional[int] = 3600,
    auto_initialize: bool = True
)
```

**Parameters:**
- `provider`: Provider name (string) or provider instance
- `config`: Provider-specific configuration dictionary
- `default_ttl`: Default TTL in seconds for stored permissions (default: 3600)
- `auto_initialize`: Whether to automatically initialize the provider (default: True)

**Example:**
```python
# Using provider name
manager = PermissionStorageManager("redis", {"url": "redis://localhost:6379"})

# Using provider instance
from permission_storage_manager import RedisProvider
provider = RedisProvider({"url": "redis://localhost:6379"})
manager = PermissionStorageManager(provider)
```

#### Methods

##### `async initialize() -> None`

Initialize the storage provider.

**Raises:**
- `ProviderError`: If initialization fails

**Example:**
```python
manager = PermissionStorageManager("redis", config, auto_initialize=False)
await manager.initialize()
```

##### `async close() -> None`

Close the storage provider and cleanup resources.

**Example:**
```python
await manager.close()
```

##### `async store_permissions(session_id: str, user_id: str, permissions: List[str], ttl: Optional[int] = None, metadata: Optional[Dict[str, Any]] = None) -> bool`

Store user permissions for a session.

**Parameters:**
- `session_id`: Unique session identifier
- `user_id`: User identifier
- `permissions`: List of permission strings
- `ttl`: Time-to-live in seconds (uses default_ttl if None)
- `metadata`: Additional metadata to store

**Returns:**
- `bool`: True if stored successfully

**Raises:**
- `ValidationError`: If input validation fails
- `ProviderError`: If storage operation fails

**Example:**
```python
success = await manager.store_permissions(
    session_id="session_123",
    user_id="user_456",
    permissions=["read", "write", "admin"],
    ttl=3600,
    metadata={"ip": "192.168.1.1", "user_agent": "Mozilla/5.0..."}
)
```

##### `async check_permission(session_id: str, permission: str) -> bool`

Check if a session has a specific permission.

**Parameters:**
- `session_id`: Session identifier
- `permission`: Permission string to check

**Returns:**
- `bool`: True if permission exists

**Raises:**
- `ValidationError`: If input validation fails
- `ProviderError`: If check operation fails

**Example:**
```python
has_read = await manager.check_permission("session_123", "read")
```

##### `async check_permissions(session_id: str, permissions: List[str]) -> Dict[str, bool]`

Check multiple permissions for a session.

**Parameters:**
- `session_id`: Session identifier
- `permissions`: List of permission strings to check

**Returns:**
- `Dict[str, bool]`: Dictionary mapping permission strings to boolean results

**Raises:**
- `ValidationError`: If input validation fails
- `ProviderError`: If check operation fails

**Example:**
```python
results = await manager.check_permissions(
    "session_123", 
    ["read", "write", "admin", "delete"]
)
# Returns: {"read": True, "write": True, "admin": True, "delete": False}
```

##### `async get_permissions(session_id: str) -> Optional[Dict[str, Any]]`

Get all permissions and metadata for a session.

**Parameters:**
- `session_id`: Session identifier

**Returns:**
- `Optional[Dict[str, Any]]`: Dictionary containing permissions data or None if not found

**Response Format:**
```python
{
    "user_id": "user_456",
    "permissions": ["read", "write", "admin"],
    "created_at": "2024-01-01T12:00:00Z",
    "updated_at": "2024-01-01T12:00:00Z",
    "metadata": {"ip": "192.168.1.1", "user_agent": "..."}
}
```

**Raises:**
- `ValidationError`: If input validation fails
- `ProviderError`: If operation fails

**Example:**
```python
data = await manager.get_permissions("session_123")
if data:
    print(f"User: {data['user_id']}")
    print(f"Permissions: {data['permissions']}")
```

##### `async invalidate_session(session_id: str) -> bool`

Invalidate/delete a session and its permissions.

**Parameters:**
- `session_id`: Session identifier to invalidate

**Returns:**
- `bool`: True if session was invalidated

**Raises:**
- `ValidationError`: If input validation fails
- `ProviderError`: If operation fails

**Example:**
```python
success = await manager.invalidate_session("session_123")
```

##### `async update_permissions(session_id: str, permissions: List[str], ttl: Optional[int] = None) -> bool`

Update permissions for an existing session.

**Parameters:**
- `session_id`: Session identifier
- `permissions`: New list of permission strings
- `ttl`: Optional new TTL in seconds

**Returns:**
- `bool`: True if updated successfully

**Raises:**
- `ValidationError`: If input validation fails
- `ProviderError`: If operation fails

**Example:**
```python
success = await manager.update_permissions(
    "session_123", 
    ["read", "write", "admin", "super_admin"],
    ttl=7200
)
```

##### `async extend_session_ttl(session_id: str, ttl: int) -> bool`

Extend the TTL of an existing session.

**Parameters:**
- `session_id`: Session identifier
- `ttl`: New TTL in seconds

**Returns:**
- `bool`: True if TTL was extended

**Raises:**
- `ValidationError`: If input validation fails
- `ProviderError`: If operation fails

**Example:**
```python
success = await manager.extend_session_ttl("session_123", 3600)
```

##### `async get_session_info(session_id: str) -> Optional[Dict[str, Any]]`

Get session metadata and statistics.

**Parameters:**
- `session_id`: Session identifier

**Returns:**
- `Optional[Dict[str, Any]]`: Dictionary containing session info or None if not found

**Response Format:**
```python
{
    "user_id": "user_456",
    "permissions": ["read", "write"],
    "created_at": "2024-01-01T12:00:00Z",
    "updated_at": "2024-01-01T12:00:00Z",
    "metadata": {},
    "ttl_remaining": 3456,  # seconds remaining, None if no TTL
    "has_ttl": True,
    "provider": "redis"
}
```

**Example:**
```python
info = await manager.get_session_info("session_123")
if info:
    print(f"TTL remaining: {info['ttl_remaining']} seconds")
```

##### `async list_sessions(user_id: Optional[str] = None, limit: int = 100, offset: int = 0) -> List[str]`

List active sessions.

**Parameters:**
- `user_id`: Optional user ID to filter sessions
- `limit`: Maximum number of sessions to return (default: 100)
- `offset`: Number of sessions to skip (default: 0)

**Returns:**
- `List[str]`: List of session IDs

**Example:**
```python
# List all sessions
all_sessions = await manager.list_sessions()

# List sessions for specific user
user_sessions = await manager.list_sessions(user_id="user_456")

# Paginated listing
page_sessions = await manager.list_sessions(limit=50, offset=100)
```

##### `async cleanup_expired_sessions() -> int`

Clean up expired sessions.

**Returns:**
- `int`: Number of sessions cleaned up

**Example:**
```python
cleaned_count = await manager.cleanup_expired_sessions()
print(f"Cleaned up {cleaned_count} expired sessions")
```

#### Synchronous Methods

All async methods have synchronous counterparts with `_sync` suffix:

```python
# Synchronous versions
manager.store_permissions_sync(session_id, user_id, permissions)
manager.check_permission_sync(session_id, permission)
manager.check_permissions_sync(session_id, permissions)
manager.get_permissions_sync(session_id)
manager.invalidate_session_sync(session_id)
```

#### Properties

##### `provider_name: str`

Get the name of the current provider.

```python
print(manager.provider_name)  # "redis", "memory", or "file"
```

##### `is_initialized: bool`

Check if the manager is initialized.

```python
if manager.is_initialized:
    print("Manager is ready")
```

##### `supports_ttl: bool`

Check if the current provider supports TTL natively.

```python
if manager.supports_ttl:
    print("Provider has native TTL support")
```

#### Class Methods

##### `register_provider(name: str, provider_class: Type[BaseProvider]) -> None`

Register a new provider class.

**Parameters:**
- `name`: Provider name
- `provider_class`: Provider class that extends BaseProvider

**Example:**
```python
from permission_storage_manager import PermissionStorageManager, BaseProvider

class CustomProvider(BaseProvider):
    # Implementation here
    pass

PermissionStorageManager.register_provider("custom", CustomProvider)
manager = PermissionStorageManager("custom", config)
```

##### `get_available_providers() -> List[str]`

Get list of available provider names.

**Returns:**
- `List[str]`: List of registered provider names

**Example:**
```python
providers = PermissionStorageManager.get_available_providers()
print(providers)  # ["redis", "memory", "file", "custom"]
```

#### Context Manager Support

The manager supports both async and sync context managers:

```python
# Async context manager
async with PermissionStorageManager("redis", config) as manager:
    await manager.store_permissions("session_1", "user_1", ["read"])

# Sync context manager
with PermissionStorageManager("memory") as manager:
    manager.store_permissions_sync("session_1", "user_1", ["read"])
```

---

### BaseProvider

Abstract base class that all storage providers must implement.

#### Constructor

```python
BaseProvider(config: Dict[str, Any] = None)
```

**Parameters:**
- `config`: Provider-specific configuration dictionary

#### Abstract Methods

All concrete providers must implement these methods:

##### `async initialize() -> None`
Initialize the provider connection/resources.

##### `async close() -> None`
Close provider connections and cleanup resources.

##### `async store_permissions(...) -> bool`
Store user permissions for a session.

##### `async check_permission(...) -> bool`
Check if a session has a specific permission.

##### `async check_permissions(...) -> Dict[str, bool]`
Check multiple permissions for a session.

##### `async get_permissions(...) -> Optional[Dict[str, Any]]`
Get all permissions and metadata for a session.

##### `async invalidate_session(...) -> bool`
Invalidate/delete a session and its permissions.

##### `async update_permissions(...) -> bool`
Update permissions for an existing session.

##### `async extend_session_ttl(...) -> bool`
Extend the TTL of an existing session.

##### `async get_session_info(...) -> Optional[Dict[str, Any]]`
Get session metadata and statistics.

##### `async list_sessions(...) -> List[str]`
List active sessions.

##### `async cleanup_expired_sessions() -> int`
Clean up expired sessions.

#### Abstract Properties

##### `provider_name: str`
Return the name of this provider.

##### `supports_ttl: bool`
Return whether this provider supports TTL natively.

---

## Providers

### RedisProvider

Redis-based storage provider with high performance and native TTL support.

#### Configuration

```python
config = {
    "url": "redis://localhost:6379/0",           # Redis connection URL
    "host": "localhost",                         # Alternative to URL
    "port": 6379,                               # Redis port
    "db": 0,                                    # Database number
    "password": "your_password",                # Authentication
    "username": "your_username",                # Username (Redis 6+)
    "socket_timeout": 5.0,                      # Socket timeout
    "socket_connect_timeout": 5.0,              # Connection timeout
    "health_check_interval": 30,                # Health check interval
    "retry_on_timeout": True,                   # Retry on timeout
    "decode_responses": True,                   # Decode responses to strings
    "max_connections": 50,                      # Connection pool size
    "key_prefix": "psm:",                       # Key prefix for isolation
    "ssl": True,                                # Enable SSL
    "ssl_cert_reqs": "required",               # SSL certificate requirements
    "ssl_ca_certs": "/path/to/ca.pem"          # SSL CA certificates
}
```

#### Redis-Specific Methods

##### `async get_connection_info() -> Dict[str, Any]`

Get Redis connection information and statistics.

**Returns:**
```python
{
    "status": "connected",
    "redis_version": "6.2.6",
    "connected_clients": 5,
    "used_memory_human": "2.4M",
    "uptime_in_seconds": 86400,
    "keyspace": {"db0": {"keys": 42, "expires": 10}},
    "key_prefix": "psm:"
}
```

##### `async flush_all_sessions() -> int`

**WARNING**: Remove ALL sessions managed by this provider.

**Returns:**
- `int`: Number of keys removed

---

### MemoryProvider

In-memory storage provider ideal for development and testing.

#### Configuration

```python
config = {
    "cleanup_interval": 60,        # Background cleanup interval in seconds
    "max_sessions": 10000,         # Maximum number of sessions to store
    "enable_monitoring": True      # Enable memory usage monitoring
}
```

#### Memory-Specific Methods

##### `async get_memory_stats() -> Dict[str, Any]`

Get memory provider statistics.

**Returns:**
```python
{
    "provider": "memory",
    "uptime_seconds": 3600,
    "total_sessions": 150,
    "active_sessions": 140,
    "sessions_with_ttl": 100,
    "unique_users": 50,
    "peak_session_count": 200,
    "total_sessions_created": 500,
    "total_sessions_expired": 10,
    "total_operations": 1500,
    "storage_limit": 10000,
    "cleanup_interval": 60
}
```

##### `async clear_all_sessions() -> int`

**WARNING**: Remove ALL sessions from memory.

**Returns:**
- `int`: Number of sessions removed

---

### FileProvider

File-based storage provider for simple deployments with data persistence.

#### Configuration

```python
config = {
    "storage_dir": "./permission_storage",     # Directory to store session files
    "cleanup_interval": 300,                   # Background cleanup interval
    "enable_backup": True,                     # Enable backup creation
    "max_backup_files": 5,                     # Maximum backup files to keep
    "file_permissions": 0o600,                 # File permissions (octal)
    "atomic_writes": True,                     # Use atomic writes for safety
    "compress_files": False                    # Compress stored files
}
```

#### File-Specific Methods

##### `async get_storage_stats() -> Dict[str, Any]`

Get file storage statistics.

**Returns:**
```python
{
    "provider": "file",
    "uptime_seconds": 3600,
    "total_sessions_created": 100,
    "total_sessions_expired": 5,
    "total_file_operations": 500,
    "total_cleanup_runs": 12,
    "cleanup_interval": 300,
    "enable_backup": True,
    "max_backup_files": 5,
    "session_files": 95,
    "user_index_files": 20,
    "backup_files": 15,
    "total_size_bytes": 1048576,
    "backup_size_bytes": 204800,
    "storage_directory": "/var/lib/app/permissions"
}
```

##### `async clear_all_sessions() -> int`

**WARNING**: Remove ALL session files.

**Returns:**
- `int`: Number of sessions removed

---

## Exceptions

### Base Exceptions

#### `PermissionStorageError`

Base exception for all permission storage related errors.

**Attributes:**
- `message`: Error message
- `details`: Additional error details (dict)

#### `ProviderError`

Raised when a storage provider encounters an error.

#### `ProviderConnectionError`

Raised when provider cannot establish or maintain connection.

#### `ProviderNotInitializedError`

Raised when trying to use provider before initialization.

#### `ProviderConfigurationError`

Raised when provider configuration is invalid.

#### `ProviderNotSupportedError`

Raised when trying to use an unsupported provider.

### Session Exceptions

#### `SessionNotFoundError`

Raised when a session is not found.

**Attributes:**
- `session_id`: The session ID that was not found

#### `SessionExpiredError`

Raised when a session has expired.

#### `InvalidSessionIdError`

Raised when session ID format is invalid.

### Permission Exceptions

#### `InvalidPermissionError`

Raised when permission format is invalid.

#### `InvalidUserIdError`

Raised when user ID format is invalid.

### Operation Exceptions

#### `TTLError`

Raised when TTL value is invalid.

#### `OperationTimeoutError`

Raised when a provider operation times out.

#### `ConcurrencyError`

Raised when concurrent operations conflict.

#### `StorageQuotaExceededError`

Raised when storage quota is exceeded.

#### `SerializationError`

Raised when data serialization/deserialization fails.

#### `ValidationError`

Raised when input validation fails.

---

## Utility Functions

### Session ID Utilities

#### `generate_session_id(prefix: str = "session", length: int = 32) -> str`

Generate a secure session ID.

#### `is_valid_session_id(session_id: str) -> bool`

Check if session ID format is valid.

#### `normalize_session_id(session_id: str) -> str`

Normalize session ID by removing invalid characters.

### Permission Utilities

#### `normalize_permissions(permissions: List[str]) -> List[str]`

Normalize permission list by removing duplicates and empty values.

#### `merge_permissions(current: List[str], new: List[str], mode: str = "replace") -> List[str]`

Merge permission lists according to specified mode.

#### `has_any_permission(user_permissions: List[str], required_permissions: List[str]) -> bool`

Check if user has any of the required permissions.

#### `has_all_permissions(user_permissions: List[str], required_permissions: List[str]) -> bool`

Check if user has all required permissions.

#### `match_permission_pattern(permission: str, pattern: str) -> bool`

Check if permission matches a pattern with wildcards.

#### `filter_permissions_by_pattern(permissions: List[str], pattern: str) -> List[str]`

Filter permissions by pattern.

### Time and TTL Utilities

#### `parse_ttl_string(ttl_str: str) -> int`

Parse TTL string to seconds (e.g., "1h" → 3600).

#### `format_ttl_remaining(seconds: int) -> str`

Format remaining TTL seconds to human-readable string.

#### `calculate_expiry_time(ttl: int) -> datetime`

Calculate expiry datetime from TTL.

#### `is_expired(expires_at: Union[str, datetime]) -> bool`

Check if given expiry time has passed.

### Configuration Utilities

#### `parse_provider_url(url: str) -> Dict[str, Any]`

Parse provider URL to configuration dictionary.

#### `merge_configs(base_config: Dict[str, Any], override_config: Dict[str, Any]) -> Dict[str, Any]`

Merge configuration dictionaries with deep merge.

### Convenience Functions

#### `create_manager(provider: str = "memory", config: dict = None, default_ttl: int = 3600) -> PermissionStorageManager`

Convenience function to create a PermissionStorageManager instance.

---

## Type Definitions

### Common Types

```python
from typing import Dict, List, Any, Optional, Union
from datetime import datetime

# Configuration types
ProviderConfig = Dict[str, Any]
SessionMetadata = Dict[str, Any]

# Permission types
PermissionList = List[str]
PermissionCheck = Dict[str, bool]

# Session data types
SessionData = Dict[str, Any]  # Complete session information
SessionInfo = Dict[str, Any]  # Session metadata and stats
SessionList = List[str]       # List of session IDs

# Provider types
ProviderName = str            # Provider name ("redis", "memory", "file")
```

### Response Formats

#### Session Data Response

```python
{
    "user_id": str,
    "permissions": List[str],
    "created_at": str,         # ISO 8601 format
    "updated_at": str,         # ISO 8601 format
    "metadata": Dict[str, Any]
}
```

#### Session Info Response

```python
{
    "user_id": str,
    "permissions": List[str],
    "created_at": str,
    "updated_at": str,
    "metadata": Dict[str, Any],
    "ttl_remaining": Optional[int],  # Seconds remaining
    "has_ttl": bool,
    "provider": str
}
```

#### Permission Check Response

```python
{
    "permission_name": bool,  # True if user has permission
    # ... more permissions
}
```

---

## Error Handling Examples

### Basic Error Handling

```python
from permission_storage_manager import (
    PermissionStorageManager,
    ProviderError,
    ValidationError,
    SessionNotFoundError
)

try:
    manager = PermissionStorageManager("redis", config)
    await manager.store_permissions("session_1", "user_1", ["read"])
    
except ValidationError as e:
    print(f"Validation failed: {e.message}")
    
except ProviderError as e:
    print(f"Provider error: {e.message}")
    if e.details:
        print(f"Details: {e.details}")
        
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Advanced Error Handling

```python
async def safe_permission_check(manager, session_id, permission):
    """Safely check permission with comprehensive error handling."""
    try:
        return await manager.check_permission(session_id, permission)
        
    except SessionNotFoundError:
        # Session doesn't exist
        return False
        
    except SessionExpiredError:
        # Session has expired
        return False
        
    except ProviderConnectionError:
        # Connection issue - could retry
        print("Connection error - retrying...")
        await asyncio.sleep(1)
        return await manager.check_permission(session_id, permission)
        
    except ProviderError as e:
        # Other provider errors
        print(f"Provider error: {e}")
        return False
        
    except Exception as e:
        # Unexpected errors
        print(f"Unexpected error: {e}")
        return False
```

---

This completes the comprehensive API documentation. For more examples and usage patterns, see the [User Guide](user-guide.md) and [Examples](examples/) directory.