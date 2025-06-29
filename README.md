# Permission Storage Manager

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI version](https://badge.fury.io/py/permission-storage-manager.svg)](https://badge.fury.io/py/permission-storage-manager)
[![PyPI downloads](https://img.shields.io/pypi/dm/permission-storage-manager.svg)](https://pypi.org/project/permission-storage-manager/)
[![Tests](https://img.shields.io/badge/tests-passing-green.svg)](https://github.com/fatihemre/permission-storage-manager)
[![Coverage](https://img.shields.io/badge/coverage-88%25-green.svg)](https://github.com/fatihemre/permission-storage-manager)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)

A flexible, high-performance permission storage system for Python applications. Store and manage user permissions across different storage backends with a unified API.

## ✨ Features

- **🔄 Multiple Storage Providers**: Redis, Memory, File-based storage
- **⚡ Async/Sync Support**: Both asynchronous and synchronous APIs
- **⏰ TTL Support**: Automatic session expiration
- **🔒 Type Safety**: Full type hints and validation
- **🎯 High Performance**: Optimized for speed and concurrent access
- **🔧 Extensible**: Easy to add custom storage providers
- **📦 Zero Dependencies**: Memory and File providers require no external dependencies
- **🧪 Well Tested**: Comprehensive test suite with 88%+ coverage
- **🚀 Production Ready**: Battle-tested with comprehensive error handling

## 🚀 Quick Start

### Installation

```bash
# Basic installation (Memory and File providers)
pip install permission-storage-manager

# With Redis support
pip install permission-storage-manager[redis]

# With all dependencies
pip install permission-storage-manager[all]

# For development
pip install permission-storage-manager[dev]
```

### Basic Usage

```python
import asyncio
from permission_storage_manager import PermissionStorageManager

async def main():
    # Create manager with memory provider (no dependencies)
    manager = PermissionStorageManager("memory")
    
    # Store user permissions
    await manager.store_permissions(
        session_id="session_123",
        user_id="user_456",
        permissions=["read", "write", "admin"],
        ttl=3600  # 1 hour
    )
    
    # Check permissions
    has_read = await manager.check_permission("session_123", "read")
    print(f"Has read permission: {has_read}")  # True
    
    # Check multiple permissions
    results = await manager.check_permissions("session_123", ["read", "delete"])
    print(f"Permission results: {results}")  # {"read": True, "delete": False}
    
    # Get all permissions
    data = await manager.get_permissions("session_123")
    print(f"User permissions: {data['permissions']}")  # ["read", "write", "admin"]
    
    # Clean up
    await manager.invalidate_session("session_123")
    await manager.close()

# Run the example
asyncio.run(main())
```

### Synchronous Usage

```python
from permission_storage_manager import PermissionStorageManager

# Create manager
manager = PermissionStorageManager("memory")

# Store permissions (sync)
manager.store_permissions_sync("session_123", "user_456", ["read", "write"])

# Check permissions (sync)
has_read = manager.check_permission_sync("session_123", "read")
print(f"Has read permission: {has_read}")  # True

# Clean up
manager.close()
```

### Provider Comparison

| Feature | Redis | Memory | File |
|---------|-------|--------|------|
| **Performance** | High | Highest | Medium |
| **Persistence** | Yes | No | Yes |
| **TTL Support** | Native | Emulated | Emulated |
| **Clustering** | Yes | No | No |
| **Dependencies** | Redis | None | None |
| **Use Case** | Production | Dev/Test | Simple Deploy |

## 📚 Storage Providers

### Redis Provider (Production)

```python
from permission_storage_manager import PermissionStorageManager

manager = PermissionStorageManager(
    provider="redis",
    config={
        "url": "redis://localhost:6379/0",
        "socket_timeout": 5.0,
        "max_connections": 50,
        "key_prefix": "app_perms:"
    }
)
```

**Features:**
- Native TTL support
- Connection pooling
- High availability
- Clustering support
- Atomic operations

### Memory Provider (Development)

```python
manager = PermissionStorageManager(
    provider="memory",
    config={
        "max_sessions": 10000,
        "cleanup_interval": 60
    }
)
```

**Features:**
- Zero dependencies
- Fastest performance
- Background cleanup
- Thread-safe operations
- Memory usage monitoring

### File Provider (Simple Deployment)

```python
manager = PermissionStorageManager(
    provider="file",
    config={
        "storage_dir": "/var/lib/app/permissions",
        "enable_backup": True,
        "atomic_writes": True
    }
)
```

**Features:**
- Data persistence
- Automatic backups
- File locking
- Atomic writes
- Zero dependencies

## 🔧 Configuration

### Environment Variables

```bash
# Redis Configuration
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=your_password
REDIS_MAX_CONNECTIONS=50

# File Configuration
PERMISSIONS_STORAGE_DIR=/var/lib/app/permissions
PERMISSIONS_BACKUP_ENABLED=true

# General Configuration
PERMISSIONS_DEFAULT_TTL=3600
PERMISSIONS_LOG_LEVEL=INFO
```

### Configuration Loading

```python
import os
from permission_storage_manager import create_manager
from permission_storage_manager.utils import parse_provider_url

# From environment
redis_config = parse_provider_url(os.getenv("REDIS_URL"))
manager = create_manager("redis", redis_config)

# Direct configuration
config = {
    "host": "localhost",
    "port": 6379,
    "db": 0,
    "socket_timeout": 5.0
}
manager = create_manager("redis", config)
```

## 🎯 Advanced Usage

### Context Managers

```python
# Async context manager
async with PermissionStorageManager("redis", config) as manager:
    await manager.store_permissions("session_1", "user_1", ["read"])
    has_read = await manager.check_permission("session_1", "read")
# Automatically closed

# Sync context manager
with PermissionStorageManager("memory") as manager:
    manager.store_permissions_sync("session_1", "user_1", ["read"])
    has_read = manager.check_permission_sync("session_1", "read")
```

### Permission Patterns

```python
from permission_storage_manager.utils import (
    has_any_permission,
    has_all_permissions,
    filter_permissions_by_pattern
)

# Check if user has any admin permission
user_perms = ["user:read", "user:write", "admin:read"]
is_admin = has_any_permission(user_perms, ["admin:*"])

# Check if user has all required permissions
required = ["user:read", "user:write"]
has_all = has_all_permissions(user_perms, required)

# Filter permissions by pattern
admin_perms = filter_permissions_by_pattern(user_perms, "admin:*")
```

### Session Management

```python
# List all sessions for a user
user_sessions = await manager.list_sessions(user_id="user_123")

# Get session information
session_info = await manager.get_session_info("session_123")
print(f"TTL remaining: {session_info['ttl_remaining']} seconds")

# Extend session TTL
await manager.extend_session_ttl("session_123", 7200)  # 2 more hours

# Cleanup expired sessions
cleaned_count = await manager.cleanup_expired_sessions()
print(f"Cleaned up {cleaned_count} expired sessions")
```

### Bulk Operations

```python
# Store multiple sessions efficiently
sessions = [
    ("session_1", "user_1", ["read"]),
    ("session_2", "user_2", ["read", "write"]),
    ("session_3", "user_1", ["admin"])
]

for session_id, user_id, permissions in sessions:
    await manager.store_permissions(session_id, user_id, permissions)

# Check permissions for multiple sessions
session_ids = ["session_1", "session_2", "session_3"]
permission_results = {}

for session_id in session_ids:
    permission_results[session_id] = await manager.check_permissions(
        session_id, ["read", "write", "admin"]
    )
```

## 🌐 Framework Integration

### FastAPI Integration

```python
from fastapi import FastAPI, HTTPException, Depends
from permission_storage_manager import create_manager

app = FastAPI()
manager = create_manager("redis", {"url": "redis://localhost:6379"})

async def get_session_permissions(session_id: str):
    """Dependency to get session permissions."""
    permissions = await manager.get_permissions(session_id)
    if not permissions:
        raise HTTPException(status_code=401, detail="Invalid session")
    return permissions["permissions"]

@app.post("/login")
async def login(user_id: str):
    from permission_storage_manager.utils import generate_session_id
    
    session_id = generate_session_id("api")
    user_permissions = get_user_permissions(user_id)  # Your logic
    
    await manager.store_permissions(
        session_id, user_id, user_permissions, ttl=3600
    )
    
    return {"session_id": session_id}

@app.get("/protected-resource")
async def protected_resource(
    permissions: list = Depends(get_session_permissions)
):
    if "admin" not in permissions:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return {"data": "sensitive information"}

@app.post("/logout")
async def logout(session_id: str):
    await manager.invalidate_session(session_id)
    return {"message": "Logged out successfully"}
```

### Django Integration

```python
# middleware.py
from django.http import JsonResponse
from permission_storage_manager import create_manager

manager = create_manager("redis", {"url": "redis://localhost:6379"})

class PermissionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        session_id = request.headers.get("X-Session-ID")
        
        if session_id:
            permissions = manager.get_permissions_sync(session_id)
            request.user_permissions = permissions["permissions"] if permissions else []
        else:
            request.user_permissions = []
        
        response = self.get_response(request)
        return response

# views.py
def admin_view(request):
    if "admin" not in request.user_permissions:
        return JsonResponse({"error": "Admin access required"}, status=403)
    
    return JsonResponse({"data": "admin data"})
```

### Flask Integration

```python
from flask import Flask, request, jsonify, g
from permission_storage_manager import create_manager

app = Flask(__name__)
manager = create_manager("memory")  # Simple setup for demo

@app.before_request
def load_permissions():
    session_id = request.headers.get("X-Session-ID")
    if session_id:
        permissions_data = manager.get_permissions_sync(session_id)
        g.user_permissions = permissions_data["permissions"] if permissions_data else []
    else:
        g.user_permissions = []

def require_permission(permission):
    def decorator(f):
        def wrapper(*args, **kwargs):
            if permission not in g.user_permissions:
                return jsonify({"error": "Permission denied"}), 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

@app.route("/admin-data")
@require_permission("admin")
def admin_data():
    return jsonify({"data": "admin information"})
```

## 🔧 Custom Providers

Create your own storage provider by extending the `BaseProvider` class:

```python
from permission_storage_manager import BaseProvider

class PostgreSQLProvider(BaseProvider):
    def __init__(self, config):
        super().__init__(config)
        self.connection_pool = None
    
    async def initialize(self):
        # Initialize database connection
        self.connection_pool = await create_pool(self.config["dsn"])
        self._initialized = True
    
    async def store_permissions(self, session_id, user_id, permissions, ttl=None, metadata=None):
        # Implement storage logic
        async with self.connection_pool.acquire() as conn:
            # Your SQL logic here
            pass
        return True
    
    # Implement other required methods...
    
    @property
    def provider_name(self):
        return "postgresql"
    
    @property 
    def supports_ttl(self):
        return True  # If your implementation supports TTL

# Register and use
from permission_storage_manager import PermissionStorageManager

PermissionStorageManager.register_provider("postgresql", PostgreSQLProvider)
manager = PermissionStorageManager("postgresql", {"dsn": "postgresql://..."})
```

## 📊 Performance & Monitoring

### Performance Monitoring

```python
from permission_storage_manager.utils import log_performance
import time

# Manual performance logging
start_time = time.time()
await manager.store_permissions("session_1", "user_1", ["read"])
duration = time.time() - start_time
log_performance("store_permissions", duration, {"session_count": 1})

# Provider-specific stats
if manager.provider_name == "memory":
    stats = await manager._provider.get_memory_stats()
    print(f"Total sessions: {stats['total_sessions']}")
    print(f"Memory usage: {stats['active_sessions']} active sessions")

elif manager.provider_name == "redis":
    info = await manager._provider.get_connection_info()
    print(f"Redis version: {info['redis_version']}")
    print(f"Connected clients: {info['connected_clients']}")

elif manager.provider_name == "file":
    stats = await manager._provider.get_storage_stats()
    print(f"Storage size: {stats['total_size_bytes']} bytes")
    print(f"Files: {stats['session_files']} sessions")
```

### Health Checks

```python
async def health_check():
    """Health check endpoint for monitoring."""
    try:
        # Test basic operations
        test_session = "health_check_session"
        await manager.store_permissions(test_session, "health_user", ["test"])
        
        has_test = await manager.check_permission(test_session, "test")
        if not has_test:
            return {"status": "error", "message": "Permission check failed"}
        
        await manager.invalidate_session(test_session)
        
        return {
            "status": "healthy",
            "provider": manager.provider_name,
            "supports_ttl": manager.supports_ttl
        }
    
    except Exception as e:
        return {"status": "error", "message": str(e)}
```

## 🧪 Testing

Run the test suite:

```bash
# All tests
pytest tests/

# Specific provider tests
pytest tests/test_providers/test_memory_provider.py
pytest tests/test_providers/test_redis_provider.py -m redis
pytest tests/test_providers/test_file_provider.py -m file

# Performance tests
pytest tests/ -m slow

# With coverage
pytest tests/ --cov=permission_storage_manager --cov-report=html
```

## 🔧 Troubleshooting

### Common Issues

#### Redis Connection Errors

```python
# Error: Connection refused
# Solution: Check Redis server is running
redis-server --port 6379

# Error: Authentication failed
# Solution: Check password in config
config = {
    "url": "redis://:password@localhost:6379/0"
}
```

#### Memory Provider Issues

```python
# Error: Too many sessions
# Solution: Increase max_sessions or cleanup more frequently
config = {
    "max_sessions": 50000,
    "cleanup_interval": 30
}
```

#### File Provider Issues

```python
# Error: Permission denied
# Solution: Check directory permissions
import os
os.chmod("/var/lib/app/permissions", 0o755)

# Error: Disk space full
# Solution: Enable compression or cleanup old files
config = {
    "compress_files": True,
    "max_backup_files": 3
}
```

#### General Issues

```python
# Error: Provider not initialized
# Solution: Ensure auto_initialize=True or call initialize()
manager = PermissionStorageManager("redis", config, auto_initialize=True)

# Error: Session expired
# Solution: Check TTL settings and extend if needed
await manager.extend_session_ttl(session_id, 3600)
```

### Performance Tips

- **Use connection pooling** for Redis in production
- **Enable compression** for File provider with large datasets
- **Set appropriate TTL** to prevent memory bloat
- **Use bulk operations** for multiple sessions
- **Monitor memory usage** with Memory provider

### Debug Mode

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Or for specific provider
logging.getLogger("permission_storage_manager.providers.redis").setLevel(logging.DEBUG)
```

## 📋 Requirements

- **Python**: 3.8+
- **Redis**: 6.0+ (for Redis provider)
- **Dependencies**: See `requirements.txt`

### Optional Dependencies

```bash
# Redis support
pip install redis>=4.0.0

# Development dependencies
pip install pytest>=6.0.0
pip install pytest-asyncio>=0.18.0
pip install pytest-cov>=3.0.0
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/fatihemre/permission-storage-manager.git
cd permission-storage-manager

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e .[dev]

# Run tests
pytest tests/

# Run linting
flake8 src/ tests/
black src/ tests/
mypy src/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Full documentation](https://permission-storage-manager.readthedocs.io/)
- **Issues**: [GitHub Issues](https://github.com/fatihemre/permission-storage-manager/issues)
- **Discussions**: [GitHub Discussions](https://github.com/fatihemre/permission-storage-manager/discussions)
- **Email**: support@permission-storage-manager.dev

## 🗺️ Roadmap

- [ ] **v1.1**: MongoDB provider
- [ ] **v1.2**: PostgreSQL provider  
- [ ] **v1.3**: Role-based permissions
- [ ] **v1.4**: Permission inheritance
- [ ] **v1.5**: GraphQL API
- [ ] **v2.0**: Distributed caching

## 📈 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.

---

**Made with ❤️ by the Permission Storage Manager team**