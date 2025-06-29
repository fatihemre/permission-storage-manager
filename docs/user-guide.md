# User Guide

Complete step-by-step guide for using Permission Storage Manager in your applications.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Installation & Setup](#installation--setup)
3. [Basic Usage](#basic-usage)
4. [Provider Selection](#provider-selection)
5. [Session Management](#session-management)
6. [Permission Patterns](#permission-patterns)
7. [Framework Integration](#framework-integration)
8. [Production Deployment](#production-deployment)
9. [Monitoring & Troubleshooting](#monitoring--troubleshooting)
10. [Migration & Upgrades](#migration--upgrades)

---

## Getting Started

### What is Permission Storage Manager?

Permission Storage Manager is a Python library that provides a unified interface for storing and managing user permissions across different storage backends. It's designed to be:

- **Simple**: Easy to integrate into existing applications
- **Flexible**: Support for multiple storage providers
- **Performant**: Optimized for high-traffic applications
- **Reliable**: Battle-tested with comprehensive error handling

### When to Use This Library

✅ **Good Use Cases:**
- Web applications with user authentication
- API services with permission-based access control
- Microservices requiring session management
- Applications needing temporary permission caching

❌ **Not Ideal For:**
- Simple applications with static permissions
- Systems requiring complex role hierarchies (consider RBAC solutions)
- Applications with permanent permission storage needs

---

## Installation & Setup

### Step 1: Install the Package

```bash
# Basic installation (Memory and File providers)
pip install permission-storage-manager

# With Redis support
pip install permission-storage-manager[redis]

# With all optional dependencies
pip install permission-storage-manager[all]
```

### Step 2: Verify Installation

```python
# test_installation.py
from permission_storage_manager import (
    PermissionStorageManager,
    get_version,
    get_supported_providers
)

print(f"Version: {get_version()}")
print(f"Supported providers: {get_supported_providers()}")

# Test basic functionality
async def test_basic():
    manager = PermissionStorageManager("memory")
    await manager.store_permissions("test_session", "test_user", ["read"])
    has_read = await manager.check_permission("test_session", "read")
    print(f"Test successful: {has_read}")
    await manager.close()

import asyncio
asyncio.run(test_basic())
```

### Step 3: Choose Your Development Approach

**Option A: Async/Await (Recommended)**
```python
# For modern async applications
async def main():
    manager = PermissionStorageManager("memory")
    await manager.store_permissions("session_1", "user_1", ["read"])
    await manager.close()

asyncio.run(main())
```

**Option B: Synchronous**
```python
# For traditional sync applications
manager = PermissionStorageManager("memory")
manager.store_permissions_sync("session_1", "user_1", ["read"])
manager.close()
```

---

## Basic Usage

### Step 1: Create a Manager

```python
from permission_storage_manager import PermissionStorageManager

# Simple setup for development
manager = PermissionStorageManager("memory")

# With configuration
manager = PermissionStorageManager(
    provider="memory",
    config={"max_sessions": 5000},
    default_ttl=3600  # 1 hour
)
```

### Step 2: Store User Permissions

```python
async def store_user_permissions():
    # Basic permission storage
    success = await manager.store_permissions(
        session_id="user_session_123",
        user_id="user_456",
        permissions=["read", "write"]
    )
    
    # With TTL and metadata
    success = await manager.store_permissions(
        session_id="user_session_124",
        user_id="user_456",
        permissions=["read", "write", "admin"],
        ttl=7200,  # 2 hours
        metadata={
            "login_time": "2024-01-01T12:00:00Z",
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0..."
        }
    )
    
    print(f"Permissions stored: {success}")
```

### Step 3: Check Permissions

```python
async def check_user_permissions():
    # Check single permission
    has_read = await manager.check_permission("user_session_123", "read")
    has_admin = await manager.check_permission("user_session_123", "admin")
    
    print(f"User has read: {has_read}")    # True
    print(f"User has admin: {has_admin}")  # False
    
    # Check multiple permissions at once
    permissions_to_check = ["read", "write", "admin", "delete"]
    results = await manager.check_permissions("user_session_123", permissions_to_check)
    
    print("Permission check results:")
    for permission, has_permission in results.items():
        print(f"  {permission}: {has_permission}")
    
    # Results: {"read": True, "write": True, "admin": False, "delete": False}
```

### Step 4: Retrieve Session Data

```python
async def get_session_data():
    # Get all session data
    session_data = await manager.get_permissions("user_session_123")
    
    if session_data:
        print(f"User ID: {session_data['user_id']}")
        print(f"Permissions: {session_data['permissions']}")
        print(f"Created: {session_data['created_at']}")
        print(f"Metadata: {session_data['metadata']}")
    else:
        print("Session not found or expired")
    
    # Get session info with TTL details
    session_info = await manager.get_session_info("user_session_124")
    if session_info:
        print(f"TTL remaining: {session_info['ttl_remaining']} seconds")
        print(f"Has TTL: {session_info['has_ttl']}")
```

### Step 5: Update and Manage Sessions

```python
async def manage_sessions():
    # Update permissions for existing session
    await manager.update_permissions(
        "user_session_123", 
        ["read", "write", "admin"]  # Add admin permission
    )
    
    # Extend session TTL
    await manager.extend_session_ttl("user_session_124", 3600)  # Add 1 hour
    
    # List all sessions for a user
    user_sessions = await manager.list_sessions(user_id="user_456")
    print(f"User has {len(user_sessions)} active sessions")
    
    # Clean up expired sessions
    cleaned = await manager.cleanup_expired_sessions()
    print(f"Cleaned up {cleaned} expired sessions")
    
    # Invalidate (logout) a session
    await manager.invalidate_session("user_session_123")
```

---

## Provider Selection

### Memory Provider (Development & Testing)

**Best for:** Development, testing, temporary sessions

```python
# Simple setup
manager = PermissionStorageManager("memory")

# With configuration
manager = PermissionStorageManager(
    provider="memory",
    config={
        "max_sessions": 10000,      # Maximum sessions to store
        "cleanup_interval": 60,     # Cleanup every 60 seconds
        "enable_monitoring": True   # Enable memory stats
    }
)

# Get memory statistics
if manager.provider_name == "memory":
    stats = await manager._provider.get_memory_stats()
    print(f"Active sessions: {stats['active_sessions']}")
    print(f"Memory usage: {stats['total_sessions']} total sessions")
```

**Pros:**
- Zero dependencies
- Fastest performance
- Great for development

**Cons:**
- No persistence (data lost on restart)
- Limited to single process
- Memory usage grows with sessions

### File Provider (Simple Production)

**Best for:** Small applications, single-server deployments

```python
manager = PermissionStorageManager(
    provider="file",
    config={
        "storage_dir": "/var/lib/myapp/permissions",
        "enable_backup": True,
        "max_backup_files": 10,
        "atomic_writes": True,
        "file_permissions": 0o600  # Read/write for owner only
    }
)

# Get storage statistics
if manager.provider_name == "file":
    stats = await manager._provider.get_storage_stats()
    print(f"Storage size: {stats['total_size_bytes']} bytes")
    print(f"Session files: {stats['session_files']}")
```

**Pros:**
- Data persistence
- Zero external dependencies
- Automatic backups
- Good for small deployments

**Cons:**
- Slower than memory/Redis
- File system limitations
- Not suitable for high concurrency

### Redis Provider (Production)

**Best for:** Production applications, high-traffic systems

```python
# Basic Redis setup
manager = PermissionStorageManager(
    provider="redis",
    config={"url": "redis://localhost:6379/0"}
)

# Advanced Redis configuration
manager = PermissionStorageManager(
    provider="redis",
    config={
        "host": "redis.example.com",
        "port": 6379,
        "db": 0,
        "password": "your_secure_password",
        "socket_timeout": 5.0,
        "max_connections": 50,
        "health_check_interval": 30,
        "key_prefix": "myapp_perms:",
        "ssl": True,
        "ssl_cert_reqs": "required"
    }
)

# Get Redis connection info
if manager.provider_name == "redis":
    info = await manager._provider.get_connection_info()
    print(f"Redis version: {info['redis_version']}")
    print(f"Connected clients: {info['connected_clients']}")
```

**Pros:**
- High performance
- Native TTL support
- Clustering and replication
- Battle-tested for production

**Cons:**
- Requires Redis server
- Additional infrastructure complexity

---

## Session Management

### Creating Sessions

```python
from permission_storage_manager.utils import generate_session_id, parse_ttl_string

async def create_user_session(user_id: str, user_permissions: list):
    # Generate secure session ID
    session_id = generate_session_id("webapp")
    
    # Parse TTL from string
    ttl = parse_ttl_string("24h")  # 24 hours = 86400 seconds
    
    # Store session with metadata
    await manager.store_permissions(
        session_id=session_id,
        user_id=user_id,
        permissions=user_permissions,
        ttl=ttl,
        metadata={
            "created_ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0...",
            "login_method": "password"
        }
    )
    
    return session_id

# Usage
session_id = await create_user_session("user_123", ["read", "write"])
print(f"Created session: {session_id}")
```

### Session Validation Middleware

```python
async def validate_session_middleware(session_id: str):
    """Middleware to validate session and return user info."""
    
    # Check if session exists and is valid
    session_data = await manager.get_permissions(session_id)
    
    if not session_data:
        raise ValueError("Invalid or expired session")
    
    # Check TTL remaining
    session_info = await manager.get_session_info(session_id)
    if session_info and session_info.get('ttl_remaining', 0) < 300:  # Less than 5 minutes
        # Auto-extend session
        await manager.extend_session_ttl(session_id, 3600)  # Add 1 hour
        print("Session TTL extended")
    
    return {
        "user_id": session_data["user_id"],
        "permissions": session_data["permissions"],
        "metadata": session_data["metadata"]
    }

# Usage in request handler
try:
    user_info = await validate_session_middleware(session_id)
    print(f"User {user_info['user_id']} is authenticated")
except ValueError as e:
    print(f"Authentication failed: {e}")
```

### Session Cleanup Strategies

```python
async def session_cleanup_job():
    """Background job for session maintenance."""
    
    # Clean up expired sessions
    cleaned_count = await manager.cleanup_expired_sessions()
    print(f"Cleaned up {cleaned_count} expired sessions")
    
    # List sessions for monitoring
    all_sessions = await manager.list_sessions(limit=1000)
    print(f"Total active sessions: {len(all_sessions)}")
    
    # Find sessions about to expire (if TTL info available)
    expiring_soon = []
    for session_id in all_sessions[:100]:  # Check first 100
        info = await manager.get_session_info(session_id)
        if info and info.get('ttl_remaining', 0) < 600:  # Less than 10 minutes
            expiring_soon.append(session_id)
    
    print(f"Sessions expiring soon: {len(expiring_soon)}")

# Run cleanup job periodically
import asyncio

async def periodic_cleanup():
    while True:
        await session_cleanup_job()
        await asyncio.sleep(300)  # Run every 5 minutes

# Start background task
# asyncio.create_task(periodic_cleanup())
```

---

## Permission Patterns

### Basic Permission Checking

```python
from permission_storage_manager.utils import (
    has_any_permission,
    has_all_permissions,
    filter_permissions_by_pattern
)

async def basic_permission_patterns(session_id: str):
    # Get user permissions
    session_data = await manager.get_permissions(session_id)
    if not session_data:
        return False
    
    user_permissions = session_data["permissions"]
    
    # Check if user has any admin permission
    admin_permissions = ["admin", "super_admin", "system_admin"]
    is_admin = has_any_permission(user_permissions, admin_permissions)
    
    # Check if user has all required permissions for an action
    required_for_publish = ["content:write", "content:publish"]
    can_publish = has_all_permissions(user_permissions, required_for_publish)
    
    # Filter permissions by pattern
    content_permissions = filter_permissions_by_pattern(
        user_permissions, "content:*"
    )
    
    return {
        "is_admin": is_admin,
        "can_publish": can_publish,
        "content_permissions": content_permissions
    }
```

### Hierarchical Permissions

```python
def check_hierarchical_permission(user_permissions: list, required_permission: str):
    """Check permission with hierarchy support."""
    
    # Define permission hierarchy
    hierarchy = {
        "read": 0,
        "write": 1,
        "admin": 2,
        "super_admin": 3
    }
    
    # Get required permission level
    required_level = hierarchy.get(required_permission, 0)
    
    # Check if user has permission at or above required level
    for perm in user_permissions:
        user_level = hierarchy.get(perm, -1)
        if user_level >= required_level:
            return True
    
    return False

# Usage
async def check_access(session_id: str, action: str):
    session_data = await manager.get_permissions(session_id)
    if not session_data:
        return False
    
    # Define required permissions for actions
    action_requirements = {
        "view_profile": "read",
        "edit_profile": "write", 
        "delete_user": "admin",
        "system_config": "super_admin"
    }
    
    required_permission = action_requirements.get(action)
    if not required_permission:
        return False
    
    return check_hierarchical_permission(
        session_data["permissions"], 
        required_permission
    )
```

### Resource-Based Permissions

```python
async def check_resource_permission(session_id: str, resource_type: str, resource_id: str, action: str):
    """Check permission for specific resource."""
    
    session_data = await manager.get_permissions(session_id)
    if not session_data:
        return False
    
    user_permissions = session_data["permissions"]
    
    # Check specific resource permission
    specific_permission = f"{resource_type}:{action}:{resource_id}"
    if specific_permission in user_permissions:
        return True
    
    # Check wildcard permissions
    wildcard_permissions = [
        f"{resource_type}:{action}:*",  # All resources of this type
        f"{resource_type}:*:{resource_id}",  # All actions on this resource
        f"{resource_type}:*:*",  # All actions on all resources of this type
        f"*:*:*"  # Global admin
    ]
    
    return has_any_permission(user_permissions, wildcard_permissions)

# Usage
can_edit_post = await check_resource_permission(
    session_id="session_123",
    resource_type="post",
    resource_id="post_456",
    action="edit"
)
```

### Permission Decorators

```python
def require_permission(permission: str):
    """Decorator to require specific permission."""
    def decorator(func):
        async def wrapper(session_id: str, *args, **kwargs):
            has_perm = await manager.check_permission(session_id, permission)
            if not has_perm:
                raise PermissionError(f"Permission '{permission}' required")
            return await func(session_id, *args, **kwargs)
        return wrapper
    return decorator

def require_any_permission(*permissions):
    """Decorator to require any of the specified permissions."""
    def decorator(func):
        async def wrapper(session_id: str, *args, **kwargs):
            session_data = await manager.get_permissions(session_id)
            if not session_data:
                raise PermissionError("Invalid session")
            
            if not has_any_permission(session_data["permissions"], permissions):
                raise PermissionError(f"One of these permissions required: {permissions}")
            
            return await func(session_id, *args, **kwargs)
        return wrapper
    return decorator

# Usage
@require_permission("admin")
async def delete_user(session_id: str, user_id: str):
    print(f"Deleting user {user_id}")

@require_any_permission("content:admin", "content:moderate")
async def moderate_content(session_id: str, content_id: str):
    print(f"Moderating content {content_id}")
```

---

## Framework Integration

### FastAPI Complete Example

```python
# app.py
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import HTTPBearer
from permission_storage_manager import create_manager
from permission_storage_manager.utils import generate_session_id
import asyncio

app = FastAPI(title="Permission Storage Example")
security = HTTPBearer()

# Initialize manager
manager = create_manager("redis", {"url": "redis://localhost:6379"})

# Startup/shutdown events
@app.on_event("startup")
async def startup():
    await manager.initialize()

@app.on_event("shutdown") 
async def shutdown():
    await manager.close()

# Dependency to get current user permissions
async def get_current_user(x_session_id: str = Header(...)):
    session_data = await manager.get_permissions(x_session_id)
    if not session_data:
        raise HTTPException(status_code=401, detail="Invalid session")
    return session_data

# Dependency to require specific permission
def require_permission(permission: str):
    async def permission_checker(current_user = Depends(get_current_user)):
        if permission not in current_user["permissions"]:
            raise HTTPException(
                status_code=403, 
                detail=f"Permission '{permission}' required"
            )
        return current_user
    return permission_checker

# Routes
@app.post("/auth/login")
async def login(user_id: str, password: str):
    # Your authentication logic here
    if not authenticate_user(user_id, password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create session
    session_id = generate_session_id("api")
    user_permissions = get_user_permissions(user_id)  # Your logic
    
    await manager.store_permissions(
        session_id, user_id, user_permissions, ttl=3600
    )
    
    return {"session_id": session_id, "expires_in": 3600}

@app.get("/profile")
async def get_profile(current_user = Depends(get_current_user)):
    return {
        "user_id": current_user["user_id"],
        "permissions": current_user["permissions"]
    }

@app.delete("/admin/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user = Depends(require_permission("admin"))
):
    # Delete user logic
    return {"message": f"User {user_id} deleted"}

@app.post("/auth/logout")
async def logout(x_session_id: str = Header(...)):
    await manager.invalidate_session(x_session_id)
    return {"message": "Logged out successfully"}

def authenticate_user(user_id: str, password: str) -> bool:
    # Your authentication logic
    return True

def get_user_permissions(user_id: str) -> list:
    # Your permission logic
    return ["read", "write"]
```

### Django Middleware Integration

```python
# middleware.py
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from permission_storage_manager import create_manager
import asyncio

# Global manager instance
manager = create_manager("redis", {"url": "redis://localhost:6379"})

class PermissionMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        self.get_response = get_response
        # Initialize manager
        asyncio.run(manager.initialize())
        super().__init__(get_response)
    
    def process_request(self, request):
        session_id = request.headers.get("X-Session-ID")
        
        if session_id:
            # Get permissions synchronously
            permissions_data = manager.get_permissions_sync(session_id)
            if permissions_data:
                request.user_id = permissions_data["user_id"]
                request.user_permissions = permissions_data["permissions"]
                request.session_metadata = permissions_data["metadata"]
            else:
                request.user_id = None
                request.user_permissions = []
                request.session_metadata = {}
        else:
            request.user_id = None
            request.user_permissions = []
            request.session_metadata = {}

# views.py
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

def require_permission(permission):
    """Decorator to require specific permission."""
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if permission not in request.user_permissions:
                return JsonResponse(
                    {"error": f"Permission '{permission}' required"}, 
                    status=403
                )
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

@require_http_methods(["POST"])
def login_view(request):
    import json
    data = json.loads(request.body)
    user_id = data.get("user_id")
    password = data.get("password")
    
    # Your authentication logic
    if authenticate_user(user_id, password):
        from permission_storage_manager.utils import generate_session_id
        
        session_id = generate_session_id("django")
        user_permissions = get_user_permissions(user_id)
        
        manager.store_permissions_sync(
            session_id, user_id, user_permissions, ttl=3600
        )
        
        return JsonResponse({
            "session_id": session_id,
            "permissions": user_permissions
        })
    else:
        return JsonResponse({"error": "Invalid credentials"}, status=401)

@require_permission("admin")
def admin_view(request):
    return JsonResponse({
        "message": "Admin access granted",
        "user_id": request.user_id
    })
```

### Flask Blueprint Example

```python
# auth.py
from flask import Blueprint, request, jsonify, g
from permission_storage_manager import create_manager
from permission_storage_manager.utils import generate_session_id
from functools import wraps

auth_bp = Blueprint("auth", __name__)
manager = create_manager("memory")  # Simple setup for demo

def require_permission(permission):
    """Decorator to require specific permission."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not hasattr(g, 'user_permissions') or permission not in g.user_permissions:
                return jsonify({"error": f"Permission '{permission}' required"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

@auth_bp.before_app_request
def load_user_permissions():
    session_id = request.headers.get("X-Session-ID")
    if session_id:
        permissions_data = manager.get_permissions_sync(session_id)
        if permissions_data:
            g.user_id = permissions_data["user_id"]
            g.user_permissions = permissions_data["permissions"]
        else:
            g.user_id = None
            g.user_permissions = []
    else:
        g.user_id = None
        g.user_permissions = []

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user_id = data.get("user_id")
    password = data.get("password")
    
    # Your authentication logic
    if authenticate_user(user_id, password):
        session_id = generate_session_id("flask")
        user_permissions = get_user_permissions(user_id)
        
        manager.store_permissions_sync(
            session_id, user_id, user_permissions, ttl=3600
        )
        
        return jsonify({
            "session_id": session_id,
            "permissions": user_permissions
        })
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@auth_bp.route("/admin/dashboard")
@require_permission("admin")
def admin_dashboard():
    return jsonify({
        "message": "Welcome to admin dashboard",
        "user_id": g.user_id
    })

def authenticate_user(user_id, password):
    # Your authentication logic
    return True

def get_user_permissions(user_id):
    # Your permission logic
    return ["read", "write"]
```

---

## Production Deployment

### Environment Configuration

```bash
# .env file
# Redis Configuration
REDIS_URL=redis://redis.example.com:6379/0
REDIS_PASSWORD=your_secure_password
REDIS_MAX_CONNECTIONS=100
REDIS_SOCKET_TIMEOUT=5.0

# Application Configuration
PERMISSIONS_DEFAULT_TTL=3600
PERMISSIONS_LOG_LEVEL=INFO
PERMISSIONS_KEY_PREFIX=prod_app:

# Security
SESSION_SECRET_KEY=your_secret_key_here
ALLOWED_HOSTS=api.example.com,app.example.com
```

```python
# config.py
import os
from permission_storage_manager.utils import parse_provider_url

class Config:
    # Redis configuration from environment
    REDIS_CONFIG = parse_provider_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
    REDIS_CONFIG.update({
        "password": os.getenv("REDIS_PASSWORD"),
        "max_connections": int(os.getenv("REDIS_MAX_CONNECTIONS", "50")),
        "socket_timeout": float(os.getenv("REDIS_SOCKET_TIMEOUT", "5.0")),
        "key_prefix": os.getenv("PERMISSIONS_KEY_PREFIX", "app:"),
    })
    
    # Permission settings
    DEFAULT_TTL = int(os.getenv("PERMISSIONS_DEFAULT_TTL", "3600"))
    LOG_LEVEL = os.getenv("PERMISSIONS_LOG_LEVEL", "INFO")

# app.py
from permission_storage_manager import create_manager
from permission_storage_manager.utils import setup_logger

# Setup logging
logger = setup_logger("permission_storage", Config.LOG_LEVEL)

# Create manager with production config
manager = create_manager("redis", Config.REDIS_CONFIG, Config.DEFAULT_TTL)
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Create non-root user
RUN useradd -m -u 1001 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - REDIS_URL=redis://redis:6379/0
      - PERMISSIONS_DEFAULT_TTL=3600
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes
    restart: unless-stopped

volumes:
  redis_data:
```

### Health Checks

```python
# health.py
async def health_check():
    """Comprehensive health check for the permission system."""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": {}
    }
    
    try:
        # Test manager initialization
        if not manager.is_initialized:
            raise Exception("Manager not initialized")
        
        health_status["checks"]["manager"] = {"status": "ok"}
        
        # Test basic operations
        test_session = f"health_check_{int(time.time())}"
        
        # Store test permission
        await manager.store_permissions(test_session, "health_user", ["test"], ttl=60)
        health_status["checks"]["store"] = {"status": "ok"}
        
        # Check test permission
        has_test = await manager.check_permission(test_session, "test")
        if not has_test:
            raise Exception("Permission check failed")
        health_status["checks"]["check"] = {"status": "ok"}
        
        # Clean up test session
        await manager.invalidate_session(test_session)
        health_status["checks"]["cleanup"] = {"status": "ok"}
        
        # Provider-specific checks
        if manager.provider_name == "redis":
            info = await manager._provider.get_connection_info()
            health_status["checks"]["redis"] = {
                "status": "ok",
                "version": info.get("redis_version"),
                "connected_clients": info.get("connected_clients")
            }
        
        # Performance check
        start_time = time.time()
        await manager.store_permissions("perf_test", "perf_user", ["test"], ttl=60)
        await manager.check_permission("perf_test", "test")
        await manager.invalidate_session("perf_test")
        duration = time.time() - start_time
        
        health_status["checks"]["performance"] = {
            "status": "ok",
            "duration_ms": round(duration * 1000, 2)
        }
        
    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["error"] = str(e)
        
        # Mark failed checks
        for check_name in ["manager", "store", "check", "cleanup", "performance"]:
            if check_name not in health_status["checks"]:
                health_status["checks"][check_name] = {"status": "failed", "error": str(e)}
    
    return health_status

# FastAPI health endpoint
@app.get("/health")
async def health_endpoint():
    health = await health_check()
    status_code = 200 if health["status"] == "healthy" else 503
    return JSONResponse(content=health, status_code=status_code)
```

### Monitoring and Metrics

```python
# monitoring.py
import time
from contextlib import asynccontextmanager
from permission_storage_manager.utils import log_performance

# Performance monitoring decorator
def monitor_performance(operation_name: str):
    def decorator(func):
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                log_performance(operation_name, duration, {"status": "success"})
                return result
            except Exception as e:
                duration = time.time() - start_time
                log_performance(operation_name, duration, {"status": "error", "error": str(e)})
                raise
        return wrapper
    return decorator

# Usage with manager operations
@monitor_performance("store_permissions")
async def monitored_store_permissions(*args, **kwargs):
    return await manager.store_permissions(*args, **kwargs)

# Metrics collection
class PermissionMetrics:
    def __init__(self):
        self.metrics = {
            "total_operations": 0,
            "successful_operations": 0,
            "failed_operations": 0,
            "active_sessions": 0,
            "average_response_time": 0.0
        }
        self.response_times = []
    
    async def collect_metrics(self):
        """Collect current metrics from the permission system."""
        try:
            # Get active sessions count
            sessions = await manager.list_sessions(limit=10000)
            self.metrics["active_sessions"] = len(sessions)
            
            # Provider-specific metrics
            if manager.provider_name == "memory":
                stats = await manager._provider.get_memory_stats()
                self.metrics.update({
                    "memory_total_sessions": stats["total_sessions"],
                    "memory_peak_sessions": stats["peak_session_count"],
                    "memory_total_operations": stats["total_operations"]
                })
            
            elif manager.provider_name == "redis":
                info = await manager._provider.get_connection_info()
                self.metrics.update({
                    "redis_connected_clients": info.get("connected_clients", 0),
                    "redis_used_memory": info.get("used_memory_human", "unknown")
                })
            
            # Calculate average response time
            if self.response_times:
                self.metrics["average_response_time"] = sum(self.response_times) / len(self.response_times)
        
        except Exception as e:
            print(f"Failed to collect metrics: {e}")
    
    def record_operation(self, duration: float, success: bool):
        """Record an operation for metrics."""
        self.metrics["total_operations"] += 1
        if success:
            self.metrics["successful_operations"] += 1
        else:
            self.metrics["failed_operations"] += 1
        
        self.response_times.append(duration)
        # Keep only last 1000 response times
        if len(self.response_times) > 1000:
            self.response_times = self.response_times[-1000:]

# Global metrics instance
metrics = PermissionMetrics()

# Metrics endpoint
@app.get("/metrics")
async def get_metrics():
    await metrics.collect_metrics()
    return metrics.metrics
```

### Load Balancing and High Availability

```python
# ha_setup.py
from permission_storage_manager import PermissionStorageManager
from permission_storage_manager.utils import retry_with_backoff

class HAPermissionManager:
    """High availability wrapper for Permission Storage Manager."""
    
    def __init__(self, redis_urls: list, fallback_provider="memory"):
        self.redis_urls = redis_urls
        self.fallback_provider = fallback_provider
        self.primary_manager = None
        self.fallback_manager = None
        self.current_redis_index = 0
    
    async def initialize(self):
        """Initialize with primary Redis and fallback."""
        # Try to connect to Redis instances
        for i, url in enumerate(self.redis_urls):
            try:
                manager = PermissionStorageManager("redis", {"url": url})
                await manager.initialize()
                self.primary_manager = manager
                self.current_redis_index = i
                print(f"Connected to Redis: {url}")
                break
            except Exception as e:
                print(f"Failed to connect to Redis {url}: {e}")
        
        # Setup fallback manager
        self.fallback_manager = PermissionStorageManager(self.fallback_provider)
        await self.fallback_manager.initialize()
        
        if not self.primary_manager:
            print("Warning: Using fallback provider only")
    
    @retry_with_backoff(max_retries=2)
    async def store_permissions(self, *args, **kwargs):
        """Store permissions with automatic failover."""
        if self.primary_manager:
            try:
                return await self.primary_manager.store_permissions(*args, **kwargs)
            except Exception as e:
                print(f"Primary storage failed: {e}")
                await self._try_failover()
        
        # Use fallback
        return await self.fallback_manager.store_permissions(*args, **kwargs)
    
    async def _try_failover(self):
        """Try to failover to another Redis instance."""
        for i, url in enumerate(self.redis_urls):
            if i == self.current_redis_index:
                continue
            
            try:
                new_manager = PermissionStorageManager("redis", {"url": url})
                await new_manager.initialize()
                
                # Close old manager
                if self.primary_manager:
                    await self.primary_manager.close()
                
                self.primary_manager = new_manager
                self.current_redis_index = i
                print(f"Failed over to Redis: {url}")
                return
            except Exception as e:
                print(f"Failover to {url} failed: {e}")
        
        # All Redis instances failed
        print("All Redis instances failed, using fallback only")
        if self.primary_manager:
            await self.primary_manager.close()
        self.primary_manager = None

# Usage
ha_manager = HAPermissionManager([
    "redis://redis1.example.com:6379",
    "redis://redis2.example.com:6379",
    "redis://redis3.example.com:6379"
])

await ha_manager.initialize()
```

---

## Monitoring & Troubleshooting

### Logging Configuration

```python
# logging_config.py
import logging
from permission_storage_manager.utils import setup_logger

# Setup comprehensive logging
def setup_application_logging():
    # Main application logger
    app_logger = setup_logger("myapp", "INFO")
    
    # Permission storage logger with more detail
    psm_logger = setup_logger("permission_storage", "DEBUG")
    
    # Add file handler for production
    file_handler = logging.FileHandler("/var/log/myapp/permissions.log")
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    ))
    psm_logger.addHandler(file_handler)
    
    return app_logger, psm_logger

# Custom logging for operations
async def logged_store_permissions(session_id, user_id, permissions, **kwargs):
    """Store permissions with detailed logging."""
    logger = logging.getLogger("permission_storage")
    
    logger.info(f"Storing permissions for session {session_id}, user {user_id}")
    logger.debug(f"Permissions: {permissions}")
    
    try:
        result = await manager.store_permissions(session_id, user_id, permissions, **kwargs)
        logger.info(f"Successfully stored permissions for session {session_id}")
        return result
    except Exception as e:
        logger.error(f"Failed to store permissions for session {session_id}: {e}")
        raise
```

### Common Issues and Solutions

```python
# troubleshooting.py
async def diagnose_session_issues(session_id: str):
    """Diagnose common session issues."""
    
    print(f"Diagnosing session: {session_id}")
    
    # Check if session exists
    session_data = await manager.get_permissions(session_id)
    if not session_data:
        print("❌ Session not found or expired")
        return
    
    print("✅ Session exists")
    print(f"   User ID: {session_data['user_id']}")
    print(f"   Permissions: {session_data['permissions']}")
    
    # Check TTL information
    session_info = await manager.get_session_info(session_id)
    if session_info:
        if session_info.get('has_ttl'):
            ttl_remaining = session_info.get('ttl_remaining', 0)
            if ttl_remaining > 0:
                print(f"✅ TTL remaining: {ttl_remaining} seconds")
            else:
                print("⚠️  Session expired (TTL reached)")
        else:
            print("ℹ️  Session has no TTL (permanent)")
    
    # Provider-specific diagnostics
    if manager.provider_name == "redis":
        try:
            conn_info = await manager._provider.get_connection_info()
            if conn_info["status"] == "connected":
                print("✅ Redis connection healthy")
            else:
                print(f"❌ Redis connection issue: {conn_info}")
        except Exception as e:
            print(f"❌ Redis diagnostics failed: {e}")
    
    elif manager.provider_name == "memory":
        try:
            stats = await manager._provider.get_memory_stats()
            print(f"ℹ️  Memory stats: {stats['total_sessions']} sessions, {stats['active_sessions']} active")
        except Exception as e:
            print(f"❌ Memory diagnostics failed: {e}")

async def test_permission_performance():
    """Test permission system performance."""
    import time
    
    print("Testing permission system performance...")
    
    # Test store operation
    start_time = time.time()
    test_sessions = []
    
    for i in range(100):
        session_id = f"perf_test_{i}"
        await manager.store_permissions(session_id, f"user_{i}", ["read", "write"])
        test_sessions.append(session_id)
    
    store_duration = time.time() - start_time
    print(f"Store 100 sessions: {store_duration:.3f}s ({100/store_duration:.1f} ops/sec)")
    
    # Test check operation
    start_time = time.time()
    
    for session_id in test_sessions:
        await manager.check_permission(session_id, "read")
    
    check_duration = time.time() - start_time
    print(f"Check 100 permissions: {check_duration:.3f}s ({100/check_duration:.1f} ops/sec)")
    
    # Cleanup
    for session_id in test_sessions:
        await manager.invalidate_session(session_id)
    
    cleanup_duration = time.time() - start_time
    print(f"Cleanup 100 sessions: {cleanup_duration:.3f}s")

# Debug mode helpers
async def debug_session_state():
    """Get comprehensive state information for debugging."""
    
    debug_info = {
        "manager": {
            "provider": manager.provider_name,
            "initialized": manager.is_initialized,
            "supports_ttl": manager.supports_ttl,
            "default_ttl": manager.default_ttl
        }
    }
    
    # Get all sessions
    try:
        all_sessions = await manager.list_sessions(limit=1000)
        debug_info["sessions"] = {
            "total_count": len(all_sessions),
            "sample_sessions": all_sessions[:5] if all_sessions else []
        }
    except Exception as e:
        debug_info["sessions"] = {"error": str(e)}
    
    # Provider-specific debug info
    try:
        if manager.provider_name == "redis":
            conn_info = await manager._provider.get_connection_info()
            debug_info["provider_info"] = conn_info
        elif manager.provider_name == "memory":
            stats = await manager._provider.get_memory_stats()
            debug_info["provider_info"] = stats
        elif manager.provider_name == "file":
            stats = await manager._provider.get_storage_stats()
            debug_info["provider_info"] = stats
    except Exception as e:
        debug_info["provider_info"] = {"error": str(e)}
    
    return debug_info
```

### Performance Tuning

```python
# performance_tuning.py
async def optimize_manager_performance():
    """Performance optimization recommendations."""
    
    provider_name = manager.provider_name
    
    if provider_name == "redis":
        print("Redis Performance Tips:")
        print("1. Use connection pooling (default: 50 connections)")
        print("2. Set appropriate socket timeout (default: 5s)")
        print("3. Use key prefixes for multi-tenant isolation")
        print("4. Monitor Redis memory usage and set maxmemory policy")
        print("5. Consider Redis Cluster for high availability")
        
        # Check current Redis configuration
        try:
            info = await manager._provider.get_connection_info()
            print(f"\nCurrent Redis stats:")
            print(f"  Connected clients: {info.get('connected_clients')}")
            print(f"  Memory usage: {info.get('used_memory_human')}")
        except Exception as e:
            print(f"Could not get Redis info: {e}")
    
    elif provider_name == "memory":
        print("Memory Performance Tips:")
        print("1. Set reasonable max_sessions limit")
        print("2. Tune cleanup_interval for your TTL patterns")
        print("3. Monitor memory usage in production")
        print("4. Consider Redis for persistence needs")
        
        try:
            stats = await manager._provider.get_memory_stats()
            print(f"\nCurrent memory stats:")
            print(f"  Active sessions: {stats['active_sessions']}")
            print(f"  Peak sessions: {stats['peak_session_count']}")
            print(f"  Storage limit: {stats['storage_limit']}")
        except Exception as e:
            print(f"Could not get memory stats: {e}")
    
    elif provider_name == "file":
        print("File Performance Tips:")
        print("1. Use SSD storage for better I/O performance")
        print("2. Enable atomic_writes for data safety")
        print("3. Adjust cleanup_interval based on TTL usage")
        print("4. Monitor disk space and backup storage")
        
        try:
            stats = await manager._provider.get_storage_stats()
            print(f"\nCurrent file stats:")
            print(f"  Session files: {stats['session_files']}")
            print(f"  Storage size: {stats['total_size_bytes']} bytes")
        except Exception as e:
            print(f"Could not get file stats: {e}")

# Batch operations for better performance
async def batch_store_permissions(sessions_data: list):
    """Store multiple sessions efficiently."""
    
    tasks = []
    for session_data in sessions_data:
        task = manager.store_permissions(
            session_data["session_id"],
            session_data["user_id"],
            session_data["permissions"],
            ttl=session_data.get("ttl"),
            metadata=session_data.get("metadata")
        )
        tasks.append(task)
    
    # Execute all stores concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Check for errors
    successful = sum(1 for r in results if r is True)
    failed = len(results) - successful
    
    print(f"Batch store: {successful} successful, {failed} failed")
    return results
```

---

## Migration & Upgrades

### Data Migration Between Providers

```python
# migration.py
async def migrate_data(source_manager, target_manager, batch_size=100):
    """Migrate data from one provider to another."""
    
    print(f"Migrating from {source_manager.provider_name} to {target_manager.provider_name}")
    
    # Get all sessions from source
    all_sessions = await source_manager.list_sessions(limit=10000)
    total_sessions = len(all_sessions)
    
    print(f"Found {total_sessions} sessions to migrate")
    
    migrated = 0
    failed = 0
    
    # Process in batches
    for i in range(0, total_sessions, batch_size):
        batch = all_sessions[i:i + batch_size]
        print(f"Processing batch {i//batch_size + 1} ({len(batch)} sessions)")
        
        for session_id in batch:
            try:
                # Get session data from source
                session_data = await source_manager.get_permissions(session_id)
                if not session_data:
                    continue
                
                # Get session info for TTL
                session_info = await source_manager.get_session_info(session_id)
                ttl = session_info.get('ttl_remaining') if session_info else None
                
                # Store in target
                await target_manager.store_permissions(
                    session_id,
                    session_data["user_id"],
                    session_data["permissions"],
                    ttl=ttl,
                    metadata=session_data["metadata"]
                )
                
                migrated += 1
                
            except Exception as e:
                print(f"Failed to migrate session {session_id}: {e}")
                failed += 1
    
    print(f"Migration complete: {migrated} migrated, {failed} failed")
    return {"migrated": migrated, "failed": failed}

# Usage example
async def migrate_memory_to_redis():
    """Example: Migrate from memory to Redis."""
    
    # Source (memory)
    memory_manager = PermissionStorageManager("memory")
    await memory_manager.initialize()
    
    # Target (Redis)
    redis_manager = PermissionStorageManager("redis", {
        "url": "redis://localhost:6379"
    })
    await redis_manager.initialize()
    
    # Perform migration
    result = await migrate_data(memory_manager, redis_manager)
    
    # Cleanup
    await memory_manager.close()
    await redis_manager.close()
    
    return result
```

### Version Compatibility

```python
# version_check.py
from permission_storage_manager import get_version, get_version_info

def check_compatibility():
    """Check version compatibility and features."""
    
    version_info = get_version_info()
    current_version = get_version()
    
    print(f"Permission Storage Manager version: {current_version}")
    print(f"Python version: {version_info['python_version']}")
    print(f"Platform: {version_info['platform']}")
    
    # Check for breaking changes
    major_version = int(current_version.split('.')[0])
    
    if major_version >= 2:
        print("⚠️  Major version 2.x detected - check migration guide")
    else:
        print("✅ Compatible version")
    
    # Check dependencies
    from permission_storage_manager.utils import check_dependencies
    deps = check_dependencies()
    
    print("\nDependency status:")
    for dep, available in deps.items():
        status = "✅" if available else "❌"
        print(f"  {dep}: {status}")

# Upgrade helpers
async def prepare_for_upgrade():
    """Prepare system for version upgrade."""
    
    print("Preparing for upgrade...")
    
    # 1. Backup current sessions (if using file provider)
    if manager.provider_name == "file":
        import shutil
        backup_dir = f"/tmp/psm_backup_{int(time.time())}"
        storage_dir = manager._provider._storage_dir
        shutil.copytree(storage_dir, backup_dir)
        print(f"Created backup at: {backup_dir}")
    
    # 2. Export session data
    sessions = await manager.list_sessions(limit=10000)
    export_data = []
    
    for session_id in sessions:
        session_data = await manager.get_permissions(session_id)
        if session_data:
            session_info = await manager.get_session_info(session_id)
            export_data.append({
                "session_id": session_id,
                "data": session_data,
                "ttl_remaining": session_info.get('ttl_remaining') if session_info else None
            })
    
    # Save export
    import json
    with open(f"/tmp/psm_export_{int(time.time())}.json", "w") as f:
        json.dump(export_data, f, indent=2)
    
    print(f"Exported {len(export_data)} sessions")
    
    return export_data

async def restore_from_export(export_file: str):
    """Restore sessions from export file."""
    
    import json
    with open(export_file, "r") as f:
        export_data = json.load(f)
    
    print(f"Restoring {len(export_data)} sessions...")
    
    restored = 0
    for item in export_data:
        try:
            session_data = item["data"]
            ttl = item.get("ttl_remaining")
            
            await manager.store_permissions(
                item["session_id"],
                session_data["user_id"],
                session_data["permissions"],
                ttl=ttl,
                metadata=session_data["metadata"]
            )
            restored += 1
        except Exception as e:
            print(f"Failed to restore session {item['session_id']}: {e}")
    
    print(f"Restored {restored} sessions")
```

---

## Performance Optimization

### Provider Performance Characteristics

#### Memory Provider
- **Best for**: Development, testing, small-scale applications
- **Performance**: Fastest (in-memory operations)
- **Memory Usage**: Linear with session count
- **Limitations**: No persistence, single-process only

#### Redis Provider
- **Best for**: Production, high-traffic applications
- **Performance**: High (network latency + Redis speed)
- **Memory Usage**: External (Redis server)
- **Limitations**: Network dependency, Redis server required

#### File Provider
- **Best for**: Simple deployments, backup storage
- **Performance**: Medium (disk I/O)
- **Memory Usage**: Low (file-based)
- **Limitations**: Disk space, file system performance

### Performance Optimization Strategies

#### 1. Connection Pooling (Redis)

```python
# Optimized Redis configuration
redis_config = {
    "url": "redis://localhost:6379/0",
    "max_connections": 50,              # Adjust based on load
    "socket_timeout": 5.0,              # Prevent hanging connections
    "socket_connect_timeout": 5.0,      # Fast connection failures
    "retry_on_timeout": True,           # Handle temporary issues
    "health_check_interval": 30,        # Regular health checks
    "decode_responses": True,           # Avoid encoding overhead
    "key_prefix": "app_perms:",         # Namespace isolation
}

manager = PermissionStorageManager("redis", redis_config)
```

#### 2. Batch Operations

```python
async def batch_permission_check(session_ids: list, permissions: list):
    """Check permissions for multiple sessions efficiently."""
    
    results = {}
    
    # Process in batches to avoid overwhelming the provider
    batch_size = 100
    for i in range(0, len(session_ids), batch_size):
        batch = session_ids[i:i + batch_size]
        
        # Create tasks for concurrent processing
        tasks = []
        for session_id in batch:
            task = manager.check_permissions(session_id, permissions)
            tasks.append(task)
        
        # Execute batch concurrently
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for session_id, result in zip(batch, batch_results):
            if isinstance(result, Exception):
                results[session_id] = {"error": str(result)}
            else:
                results[session_id] = result
    
    return results

# Usage
session_ids = ["session_1", "session_2", "session_3", ...]
permissions = ["read", "write", "admin"]
results = await batch_permission_check(session_ids, permissions)
```

#### 3. Caching Strategies

```python
from functools import lru_cache
import time

class CachedPermissionManager:
    """Wrapper that adds caching to permission checks."""
    
    def __init__(self, manager, cache_ttl=300):
        self.manager = manager
        self.cache_ttl = cache_ttl
        self._cache = {}
        self._cache_timestamps = {}
    
    async def check_permission(self, session_id: str, permission: str) -> bool:
        """Check permission with caching."""
        
        cache_key = f"{session_id}:{permission}"
        current_time = time.time()
        
        # Check cache
        if cache_key in self._cache:
            if current_time - self._cache_timestamps[cache_key] < self.cache_ttl:
                return self._cache[cache_key]
        
        # Get from provider
        result = await self.manager.check_permission(session_id, permission)
        
        # Cache result
        self._cache[cache_key] = result
        self._cache_timestamps[cache_key] = current_time
        
        return result
    
    async def invalidate_cache(self, session_id: str = None):
        """Invalidate cache entries."""
        if session_id:
            # Remove specific session entries
            keys_to_remove = [k for k in self._cache.keys() if k.startswith(f"{session_id}:")]
            for key in keys_to_remove:
                del self._cache[key]
                del self._cache_timestamps[key]
        else:
            # Clear all cache
            self._cache.clear()
            self._cache_timestamps.clear()

# Usage
cached_manager = CachedPermissionManager(manager, cache_ttl=60)
has_permission = await cached_manager.check_permission("session_123", "read")
```

#### 4. Memory Provider Optimization

```python
# Optimized memory provider configuration
memory_config = {
    "max_sessions": 50000,          # Increase for high-traffic apps
    "cleanup_interval": 30,         # More frequent cleanup
    "enable_monitoring": True,      # Monitor memory usage
}

# Memory usage monitoring
async def monitor_memory_usage(manager):
    """Monitor memory provider usage."""
    
    if manager.provider_name != "memory":
        return
    
    stats = await manager._provider.get_memory_stats()
    
    # Calculate memory efficiency
    efficiency = stats['active_sessions'] / stats['total_sessions'] if stats['total_sessions'] > 0 else 0
    
    print(f"Memory Usage Report:")
    print(f"  Active sessions: {stats['active_sessions']}")
    print(f"  Total sessions: {stats['total_sessions']}")
    print(f"  Efficiency: {efficiency:.2%}")
    print(f"  Peak usage: {stats['peak_session_count']}")
    
    # Alert if approaching limits
    if stats['active_sessions'] > stats['storage_limit'] * 0.8:
        print("⚠️  Warning: Approaching session limit")
    
    return stats
```

#### 5. File Provider Optimization

```python
# Optimized file provider configuration
file_config = {
    "storage_dir": "/var/lib/app/permissions",
    "cleanup_interval": 300,        # 5 minutes
    "enable_backup": True,
    "max_backup_files": 3,          # Keep fewer backups
    "compress_files": True,         # Enable compression
    "atomic_writes": True,          # Ensure data integrity
    "file_permissions": 0o600,      # Secure permissions
}

# Disk space monitoring
async def monitor_disk_usage(manager):
    """Monitor file provider disk usage."""
    
    if manager.provider_name != "file":
        return
    
    import os
    import shutil
    
    storage_dir = manager._provider._storage_dir
    stats = await manager._provider.get_storage_stats()
    
    # Get disk usage
    total, used, free = shutil.disk_usage(storage_dir)
    
    print(f"Disk Usage Report:")
    print(f"  Storage size: {stats['total_size_bytes']} bytes")
    print(f"  Session files: {stats['session_files']}")
    print(f"  Disk free: {free} bytes")
    print(f"  Disk usage: {used/total:.2%}")
    
    # Alert if disk space is low
    if free < total * 0.1:  # Less than 10% free
        print("⚠️  Warning: Low disk space")
    
    return stats
```

### Performance Monitoring

#### 1. Performance Metrics

```python
import time
import asyncio
from collections import defaultdict

class PerformanceMonitor:
    """Monitor permission storage performance."""
    
    def __init__(self):
        self.metrics = defaultdict(list)
        self.start_times = {}
    
    def start_operation(self, operation: str):
        """Start timing an operation."""
        self.start_times[operation] = time.time()
    
    def end_operation(self, operation: str, details: dict = None):
        """End timing an operation and record metrics."""
        if operation in self.start_times:
            duration = time.time() - self.start_times[operation]
            metric = {
                "duration": duration,
                "timestamp": time.time(),
                "details": details or {}
            }
            self.metrics[operation].append(metric)
            del self.start_times[operation]
    
    def get_statistics(self):
        """Get performance statistics."""
        stats = {}
        
        for operation, measurements in self.metrics.items():
            if not measurements:
                continue
            
            durations = [m["duration"] for m in measurements]
            stats[operation] = {
                "count": len(measurements),
                "avg_duration": sum(durations) / len(durations),
                "min_duration": min(durations),
                "max_duration": max(durations),
                "total_duration": sum(durations)
            }
        
        return stats

# Usage
monitor = PerformanceMonitor()

async def monitored_operation():
    monitor.start_operation("store_permissions")
    
    try:
        result = await manager.store_permissions("session_1", "user_1", ["read"])
        monitor.end_operation("store_permissions", {"success": True})
        return result
    except Exception as e:
        monitor.end_operation("store_permissions", {"success": False, "error": str(e)})
        raise

# Get performance report
stats = monitor.get_statistics()
for operation, stat in stats.items():
    print(f"{operation}: {stat['avg_duration']:.3f}s avg ({stat['count']} operations)")
```

#### 2. Health Checks

```python
async def comprehensive_health_check(manager):
    """Comprehensive health check with performance metrics."""
    
    health_report = {
        "status": "healthy",
        "provider": manager.provider_name,
        "timestamp": time.time(),
        "checks": {}
    }
    
    # Basic connectivity check
    try:
        test_session = f"health_check_{int(time.time())}"
        await manager.store_permissions(test_session, "health_user", ["test"])
        
        has_test = await manager.check_permission(test_session, "test")
        if not has_test:
            health_report["status"] = "error"
            health_report["checks"]["permission_check"] = "failed"
        else:
            health_report["checks"]["permission_check"] = "passed"
        
        await manager.invalidate_session(test_session)
        
    except Exception as e:
        health_report["status"] = "error"
        health_report["checks"]["basic_operations"] = f"failed: {str(e)}"
    
    # Performance check
    try:
        start_time = time.time()
        await manager.store_permissions("perf_test", "perf_user", ["read"])
        duration = time.time() - start_time
        
        if duration > 1.0:  # More than 1 second
            health_report["checks"]["performance"] = f"slow: {duration:.3f}s"
        else:
            health_report["checks"]["performance"] = f"good: {duration:.3f}s"
        
        await manager.invalidate_session("perf_test")
        
    except Exception as e:
        health_report["checks"]["performance"] = f"failed: {str(e)}"
    
    # Provider-specific checks
    if manager.provider_name == "redis":
        try:
            info = await manager._provider.get_connection_info()
            health_report["checks"]["redis_info"] = info
        except Exception as e:
            health_report["checks"]["redis_info"] = f"failed: {str(e)}"
    
    elif manager.provider_name == "memory":
        try:
            stats = await manager._provider.get_memory_stats()
            health_report["checks"]["memory_stats"] = stats
        except Exception as e:
            health_report["checks"]["memory_stats"] = f"failed: {str(e)}"
    
    elif manager.provider_name == "file":
        try:
            stats = await manager._provider.get_storage_stats()
            health_report["checks"]["storage_stats"] = stats
        except Exception as e:
            health_report["checks"]["storage_stats"] = f"failed: {str(e)}"
    
    return health_report

# Usage
health = await comprehensive_health_check(manager)
print(f"Health Status: {health['status']}")
for check, result in health['checks'].items():
    print(f"  {check}: {result}")
```

### Performance Best Practices Summary

1. **Choose the Right Provider**: Match provider to your use case and scale
2. **Optimize Configuration**: Tune provider-specific settings
3. **Use Batch Operations**: Process multiple operations concurrently
4. **Implement Caching**: Cache frequently accessed permissions
5. **Monitor Performance**: Track metrics and set up alerts
6. **Regular Cleanup**: Clean up expired sessions to prevent bloat
7. **Connection Pooling**: Use appropriate pool sizes for Redis
8. **Compression**: Enable compression for file provider
9. **Health Checks**: Implement comprehensive health monitoring
10. **Load Testing**: Test performance under expected load

---

## Best Practices Summary

### 🔒 Security Best Practices

1. **Session ID Generation**: Use cryptographically secure session IDs
2. **TTL Configuration**: Set appropriate TTL values for your use case
3. **Permission Validation**: Always validate permissions server-side
4. **Secure Storage**: Use Redis AUTH or file permissions appropriately
5. **HTTPS Only**: Never transmit session IDs over unencrypted connections

### ⚡ Performance Best Practices

1. **Provider Selection**: Choose the right provider for your scale
2. **Connection Pooling**: Configure appropriate pool sizes for Redis
3. **Batch Operations**: Use batch operations for multiple permission checks
4. **TTL Optimization**: Set TTL values that balance security and performance
5. **Monitoring**: Implement comprehensive monitoring and alerting

### 🏗️ Architecture Best Practices

1. **Dependency Injection**: Make the manager easily configurable
2. **Error Handling**: Implement comprehensive error handling
3. **Graceful Degradation**: Plan for provider failures
4. **Testing**: Write tests for all permission scenarios
5. **Documentation**: Document your permission model clearly

### 🔧 Operational Best Practices

1. **Logging**: Log all permission operations for audit trails
2. **Monitoring**: Monitor session counts, TTL, and performance
3. **Backup**: Backup session data for file and Redis providers
4. **Cleanup**: Implement regular cleanup of expired sessions
5. **Health Checks**: Implement health checks for your permission system

---

This comprehensive user guide should help you successfully implement and operate Permission Storage Manager in your applications. For more technical details, see the [API Reference](api_reference.md), and for code examples, check out the [Examples](examples.md) section.