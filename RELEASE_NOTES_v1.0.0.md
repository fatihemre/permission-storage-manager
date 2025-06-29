# 🚀 Permission Storage Manager v1.0.0 - Initial Release

## 🎉 What's New

**Permission Storage Manager** is a flexible, high-performance permission storage system for Python applications. This initial release provides a complete solution for storing and managing user permissions across different storage backends with a unified API.

## ✨ Key Features

### 🔄 Multiple Storage Providers
- **Redis Provider**: High-performance Redis-based storage with native TTL support
- **Memory Provider**: Ultra-fast in-memory storage for development and testing
- **File Provider**: File-based storage for simple deployments with persistence

### ⚡ Async/Sync Support
- Full asynchronous API for high-performance applications
- Synchronous API for simpler use cases
- Context manager support for both async and sync operations

### ⏰ Advanced Features
- **TTL Support**: Automatic session expiration with native Redis TTL
- **Type Safety**: Complete type hints and comprehensive validation
- **High Performance**: Optimized for speed and concurrent access
- **Extensible**: Easy to add custom storage providers

### 🛡️ Production Ready
- **Zero Dependencies**: Memory and File providers require no external dependencies
- **Well Tested**: Comprehensive test suite with 88%+ coverage
- **Error Handling**: Battle-tested with comprehensive exception handling
- **Thread Safety**: Safe for concurrent operations

## 📦 Installation

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

## 🚀 Quick Start

```python
import asyncio
from permission_storage_manager import PermissionStorageManager

async def main():
    # Create manager with memory provider
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
    
    # Clean up
    await manager.close()

asyncio.run(main())
```

## 🔧 Provider Comparison

| Feature | Redis | Memory | File |
|---------|-------|--------|------|
| **Performance** | High | Highest | Medium |
| **Persistence** | Yes | No | Yes |
| **TTL Support** | Native | Emulated | Emulated |
| **Clustering** | Yes | No | No |
| **Dependencies** | Redis | None | None |
| **Use Case** | Production | Dev/Test | Simple Deploy |

## 📚 Documentation

- **[User Guide](https://github.com/fatihemre/permission-storage-manager/blob/main/docs/user-guide.md)**: Complete usage guide
- **[API Reference](https://github.com/fatihemre/permission-storage-manager/blob/main/docs/api_reference.md)**: Detailed API documentation
- **[Examples](https://github.com/fatihemre/permission-storage-manager/tree/main/examples)**: Framework integration examples

## 🧪 Testing

The project includes a comprehensive test suite:
- **401 tests** covering all functionality
- **88%+ code coverage**
- **Integration tests** for all providers
- **Performance benchmarks**
- **Concurrent access testing**

## 🔗 Links

- **Repository**: https://github.com/fatihemre/permission-storage-manager
- **Documentation**: https://github.com/fatihemre/permission-storage-manager/tree/main/docs
- **Issues**: https://github.com/fatihemre/permission-storage-manager/issues
- **Discussions**: https://github.com/fatihemre/permission-storage-manager/discussions

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](https://github.com/fatihemre/permission-storage-manager/blob/main/CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/fatihemre/permission-storage-manager/blob/main/LICENSE) file for details.

## 🙏 Acknowledgments

Special thanks to all contributors and the Python community for making this project possible.

---

**Author**: Fatih Emre  
**Email**: info@fatihemre.net  
**Version**: 1.0.0  
**Release Date**: January 2025 