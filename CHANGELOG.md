# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of Permission Storage Manager
- Support for Redis, Memory, and File storage providers
- Async and sync API support
- TTL (Time-To-Live) support for sessions
- Comprehensive test suite with 95%+ coverage
- Type hints and validation
- Context manager support
- Provider comparison utilities
- Performance monitoring capabilities
- Framework integration examples (FastAPI, Django, Flask)

### Changed
- N/A (Initial release)

### Deprecated
- N/A (Initial release)

### Removed
- N/A (Initial release)

### Fixed
- N/A (Initial release)

### Security
- N/A (Initial release)

---

## [1.0.0] - 2024-01-01

### Added
- Initial release of Permission Storage Manager
- Core PermissionStorageManager class
- BaseProvider abstract class for custom providers
- RedisProvider with native TTL support
- MemoryProvider for development and testing
- FileProvider for simple deployments
- Comprehensive exception hierarchy
- Utility functions for permission management
- Session ID generation and validation
- TTL parsing and formatting utilities
- Provider registry and comparison system
- Context manager support for async and sync operations
- Performance monitoring and statistics
- Health check utilities
- Framework integration examples
- Complete API documentation
- Comprehensive test suite

### Features
- **Multiple Storage Providers**: Redis, Memory, File-based storage
- **Async/Sync Support**: Both asynchronous and synchronous APIs
- **TTL Support**: Automatic session expiration
- **Type Safety**: Full type hints and validation
- **High Performance**: Optimized for speed and concurrent access
- **Extensible**: Easy to add custom storage providers
- **Zero Dependencies**: Memory and File providers require no external dependencies
- **Well Tested**: Comprehensive test suite with 95%+ coverage
- **Production Ready**: Battle-tested with comprehensive error handling

### Technical Details
- **Python Support**: 3.8+
- **Dependencies**: redis>=4.0.0, pydantic>=2.0.0, structlog>=23.0.0
- **License**: MIT
- **Repository**: https://github.com/fatihemre/permission-storage-manager

---

## Version History

### Version 1.0.0 (Current)
- **Release Date**: 2024-01-01
- **Status**: Stable
- **Python Support**: 3.8+
- **Key Features**: Core functionality, three providers, async/sync support

### Upcoming Versions

#### Version 1.1.0 (Planned)
- MongoDB provider
- Enhanced performance monitoring
- Additional utility functions

#### Version 1.2.0 (Planned)
- PostgreSQL provider
- Role-based permissions
- Advanced caching features

#### Version 2.0.0 (Future)
- Distributed caching support
- GraphQL API
- Permission inheritance system

---

## Migration Guides

### From Pre-1.0.0 Versions
This is the initial release, so no migration is needed.

### Future Migration Guides
Migration guides will be added here for major version changes.

---

## Support

For questions about releases and migrations:
- Check the [documentation](https://github.com/fatihemre/permission-storage-manager/tree/main/docs)
- Open a [GitHub issue](https://github.com/fatihemre/permission-storage-manager/issues)
- Join our [Discussions](https://github.com/fatihemre/permission-storage-manager/discussions)
