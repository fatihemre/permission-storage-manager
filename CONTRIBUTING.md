# Contributing to Permission Storage Manager

Thank you for your interest in contributing to Permission Storage Manager! This guide will help you get started with contributing to the project.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Environment](#development-environment)
4. [Project Structure](#project-structure)
5. [Development Workflow](#development-workflow)
6. [Testing](#testing)
7. [Code Style](#code-style)
8. [Documentation](#documentation)
9. [Submitting Changes](#submitting-changes)
10. [Code Review Guidelines](#code-review-guidelines)
11. [Creating New Providers](#creating-new-providers)
12. [Performance Guidelines](#performance-guidelines)
13. [Security Considerations](#security-considerations)
14. [Release Process](#release-process)

---

## Code of Conduct

### Our Pledge

We are committed to making participation in this project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Expected Behavior

- Be respectful and inclusive in your communications
- Focus on what is best for the community
- Show empathy towards other community members
- Be collaborative and constructive in discussions
- Help others learn and grow

### Unacceptable Behavior

- Harassment, discrimination, or inappropriate comments
- Trolling, insulting, or derogatory comments
- Public or private harassment
- Publishing others' private information without permission
- Other conduct that could reasonably be considered inappropriate

---

## Getting Started

### Prerequisites

- **Python 3.8+** (3.9+ recommended)
- **Git** for version control
- **Redis** (optional, for Redis provider testing)
- **Knowledge**: Basic understanding of Python, async/await, and storage systems

### Ways to Contribute

- 🐛 **Bug Reports**: Report issues you encounter
- 💡 **Feature Requests**: Suggest new features or improvements
- 📝 **Documentation**: Improve documentation and examples
- 🧪 **Testing**: Add tests or improve test coverage
- 🔧 **Code**: Fix bugs or implement new features
- 🚀 **Providers**: Create new storage providers
- 📊 **Performance**: Optimize performance and benchmarks

---

## Development Environment

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/permission-storage-manager.git
cd permission-storage-manager

# Add upstream remote
git remote add upstream https://github.com/original-owner/permission-storage-manager.git
```

### 2. Create Virtual Environment

```bash
# Create and activate virtual environment
python -m venv venv

# On Linux/macOS
source venv/bin/activate

# On Windows
venv\Scripts\activate
```

### 3. Install Development Dependencies

```bash
# Install package in development mode with all dependencies
pip install -e ".[all,dev]"

# Or install manually
pip install -e .
pip install pytest pytest-asyncio pytest-cov
pip install black flake8 mypy isort
pip install redis  # For Redis provider testing
```

### 4. Install Pre-commit Hooks

```bash
# Install pre-commit
pip install pre-commit

# Install git hooks
pre-commit install

# Run hooks on all files (optional)
pre-commit run --all-files
```

### 5. Verify Installation

```bash
# Run basic tests to verify setup
pytest tests/test_manager.py -v

# Run code quality checks
black --check src/
flake8 src/
mypy src/
```

---

## Project Structure

```
permission-storage-manager/
├── src/
│   └── permission_storage_manager/
│       ├── __init__.py           # Main package exports
│       ├── core/                 # Core functionality
│       │   ├── __init__.py
│       │   ├── base.py          # BaseProvider abstract class
│       │   ├── manager.py       # PermissionStorageManager
│       │   └── exceptions.py    # Custom exceptions
│       ├── providers/           # Storage providers
│       │   ├── __init__.py
│       │   ├── redis_provider.py
│       │   ├── memory_provider.py
│       │   └── file_provider.py
│       └── utils/               # Utility functions
│           ├── __init__.py
│           └── helpers.py
├── tests/                       # Test suite
│   ├── conftest.py             # Pytest configuration
│   ├── test_manager.py         # Manager tests
│   ├── test_providers/         # Provider-specific tests
│   └── integration/            # Integration tests
├── docs/                       # Documentation
│   ├── api_reference.md
│   ├── user_guide.md
│   └── contributing.md
├── examples/                   # Usage examples
├── pyproject.toml             # Project configuration
├── README.md
└── CHANGELOG.md
```

### Key Modules

#### Core Module (`src/permission_storage_manager/core/`)
- **`base.py`**: Abstract base class that all providers must implement
- **`manager.py`**: Main PermissionStorageManager class
- **`exceptions.py`**: All custom exceptions with proper inheritance

#### Providers Module (`src/permission_storage_manager/providers/`)
- **Provider implementations**: Redis, Memory, File providers
- **Provider registry**: Auto-registration system
- **Provider utilities**: Helper functions and comparisons

#### Utils Module (`src/permission_storage_manager/utils/`)
- **Session utilities**: ID generation, validation, normalization
- **Permission utilities**: Merging, pattern matching, filtering
- **Time utilities**: TTL parsing, formatting, calculations
- **Configuration utilities**: URL parsing, config merging

---

## Development Workflow

### 1. Choose an Issue

- Browse [open issues](https://github.com/fatihemre/permission-storage-manager/issues)
- Look for `good first issue` or `help wanted` labels
- Comment on the issue to claim it
- Ask questions if anything is unclear

### 2. Create a Branch

```bash
# Update your main branch
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-number-description
```

### 3. Development Cycle

```bash
# Make your changes
# Edit files, add features, fix bugs

# Run tests frequently
pytest tests/test_specific_module.py -v

# Check code quality
black src/ tests/
flake8 src/ tests/
mypy src/

# Run full test suite
pytest tests/ --cov=permission_storage_manager

# Commit changes
git add .
git commit -m "feat: add new feature description"
```

### 4. Keep Your Branch Updated

```bash
# Fetch latest changes from upstream
git fetch upstream

# Rebase your branch on latest main
git rebase upstream/main

# If there are conflicts, resolve them and continue
git add .
git rebase --continue
```

### 5. Push and Create PR

```bash
# Push your branch to your fork
git push origin feature/your-feature-name

# Create Pull Request on GitHub
# Use the PR template and provide detailed description
```

---

## Testing

### Test Structure

Our test suite is comprehensive and organized by functionality:

```
tests/
├── conftest.py                    # Shared fixtures
├── test_manager.py               # Manager functionality
├── test_providers/
│   ├── test_redis_provider.py    # Redis-specific tests
│   ├── test_memory_provider.py   # Memory-specific tests
│   └── test_file_provider.py     # File-specific tests
└── integration/
    └── test_integration.py       # Cross-provider tests
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_manager.py

# Run specific test class
pytest tests/test_manager.py::TestPermissionOperations

# Run specific test method
pytest tests/test_manager.py::TestPermissionOperations::test_store_permissions_basic

# Run with coverage
pytest --cov=permission_storage_manager --cov-report=html

# Run only fast tests (exclude slow performance tests)
pytest -m "not slow"

# Run Redis tests (requires Redis server)
pytest tests/test_providers/test_redis_provider.py -m redis

# Verbose output
pytest -v

# Stop on first failure
pytest -x
```

### Writing Tests

#### Test Naming Convention

```python
# Class names: Test + Functionality
class TestPermissionOperations:
    pass

# Method names: test_ + what_is_tested + scenario
def test_store_permissions_basic(self):
    pass

def test_store_permissions_with_ttl(self):
    pass

def test_store_permissions_validation_error(self):
    pass
```

#### Test Structure

```python
import pytest
from permission_storage_manager import PermissionStorageManager

class TestNewFeature:
    """Test the new feature functionality."""
    
    async def test_feature_basic_usage(self, memory_manager):
        """Test basic usage of the new feature."""
        # Arrange
        session_id = "test_session"
        user_id = "test_user"
        permissions = ["read", "write"]
        
        # Act
        result = await memory_manager.store_permissions(session_id, user_id, permissions)
        
        # Assert
        assert result is True
        data = await memory_manager.get_permissions(session_id)
        assert data["user_id"] == user_id
        assert set(data["permissions"]) == set(permissions)
    
    async def test_feature_edge_case(self, memory_manager):
        """Test edge case handling."""
        # Test edge cases, error conditions, boundary values
        pass
    
    @pytest.mark.parametrize("provider_name", ["memory", "redis", "file"])
    async def test_feature_all_providers(self, provider_name):
        """Test feature works with all providers."""
        # Use parametrized test for cross-provider compatibility
        pass
```

#### Using Fixtures

```python
async def test_with_custom_fixture(self, memory_manager, sample_session_data):
    """Use existing fixtures for common test data."""
    await memory_manager.store_permissions(
        sample_session_data["session_id"],
        sample_session_data["user_id"],
        sample_session_data["permissions"]
    )
    
    # Test your functionality
    pass

@pytest.fixture
async def custom_test_data():
    """Create custom fixture for specific test needs."""
    return {
        "special_data": "value",
        "test_config": {"setting": True}
    }
```

### Test Guidelines

1. **Test Coverage**: Aim for >95% test coverage
2. **Test All Providers**: Use parametrized tests for cross-provider functionality
3. **Test Error Cases**: Include negative tests for error handling
4. **Test Edge Cases**: Boundary values, empty inputs, large data
5. **Test Concurrency**: Include tests for concurrent operations
6. **Performance Tests**: Mark slow tests with `@pytest.mark.slow`
7. **Provider-Specific Tests**: Test provider-specific features separately

---

## Code Style

### Python Code Style

We follow [PEP 8](https://pep8.org/) with some specific conventions:

#### Formatting with Black

```bash
# Format all code
black src/ tests/

# Check formatting without changes
black --check src/ tests/

# Format specific file
black src/permission_storage_manager/core/manager.py
```

#### Linting with Flake8

```bash
# Run flake8 on all code
flake8 src/ tests/

# Configuration in pyproject.toml or .flake8
```

#### Type Checking with MyPy

```bash
# Run type checking
mypy src/

# Check specific file
mypy src/permission_storage_manager/core/manager.py
```

### Code Style Guidelines

#### 1. Imports

```python
# Standard library imports first
import asyncio
import time
from typing import Dict, List, Optional, Any
from datetime import datetime

# Third-party imports
import redis

# Local imports
from .base import BaseProvider
from .exceptions import ProviderError
from ..utils.helpers import normalize_permissions
```

#### 2. Type Hints

```python
# Use type hints for all public methods
async def store_permissions(
    self,
    session_id: str,
    user_id: str,
    permissions: List[str],
    ttl: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> bool:
    """Store user permissions with proper type hints."""
    pass
```

#### 3. Docstrings

```python
def complex_function(param1: str, param2: int) -> Dict[str, Any]:
    """
    Brief description of what the function does.
    
    Longer description if needed, explaining the purpose,
    behavior, and any important details.
    
    Args:
        param1: Description of param1
        param2: Description of param2
        
    Returns:
        Description of return value
        
    Raises:
        SpecificError: When this error occurs
        AnotherError: When this other error occurs
        
    Example:
        >>> result = complex_function("test", 42)
        >>> print(result["key"])
        "value"
    """
    pass
```

#### 4. Error Handling

```python
# Specific exception handling
try:
    result = await some_operation()
except ProviderConnectionError as e:
    logger.error(f"Connection failed: {e}")
    raise
except ProviderError as e:
    logger.error(f"Provider error: {e}")
    raise
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    raise ProviderError(f"Operation failed: {e}") from e
```

#### 5. Logging

```python
import logging

logger = logging.getLogger(__name__)

class MyProvider(BaseProvider):
    async def store_permissions(self, session_id: str, ...):
        logger.debug(f"Storing permissions for session {session_id}")
        
        try:
            # Operation
            logger.info(f"Successfully stored permissions for {session_id}")
        except Exception as e:
            logger.error(f"Failed to store permissions for {session_id}: {e}")
            raise
```

### Configuration Files

#### pyproject.toml

```toml
[tool.black]
line-length = 88
target-version = ['py38']
include = '\.pyi?$'
extend-exclude = '''
/(
  # directories
  \.eggs
  | \.git
  | \.venv
  | build
  | dist
)/
'''

[tool.isort]
profile = "black"
line_length = 88
multi_line_output = 3

[tool.mypy]
python_version = "3.8"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
```

---

## Documentation

### Documentation Standards

1. **API Documentation**: All public methods must have comprehensive docstrings
2. **User Guide**: Update user guide for new features
3. **Examples**: Provide practical examples for new functionality
4. **README**: Update README if adding major features
5. **CHANGELOG**: Document all changes

### Writing Documentation

#### Docstring Format

Use Google-style docstrings:

```python
async def new_method(
    self,
    param1: str,
    param2: Optional[int] = None
) -> Dict[str, Any]:
    """
    Brief one-line description.
    
    More detailed description explaining the method's purpose,
    behavior, and any important considerations.
    
    Args:
        param1: Description of the first parameter
        param2: Optional parameter with default value
        
    Returns:
        Dictionary containing the result data with keys:
        - "success": Boolean indicating operation success
        - "data": The actual result data
        
    Raises:
        ValidationError: If param1 is empty or invalid
        ProviderError: If the operation fails
        
    Example:
        >>> result = await provider.new_method("test_value")
        >>> print(result["success"])
        True
        
    Note:
        This method requires the provider to be initialized.
    """
    pass
```

#### Markdown Documentation

```markdown
## New Feature

Brief description of the new feature.

### Usage

```python
# Basic usage example
from permission_storage_manager import PermissionStorageManager

manager = PermissionStorageManager("redis")
result = await manager.new_feature("parameter")
```

### Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| param1 | str | required | Description of param1 |
| param2 | int | 100 | Description of param2 |

### Examples

#### Basic Example

```python
# Detailed example with explanation
```

#### Advanced Example

```python
# More complex usage scenario
```
```

---

## Submitting Changes

### Pull Request Process

#### 1. PR Requirements

Before submitting a PR, ensure:

- [ ] All tests pass (`pytest tests/`)
- [ ] Code is properly formatted (`black src/ tests/`)
- [ ] No linting errors (`flake8 src/ tests/`)
- [ ] Type checking passes (`mypy src/`)
- [ ] Test coverage is maintained or improved
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated

#### 2. PR Template

Use this template for your PR description:

```markdown
## Description

Brief description of the changes made.

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Changes Made

- Specific change 1
- Specific change 2
- Specific change 3

## Testing

- [ ] Added tests for new functionality
- [ ] All existing tests pass
- [ ] Tested with all providers (Redis, Memory, File)

## Performance Impact

Describe any performance implications of your changes.

## Breaking Changes

List any breaking changes and migration steps if applicable.

## Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review of the code completed
- [ ] Code is commented where necessary
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] CHANGELOG.md updated
```

#### 3. Review Process

1. **Automated Checks**: CI/CD pipeline runs tests and checks
2. **Code Review**: Maintainers review your code
3. **Feedback**: Address any feedback or requested changes
4. **Approval**: Once approved, your PR will be merged

### Commit Message Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Format: type(scope): description

# Types:
feat: new feature
fix: bug fix
docs: documentation changes
style: formatting, missing semicolons, etc.
refactor: code change that neither fixes a bug nor adds a feature
test: adding missing tests
chore: maintain, dependencies, build changes

# Examples:
feat(providers): add PostgreSQL provider
fix(redis): handle connection timeout properly
docs(api): update store_permissions documentation
test(memory): add concurrent access tests
refactor(core): simplify session validation logic
```

---

## Creating New Providers

### Provider Implementation Guide

To create a new storage provider, follow these steps:

#### 1. Create Provider Class

```python
# src/permission_storage_manager/providers/your_provider.py
from typing import List, Optional, Dict, Any
from ..core.base import BaseProvider
from ..core.exceptions import ProviderError

class YourProvider(BaseProvider):
    """
    Your storage provider implementation.
    
    This provider uses [storage system] for persistence.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        # Initialize your provider-specific attributes
        self._connection = None
    
    async def initialize(self) -> None:
        """Initialize connection to your storage system."""
        try:
            # Initialize connection
            self._connection = await connect_to_your_system(self.config)
            self._initialized = True
        except Exception as e:
            raise ProviderError(f"Failed to initialize: {e}") from e
    
    async def close(self) -> None:
        """Close connection and cleanup."""
        if self._connection:
            await self._connection.close()
            self._connection = None
        self._initialized = False
    
    # Implement all abstract methods from BaseProvider
    async def store_permissions(
        self,
        session_id: str,
        user_id: str,
        permissions: List[str],
        ttl: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Implement permission storage."""
        # Your implementation here
        pass
    
    # ... implement all other required methods
    
    @property
    def provider_name(self) -> str:
        return "your_provider"
    
    @property
    def supports_ttl(self) -> bool:
        return True  # or False if your system doesn't support TTL
```

#### 2. Add Provider Tests

```python
# tests/test_providers/test_your_provider.py
import pytest
from permission_storage_manager.providers import YourProvider

class TestYourProvider:
    """Test YourProvider implementation."""
    
    @pytest.fixture
    async def your_provider(self):
        config = {"connection_string": "your://connection/string"}
        provider = YourProvider(config)
        await provider.initialize()
        yield provider
        await provider.close()
    
    async def test_store_permissions(self, your_provider):
        """Test storing permissions."""
        result = await your_provider.store_permissions(
            "session_1", "user_1", ["read", "write"]
        )
        assert result is True
    
    # Add comprehensive tests for all functionality
```

#### 3. Register Provider

```python
# src/permission_storage_manager/providers/__init__.py
from .your_provider import YourProvider

AVAILABLE_PROVIDERS["your_provider"] = {
    "class": YourProvider,
    "description": "Your storage system provider",
    "features": ["ttl", "persistence"],  # List provider features
    "dependencies": ["your_dependency"],
    "available": True
}

# Add to __all__
__all__.append("YourProvider")
```

#### 4. Update Main Package

```python
# src/permission_storage_manager/__init__.py
def _register_builtin_providers():
    """Register built-in providers with the manager."""
    # ... existing providers
    
    try:
        from .providers.your_provider import YourProvider
        PermissionStorageManager.register_provider("your_provider", YourProvider)
    except ImportError:
        # Your provider dependencies not available
        pass
```

#### 5. Add Documentation

```markdown
<!-- docs/providers/your_provider.md -->
# Your Provider

Description of your storage provider.

## Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| connection_string | str | required | Connection to your system |

## Usage

```python
from permission_storage_manager import PermissionStorageManager

manager = PermissionStorageManager(
    provider="your_provider",
    config={
        "connection_string": "your://connection/string"
    }
)
```

## Features

- Native TTL support: Yes/No
- Clustering support: Yes/No
- Persistence: Yes/No
```

### Provider Guidelines

1. **Error Handling**: Use appropriate exception types from `core.exceptions`
2. **Logging**: Add comprehensive logging for debugging
3. **Configuration**: Validate configuration in `__init__`
4. **Testing**: Write comprehensive tests including error cases
5. **Documentation**: Document configuration options and usage
6. **Performance**: Consider performance implications of your implementation
7. **Thread Safety**: Ensure thread-safe operations if applicable

---

## Performance Guidelines

### Performance Considerations

When contributing code, consider these performance aspects:

#### 1. Async/Await Best Practices

```python
# Good: Proper async/await usage
async def efficient_operation():
    async with self._connection_pool.acquire() as conn:
        result = await conn.execute("SELECT * FROM sessions")
    return result

# Bad: Blocking operations in async context
async def inefficient_operation():
    time.sleep(1)  # Blocks the event loop
    return "result"
```

#### 2. Batch Operations

```python
# Good: Batch multiple operations
async def batch_store_permissions(self, sessions_data: List[Dict]):
    async with self._connection.pipeline() as pipe:
        for data in sessions_data:
            pipe.set(data["session_id"], data["permissions"])
        await pipe.execute()

# Bad: Individual operations in loop
async def individual_store_permissions(self, sessions_data: List[Dict]):
    for data in sessions_data:
        await self.store_permissions(data["session_id"], data["permissions"])
```

#### 3. Memory Usage

```python
# Good: Generator for large datasets
async def list_sessions_generator(self, limit: int = 1000):
    offset = 0
    while True:
        batch = await self._get_session_batch(offset, 1000)
        if not batch:
            break
        for session in batch:
            yield session
        offset += 1000

# Bad: Loading everything into memory
async def list_all_sessions(self):
    return await self._get_all_sessions()  # Could be millions of sessions
```

#### 4. Connection Management

```python
# Good: Connection pooling
class EfficientProvider(BaseProvider):
    def __init__(self, config):
        super().__init__(config)
        self._pool = ConnectionPool(max_connections=50)

# Bad: Creating new connections per operation
class InefficientProvider(BaseProvider):
    async def store_permissions(self, ...):
        conn = await create_connection()  # Expensive operation
        # ... use connection
        await conn.close()
```

### Performance Testing

```python
# Add performance tests for new features
@pytest.mark.slow
async def test_bulk_operations_performance(self, provider):
    """Test performance with bulk operations."""
    import time
    
    num_operations = 1000
    start_time = time.time()
    
    # Perform bulk operations
    for i in range(num_operations):
        await provider.store_permissions(f"session_{i}", f"user_{i}", ["read"])
    
    duration = time.time() - start_time
    ops_per_second = num_operations / duration
    
    print(f"Performance: {ops_per_second:.1f} ops/sec")
    
    # Assert reasonable performance
    assert ops_per_second > 100  # Adjust based on provider expectations
```

---

## Code Review Guidelines

### Review Process

1. **Automated Checks**: All PRs must pass CI/CD checks
2. **Code Review**: At least one maintainer must approve
3. **Documentation**: New features require documentation updates
4. **Tests**: New code must include appropriate tests

### What We Look For

#### Code Quality
- **Readability**: Code should be self-documenting
- **Performance**: No unnecessary performance regressions
- **Security**: No security vulnerabilities
- **Maintainability**: Code should be easy to maintain

#### Testing
- **Coverage**: New code should have good test coverage
- **Edge Cases**: Tests should cover edge cases and error conditions
- **Integration**: New features should have integration tests

#### Documentation
- **API Changes**: All API changes must be documented
- **Examples**: New features should include usage examples
- **Migration**: Breaking changes need migration guides

### Review Checklist

#### For Contributors
- [ ] Code follows project style guidelines
- [ ] Tests pass locally and in CI
- [ ] Documentation is updated
- [ ] No breaking changes without discussion
- [ ] Performance impact is considered

#### For Reviewers
- [ ] Code is clear and well-structured
- [ ] Tests are comprehensive
- [ ] Documentation is accurate
- [ ] Security implications are considered
- [ ] Performance impact is acceptable

### Review Comments

When commenting on PRs:

- **Be Specific**: Point to exact lines and explain issues
- **Be Constructive**: Suggest improvements, not just problems
- **Be Respectful**: Remember the human behind the code
- **Be Helpful**: Provide resources or examples when possible

---

## Security Considerations

### Security Guidelines

When contributing, keep these security considerations in mind:

#### 1. Input Validation

```python
# Good: Validate all inputs
def validate_session_id(session_id: str) -> None:
    if not session_id or not isinstance(session_id, str):
        raise InvalidSessionIdError(session_id, "Must be non-empty string")
    
    if len(session_id) > 255:
        raise InvalidSessionIdError(session_id, "Too long")
    
    if not re.match(r'^[a-zA-Z0-9\-_.]+$', session_id):
        raise InvalidSessionIdError(session_id, "Contains invalid characters")

# Bad: No validation
def store_permissions(self, session_id, ...):
    # Direct use without validation
    self._storage[session_id] = data
```

#### 2. Secure Defaults

```python
# Good: Secure defaults
class SecureProvider(BaseProvider):
    def __init__(self, config):
        self._config = {
            "ssl": True,                    # Enable SSL by default
            "file_permissions": 0o600,      # Restrictive file permissions
            "key_prefix": "secure:",        # Namespace isolation
            "max_ttl": 86400,              # Reasonable TTL limit
            **config
        }

# Bad: Insecure defaults
class InsecureProvider(BaseProvider):
    def __init__(self, config):
        self._config = {
            "ssl": False,                   # Insecure default
            "file_permissions": 0o777,      # World-writable
            **config
        }
```

#### 3. Sensitive Data Handling

```python
# Good: Careful logging of sensitive data
logger.info(f"Storing permissions for session {session_id[:8]}...")  # Truncated ID
logger.debug(f"Permission count: {len(permissions)}")  # Count, not content

# Bad: Logging sensitive information
logger.info(f"Storing permissions {permissions} for session {session_id}")
```

#### 4. Error Information Disclosure

```python
# Good: Generic error messages to users
try:
    result = await database.query(sql, params)
except DatabaseError as e:
    logger.error(f"Database error: {e}")  # Log detailed error
    raise ProviderError("Storage operation failed")  # Generic user message

# Bad: Exposing internal details
try:
    result = await database.query(sql, params)
except DatabaseError as e:
    raise ProviderError(f"SQL error: {e}")  # Exposes internal structure
```

### Security Testing

```python
# Add security-focused tests
class TestSecurity:
    async def test_session_id_injection(self, provider):
        """Test that malicious session IDs are rejected."""
        malicious_ids = [
            "../../../etc/passwd",
            "'; DROP TABLE sessions; --",
            "<script>alert('xss')</script>",
            "\x00\x01\x02"  # Null bytes
        ]
        
        for malicious_id in malicious_ids:
            with pytest.raises(InvalidSessionIdError):
                await provider.store_permissions(malicious_id, "user", ["read"])
    
    async def test_ttl_limits(self, provider):
        """Test that TTL limits are enforced."""
        with pytest.raises(TTLError):
            await provider.store_permissions("session", "user", ["read"], ttl=999999999)
```

---

## Release Process

### Version Management

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Creating a Release

1. **Update Version**: Update version in `pyproject.toml` and `__init__.py`
2. **Update CHANGELOG**: Document all changes since last release
3. **Create Release PR**: Submit PR with version bump and changelog
4. **Tag Release**: After merging, create git tag
5. **Publish**: GitHub Actions will publish to PyPI

### CHANGELOG Format

```markdown
# Changelog

## [1.2.0] - 2024-01-15

### Added
- New PostgreSQL provider
- Support for role-based permissions
- Performance improvements for Redis provider

### Changed
- Improved error messages for validation failures
- Updated dependencies to latest versions

### Deprecated
- Old configuration format (will be removed in v2.0)

### Removed
- Support for Python 3.7

### Fixed
- Memory leak in file provider cleanup
- Race condition in concurrent session access

### Security
- Fixed potential session ID enumeration vulnerability
```

---

## Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Discord**: Real-time chat (link in README)
- **Email**: maintainers@permission-storage-manager.dev

### Asking for Help

When asking for help:

1. **Search First**: Check existing issues and documentation
2. **Provide Context**: Include relevant code, error messages, and environment details
3. **Minimal Example**: Create a minimal reproducible example
4. **Be Specific**: Clearly describe what you expect vs. what happens

### Issue Templates

Use our issue templates:

- **Bug Report**: For reporting bugs
- **Feature Request**: For suggesting new features
- **Provider Request**: For requesting new storage providers
- **Documentation**: For documentation improvements

---

## Recognition

### Contributors

All contributors are recognized in:

- **README.md**: Contributors section
- **Release Notes**: Major contributors mentioned
- **GitHub**: Contributor graphs and statistics

### Contribution Types

We recognize all types of contributions:

- 🐛 **Bug fixes**
- ✨ **New features**
- 📝 **Documentation improvements**
- 🧪 **Testing enhancements**
- 🚀 **Performance optimizations**
- 🎨 **Code quality improvements**
- 💡 **Ideas and suggestions**
- 🤝 **Community support**

### Attribution

- **Git commits**: All commits are attributed to their authors
- **Release notes**: Significant contributors are mentioned
- **Documentation**: Contributor acknowledgments in relevant sections
- **Special recognition**: Outstanding contributions receive special mention

---

## Maintainer Guidelines

### For Project Maintainers

#### Code Review Checklist

When reviewing pull requests, check for:

**Functionality**
- [ ] Code works as intended
- [ ] Edge cases are handled
- [ ] Error handling is appropriate
- [ ] No breaking changes (or properly documented)

**Code Quality**
- [ ] Follows project coding standards
- [ ] Type hints are present and correct
- [ ] Docstrings are comprehensive
- [ ] Code is readable and well-structured

**Testing**
- [ ] Tests cover new functionality
- [ ] All tests pass
- [ ] Test coverage is maintained or improved
- [ ] Performance tests included if relevant

**Documentation**
- [ ] API documentation updated
- [ ] User guide updated if necessary
- [ ] Examples provided for new features
- [ ] CHANGELOG.md updated

**Security & Performance**
- [ ] No security vulnerabilities introduced
- [ ] Performance implications considered
- [ ] Resource usage is reasonable
- [ ] Follows security best practices

#### Release Management

**Preparation**
1. Review all changes since last release
2. Update version numbers consistently
3. Update CHANGELOG.md with all changes
4. Test release candidate thoroughly
5. Update documentation for new features

**Release Process**
1. Create release branch
2. Update version and changelog
3. Create and merge release PR
4. Tag release with semantic version
5. GitHub Actions handles PyPI publication
6. Update documentation sites
7. Announce release

**Post-Release**
1. Monitor for issues
2. Address critical bugs quickly
3. Plan next release cycle
4. Update roadmap if needed

---

## Development Tools

### Recommended IDE Setup

#### VS Code Extensions
```json
{
    "recommendations": [
        "ms-python.python",
        "ms-python.black-formatter",
        "ms-python.flake8",
        "ms-python.mypy-type-checker",
        "ms-python.isort",
        "redhat.vscode-yaml",
        "ms-python.pytest"
    ]
}
```

#### VS Code Settings
```json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black",
    "python.testing.pytestEnabled": true,
    "python.testing.unittestEnabled": false,
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    }
}
```

### Development Scripts

Create these utility scripts for common tasks:

#### `scripts/setup.sh`
```bash
#!/bin/bash
# Development environment setup script

set -e

echo "Setting up Permission Storage Manager development environment..."

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -e ".[all,dev]"

# Install pre-commit hooks
pre-commit install

# Run initial tests
pytest tests/test_manager.py -v

echo "Setup complete! Activate with: source venv/bin/activate"
```

#### `scripts/test.sh`
```bash
#!/bin/bash
# Comprehensive testing script

set -e

echo "Running comprehensive test suite..."

# Code formatting
echo "Checking code formatting..."
black --check src/ tests/

# Linting
echo "Running linting..."
flake8 src/ tests/

# Type checking
echo "Running type checking..."
mypy src/

# Import sorting
echo "Checking import sorting..."
isort --check-only src/ tests/

# Tests with coverage
echo "Running tests with coverage..."
pytest tests/ --cov=permission_storage_manager --cov-report=term-missing

echo "All checks passed!"
```

#### `scripts/release.sh`
```bash
#!/bin/bash
# Release preparation script

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.2.0"
    exit 1
fi

VERSION=$1
echo "Preparing release $VERSION..."

# Update version in pyproject.toml
sed -i "s/version = \".*\"/version = \"$VERSION\"/" pyproject.toml

# Update version in __init__.py
sed -i "s/__version__ = \".*\"/__version__ = \"$VERSION\"/" src/permission_storage_manager/__init__.py

# Update CHANGELOG.md
echo "Please update CHANGELOG.md with changes for version $VERSION"
echo "Press any key when ready..."
read -n 1

# Create release commit
git add pyproject.toml src/permission_storage_manager/__init__.py CHANGELOG.md
git commit -m "chore: bump version to $VERSION"

# Create tag
git tag -a "v$VERSION" -m "Release version $VERSION"

echo "Release $VERSION prepared!"
echo "Next steps:"
echo "1. Push changes: git push origin main"
echo "2. Push tags: git push origin v$VERSION"
echo "3. Create GitHub release"
```

### Debugging Tools

#### Enable Debug Logging
```python
# debug_config.py
import logging
from permission_storage_manager.utils import setup_logger

def enable_debug_logging():
    """Enable detailed debug logging for development."""
    
    # Set up debug logging
    logger = setup_logger("permission_storage", "DEBUG")
    
    # Enable asyncio debug mode
    import asyncio
    asyncio.get_event_loop().set_debug(True)
    
    # Log configuration
    logger.debug("Debug logging enabled")
    
    return logger

# Usage in tests or development
logger = enable_debug_logging()
```

#### Performance Profiling
```python
# profile_performance.py
import cProfile
import pstats
from permission_storage_manager import create_manager

async def profile_operations():
    """Profile performance of common operations."""
    
    manager = create_manager("memory")
    
    # Profile store operations
    pr = cProfile.Profile()
    pr.enable()
    
    for i in range(1000):
        await manager.store_permissions(f"session_{i}", f"user_{i}", ["read"])
    
    pr.disable()
    
    # Show results
    stats = pstats.Stats(pr)
    stats.sort_stats('cumulative')
    stats.print_stats(10)

# Run profiling
import asyncio
asyncio.run(profile_operations())
```

---

## Troubleshooting Development Issues

### Common Issues and Solutions

#### 1. Import Errors
```bash
# Problem: Cannot import permission_storage_manager
# Solution: Install in development mode
pip install -e .

# Problem: Cannot import test modules
# Solution: Add src to Python path or use pytest
export PYTHONPATH="${PYTHONPATH}:${PWD}/src"
pytest tests/
```

#### 2. Test Failures
```bash
# Problem: Redis tests fail
# Solution: Start Redis server
docker run -d -p 6379:6379 redis:7-alpine

# Problem: File permission errors
# Solution: Check file permissions and ownership
chmod 755 tests/
sudo chown -R $USER:$USER tests/
```

#### 3. Code Quality Issues
```bash
# Problem: Black formatting failures
# Solution: Run black to fix formatting
black src/ tests/

# Problem: Flake8 linting errors
# Solution: Fix linting issues or update configuration
flake8 src/ tests/ --ignore=E501,W503

# Problem: MyPy type errors
# Solution: Add type hints or type ignores
mypy src/ --ignore-missing-imports
```

#### 4. Performance Issues
```python
# Problem: Tests running slowly
# Solution: Use faster providers for testing
@pytest.fixture
def fast_manager():
    return PermissionStorageManager("memory", {"cleanup_interval": 1})

# Problem: Memory usage growing during tests
# Solution: Ensure proper cleanup
@pytest.fixture
async def clean_manager():
    manager = PermissionStorageManager("memory")
    yield manager
    await manager.close()  # Ensure cleanup
```

### Getting Debug Information

```python
# debug_info.py
async def collect_debug_info():
    """Collect comprehensive debug information."""
    
    from permission_storage_manager import get_version_info, get_supported_providers
    from permission_storage_manager.utils import check_dependencies
    
    info = {
        "version": get_version_info(),
        "providers": get_supported_providers(),
        "dependencies": check_dependencies(),
        "python_path": sys.path,
        "working_directory": os.getcwd(),
        "environment": dict(os.environ)
    }
    
    # Test basic functionality
    try:
        manager = PermissionStorageManager("memory")
        await manager.store_permissions("debug_test", "debug_user", ["test"])
        has_test = await manager.check_permission("debug_test", "test")
        await manager.close()
        
        info["functionality_test"] = {
            "status": "success" if has_test else "failed",
            "details": "Basic operations working"
        }
    except Exception as e:
        info["functionality_test"] = {
            "status": "error",
            "error": str(e)
        }
    
    return info

# Use when reporting issues
import asyncio
debug_info = asyncio.run(collect_debug_info())
print(json.dumps(debug_info, indent=2))
```

---

## Advanced Contributing Topics

### Custom Provider Development

For complex providers that need special consideration:

#### Database Providers
```python
# Example: PostgreSQL provider implementation
class PostgreSQLProvider(BaseProvider):
    """PostgreSQL-based permission storage."""
    
    def __init__(self, config):
        super().__init__(config)
        self._pool = None
        self._schema = config.get("schema", "permissions")
    
    async def initialize(self):
        """Initialize connection pool and create tables."""
        import asyncpg
        
        self._pool = await asyncpg.create_pool(
            self.config["dsn"],
            min_size=5,
            max_size=20
        )
        
        # Create schema and tables
        await self._create_schema()
        self._initialized = True
    
    async def _create_schema(self):
        """Create necessary database schema."""
        async with self._pool.acquire() as conn:
            await conn.execute(f"""
                CREATE SCHEMA IF NOT EXISTS {self._schema}
            """)
            
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {self._schema}.sessions (
                    session_id VARCHAR(255) PRIMARY KEY,
                    user_id VARCHAR(255) NOT NULL,
                    permissions JSONB NOT NULL,
                    metadata JSONB DEFAULT '{{}}',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    expires_at TIMESTAMP WITH TIME ZONE
                )
            """)
            
            # Create indices for performance
            await conn.execute(f"""
                CREATE INDEX IF NOT EXISTS idx_sessions_user_id 
                ON {self._schema}.sessions(user_id)
            """)
```

#### Cloud Storage Providers
```python
# Example: AWS DynamoDB provider
class DynamoDBProvider(BaseProvider):
    """AWS DynamoDB provider for scalable permission storage."""
    
    def __init__(self, config):
        super().__init__(config)
        self._dynamodb = None
        self._table_name = config.get("table_name", "permission_sessions")
    
    async def initialize(self):
        """Initialize DynamoDB client."""
        import aioboto3
        
        session = aioboto3.Session()
        self._dynamodb = await session.resource(
            'dynamodb',
            region_name=self.config.get('region', 'us-east-1')
        ).__aenter__()
        
        # Ensure table exists
        await self._ensure_table_exists()
        self._initialized = True
    
    async def store_permissions(self, session_id, user_id, permissions, ttl=None, metadata=None):
        """Store permissions in DynamoDB."""
        table = await self._dynamodb.Table(self._table_name)
        
        item = {
            'session_id': session_id,
            'user_id': user_id,
            'permissions': permissions,
            'metadata': metadata or {},
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }
        
        if ttl:
            item['ttl'] = int(time.time()) + ttl
        
        await table.put_item(Item=item)
        return True
```

### Performance Optimization Contributions

When contributing performance improvements:

#### Profiling Integration
```python
# performance/profiler.py
import cProfile
import pstats
from functools import wraps

def profile_method(method):
    """Decorator to profile method performance."""
    @wraps(method)
    async def wrapper(*args, **kwargs):
        pr = cProfile.Profile()
        pr.enable()
        
        try:
            result = await method(*args, **kwargs)
            return result
        finally:
            pr.disable()
            
            # Save profile data
            pr.dump_stats(f"profile_{method.__name__}.prof")
            
            # Print quick stats
            stats = pstats.Stats(pr)
            stats.sort_stats('cumulative')
            stats.print_stats(5)
    
    return wrapper

# Usage in providers
class OptimizedProvider(BaseProvider):
    @profile_method
    async def store_permissions(self, ...):
        # Implementation here
        pass
```

#### Benchmarking Framework
```python
# performance/benchmark.py
import time
import asyncio
from typing import Dict, Any
from permission_storage_manager import PermissionStorageManager

class ProviderBenchmark:
    """Benchmark framework for comparing provider performance."""
    
    def __init__(self, providers: Dict[str, Dict[str, Any]]):
        self.providers = providers
        self.results = {}
    
    async def run_benchmarks(self):
        """Run comprehensive benchmarks on all providers."""
        
        for provider_name, config in self.providers.items():
            print(f"Benchmarking {provider_name}...")
            
            manager = PermissionStorageManager(provider_name, config)
            await manager.initialize()
            
            try:
                results = await self._benchmark_provider(manager)
                self.results[provider_name] = results
            finally:
                await manager.close()
    
    async def _benchmark_provider(self, manager):
        """Benchmark a specific provider."""
        results = {}
        
        # Store operations benchmark
        results['store'] = await self._benchmark_store_operations(manager)
        
        # Check operations benchmark
        results['check'] = await self._benchmark_check_operations(manager)
        
        # Concurrent operations benchmark
        results['concurrent'] = await self._benchmark_concurrent_operations(manager)
        
        return results
    
    async def _benchmark_store_operations(self, manager, count=1000):
        """Benchmark store operations."""
        start_time = time.time()
        
        for i in range(count):
            await manager.store_permissions(f"bench_session_{i}", f"user_{i}", ["read"])
        
        duration = time.time() - start_time
        
        return {
            'operations': count,
            'duration': duration,
            'ops_per_second': count / duration
        }

# Usage
benchmark = ProviderBenchmark({
    'memory': {},
    'redis': {'url': 'redis://localhost:6379'},
    'file': {'storage_dir': '/tmp/benchmark'}
})

await benchmark.run_benchmarks()
```

### Documentation Contributions

#### API Documentation Generation
```python
# docs/generate_api_docs.py
import inspect
import ast
from pathlib import Path

def generate_provider_api_docs():
    """Generate API documentation for all providers."""
    
    providers_dir = Path("src/permission_storage_manager/providers")
    docs_dir = Path("docs/providers")
    docs_dir.mkdir(exist_ok=True)
    
    for provider_file in providers_dir.glob("*_provider.py"):
        provider_name = provider_file.stem
        
        # Parse the Python file
        with open(provider_file) as f:
            tree = ast.parse(f.read())
        
        # Extract class documentation
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name.endswith('Provider'):
                class_doc = ast.get_docstring(node)
                
                # Generate documentation
                doc_content = generate_provider_doc(provider_name, class_doc, node)
                
                # Write documentation file
                doc_file = docs_dir / f"{provider_name}.md"
                with open(doc_file, 'w') as f:
                    f.write(doc_content)

def generate_provider_doc(name, docstring, class_node):
    """Generate markdown documentation for a provider."""
    # Implementation to generate comprehensive provider docs
    pass
```

---

## Community and Governance

### Project Governance

The project follows an open governance model:

- **Maintainers**: Core team responsible for project direction
- **Contributors**: Community members who contribute code, docs, or ideas
- **Users**: People who use the library and provide feedback

### Decision Making Process

1. **Minor Changes**: Direct pull requests
2. **Major Changes**: RFC (Request for Comments) process
3. **Breaking Changes**: Community discussion and consensus
4. **New Providers**: Review for quality and maintenance commitment

### Communication Guidelines

- **Be Respectful**: Treat all community members with respect
- **Be Constructive**: Provide helpful feedback and suggestions
- **Be Patient**: Maintainers and contributors are often volunteers
- **Be Clear**: Communicate clearly and provide necessary context

---

Thank you for contributing to Permission Storage Manager! Your efforts help make this project better for everyone. 🚀

For questions about contributing, please:
- Open a GitHub Discussion for general questions
- Create an issue for specific problems
- Join our Discord for real-time discussion
- Email maintainers for sensitive topics

Happy coding! 🎉