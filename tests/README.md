# Project Mumei - Test Suite

## Overview

This directory contains comprehensive tests for Project Mumei, including unit tests, integration tests, and system tests.

## Test Structure

```
tests/
├── unit/                    # Unit tests
│   ├── test_models.py      # Data model tests
│   ├── test_base_agent.py  # Base agent tests
│   └── test_state_manager.py # State manager tests
├── integration/             # Integration tests
│   └── test_blackboard.py  # Blackboard/Redis tests
├── system/                  # System tests
│   └── test_deployment.py  # Full deployment and engagement tests
└── README.md               # This file
```

## Running Tests

### All Tests
```bash
pytest
```

### Unit Tests Only
```bash
pytest tests/unit/
```

### Integration Tests Only
```bash
pytest tests/integration/
```

### System Tests Only
```bash
pytest tests/system/
```

### Specific Test File
```bash
pytest tests/unit/test_models.py
```

### Specific Test Class
```bash
pytest tests/unit/test_models.py::TestEvent
```

### Specific Test Method
```bash
pytest tests/unit/test_models.py::TestEvent::test_event_creation
```

### With Coverage
```bash
pytest --cov=mumei --cov=agents --cov-report=html
```

### Verbose Output
```bash
pytest -v
```

### Show Print Statements
```bash
pytest -s
```

## Test Categories

### Unit Tests
- **test_models.py**: Tests for all Pydantic data models
  - Event creation and validation
  - Host, Service, Vulnerability models
  - Credential, Session, Evidence models
  - GlobalState and query models
  - Serialization/deserialization
  - Edge cases and validation

- **test_base_agent.py**: Tests for BaseAgent class
  - Initialization and configuration
  - Event publishing and subscription
  - CLI command execution
  - State queries
  - Logging and heartbeats
  - Shutdown procedures

- **test_state_manager.py**: Tests for State Manager
  - State initialization
  - Event handling (all event types)
  - State queries with filters
  - State export
  - Metadata updates

### Integration Tests
- **test_blackboard.py**: Tests for Blackboard (Redis Pub/Sub)
  - Connection management
  - Event publishing
  - Event subscription
  - Performance and latency
  - Error handling
  - Concurrent operations
  - Real agent communication flows

### System Tests
- **test_deployment.py**: End-to-end deployment and engagement tests
  - Scope configuration setup (config/scope.json)
  - Environment file management (.env.local/.env)
  - Script permissions and execution
  - Service startup (start.sh)
  - Engagement initialization (init_engagement.sh)
  - Docker container log monitoring
  - Graceful shutdown procedures (stop.sh)
  - Full deployment workflow orchestration

#### Running System Tests

**Full deployment test** (executes complete workflow):
```bash
python tests/system/test_deployment.py
```

**With pytest** (runs specific test methods):
```bash
# Run full deployment
pytest tests/system/test_deployment.py::TestDeployment::test_full_deployment

# Run individual steps
pytest tests/system/test_deployment.py::TestDeployment::test_write_scope_config
pytest tests/system/test_deployment.py::TestDeployment::test_run_start_script
```

**Note**: System tests require Docker and docker-compose to be installed and running. Press Ctrl+C during log monitoring to trigger graceful shutdown.

## Prerequisites

### For Unit Tests
```bash
pip install pytest pytest-mock
```

### For Integration Tests
```bash
# Requires Redis running
docker run -d -p 6379:6379 redis:7-alpine

# Or use docker-compose
docker-compose up -d redis
```

### For System Tests
```bash
# Requires Docker and docker-compose
docker --version
docker-compose --version

# Ensure scripts directory exists with executable shell scripts
ls -la scripts/
```

### For Coverage Reports
```bash
pip install pytest-cov
```

## Test Markers

Tests are marked with pytest markers for selective execution:

- `@pytest.mark.unit`: Unit tests (no external dependencies)
- `@pytest.mark.integration`: Integration tests (require Redis)
- `@pytest.mark.system`: System tests (require Docker/services)
- `@pytest.mark.slow`: Slow-running tests
- `@pytest.mark.agent`: Agent-specific tests

### Run Only Unit Tests
```bash
pytest -m unit
```

### Run Only Integration Tests
```bash
pytest -m integration
```

### Run Only System Tests
```bash
pytest -m system
```

### Skip Slow Tests
```bash
pytest -m "not slow"
```

## Continuous Integration

### GitHub Actions Example
```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
    
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pip install pytest pytest-cov
      - run: pytest --cov=mumei --cov-report=xml
      - uses: codecov/codecov-action@v2
```

## Writing New Tests

### Unit Test Template
```python
import pytest
from mumei.shared.models import YourModel

class TestYourModel:
    """Test YourModel"""
    
    def test_creation(self):
        """Test creating a model"""
        model = YourModel(field="value")
        assert model.field == "value"
    
    def test_validation(self):
        """Test validation"""
        with pytest.raises(ValidationError):
            YourModel(invalid_field="value")
```

### Integration Test Template
```python
import pytest
from mumei.shared.blackboard import Blackboard

@pytest.fixture
def blackboard():
    bb = Blackboard()
    yield bb
    bb.close()

class TestIntegration:
    """Integration tests"""
    
    def test_feature(self, blackboard):
        """Test a feature"""
        # Test code here
        pass
```

### System Test Template
```python
import pytest
import subprocess

class TestSystemFeature:
    """System test for feature"""
    
    def test_feature_deployment(self):
        """Test feature deployment workflow"""
        # Setup
        # Execute
        # Verify
        # Cleanup
        pass
```

## Test Coverage Goals

- **Unit Tests**: >80% code coverage
- **Integration Tests**: All critical paths
- **System Tests**: End-to-end workflows

## Current Coverage

Run to see current coverage:
```bash
pytest --cov=mumei --cov=agents --cov-report=term-missing
```

## Troubleshooting

### Redis Connection Errors
```bash
# Check if Redis is running
docker ps | grep redis

# Start Redis
docker-compose up -d redis

# Test Redis connection
redis-cli ping
```

### Docker/System Test Errors
```bash
# Check Docker status
docker ps

# Check docker-compose services
docker-compose ps

# View service logs
docker-compose logs

# Stop all services
./scripts/stop.sh
```

### Import Errors
```bash
# Ensure PYTHONPATH is set
export PYTHONPATH=$PWD:$PYTHONPATH

# Or install in development mode
pip install -e .
```

### Slow Tests
```bash
# Skip slow tests
pytest -m "not slow"

# Run with timeout
pytest --timeout=10
```

## Best Practices

1. **Isolation**: Each test should be independent
2. **Mocking**: Use mocks for external dependencies in unit tests
3. **Fixtures**: Use pytest fixtures for common setup
4. **Naming**: Use descriptive test names (test_what_when_then)
5. **Documentation**: Add docstrings to test classes and methods
6. **Assertions**: Use specific assertions with clear messages
7. **Cleanup**: Always clean up resources (use fixtures with yield)
8. **System Tests**: Ensure proper cleanup even on test failure

## Contributing

When adding new features:
1. Write tests first (TDD)
2. Ensure all tests pass
3. Maintain >80% coverage
4. Update this README if needed

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Pytest Best Practices](https://docs.pytest.org/en/stable/goodpractices.html)
- [Python Testing Guide](https://realpython.com/pytest-python-testing/)
