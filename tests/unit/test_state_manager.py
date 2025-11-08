"""
Unit tests for State Manager
"""

import pytest
from unittest.mock import Mock, MagicMock
import json

from agents.state_manager.state_manager import StateManager
from mumei.shared.models import (
    Event, EventType, Scope, Host, Service, Vulnerability,
    Credential, Session, Evidence
)


@pytest.fixture
def mock_redis():
    """Create a mock Redis client"""
    redis_mock = MagicMock()
    redis_mock.ping.return_value = True
    redis_mock.get.return_value = None
    redis_mock.set.return_value = True
    return redis_mock


@pytest.fixture
def state_manager(mock_redis, monkeypatch):
    """Create a State Manager with mocked Redis"""
    def mock_redis_init(*args, **kwargs):
        return mock_redis
    
    monkeypatch.setattr("redis.Redis", mock_redis_init)
    
    sm = StateManager(redis_host="localhost", redis_port=6379)
    return sm


class TestStateManagerInitialization:
    """Test State Manager initialization"""

    def test_initialization(self, state_manager):
        """Test State Manager initializes correctly"""
        assert state_manager.state is None
        assert state_manager.redis_client is not None

    def test_initialize_state(self, state_manager):
        """Test initializing global state"""
        scope = Scope(
            engagement_name="Test Engagement",
            targets=["192.168.1.0/24"]
        )
        
        state_manager.initialize_state(scope)
        
        assert state_manager.state is not None
        assert state_manager.state.scope.engagement_name == "Test Engagement"
        assert len(state_manager.state.hosts) == 0


class TestStateManagerEventHandling:
    """Test event handling"""

    def test_handle_host_found(self, state_manager):
        """Test handling HostFound event"""
        scope = Scope(engagement_name="Test", targets=["10.0.0.0/24"])
        state_manager.initialize_state(scope)
        
        event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={
                "ip_address": "10.0.0.1",
                "hostname": "test.local"
            }
        )
        
        state_manager.update_from_event(event)
        
        assert len(state_manager.state.hosts) == 1
        host = list(state_manager.state.hosts.values())[0]
        assert host.ip_address == "10.0.0.1"
        assert host.hostname == "test.local"

    def test_handle_service_discovered(self, state_manager):
        """Test handling ServiceDiscovered event"""
        scope = Scope(engagement_name="Test", targets=["10.0.0.0/24"])
        state_manager.initialize_state(scope)
        
        # First add a host
        host_event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={"ip_address": "10.0.0.1"}
        )
        state_manager.update_from_event(host_event)
        
        # Then add a service
        service_event = Event(
            event_type=EventType.SERVICE_DISCOVERED,
            source_agent_id="test_agent",
            data={
                "target": "10.0.0.1",
                "port": 80,
                "protocol": "tcp",
                "service_name": "http",
                "banner": "Apache/2.4.49"
            }
        )
        state_manager.update_from_event(service_event)
        
        assert len(state_manager.state.services) == 1
        service = list(state_manager.state.services.values())[0]
        assert service.port == 80
        assert service.service_name == "http"

    def test_handle_vulnerability_identified(self, state_manager):
        """Test handling VulnerabilityIdentified event"""
        scope = Scope(engagement_name="Test", targets=["10.0.0.0/24"])
        state_manager.initialize_state(scope)
        
        # Add host and service first
        host_event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={"ip_address": "10.0.0.1"}
        )
        state_manager.update_from_event(host_event)
        
        service_event = Event(
            event_type=EventType.SERVICE_DISCOVERED,
            source_agent_id="test_agent",
            data={
                "target": "10.0.0.1",
                "port": 80,
                "protocol": "tcp",
                "service_name": "http"
            }
        )
        state_manager.update_from_event(service_event)
        
        service_id = list(state_manager.state.services.keys())[0]
        
        # Add vulnerability
        vuln_event = Event(
            event_type=EventType.VULNERABILITY_IDENTIFIED,
            source_agent_id="test_agent",
            data={
                "service_id": service_id,
                "cve_id": "CVE-2021-41773",
                "cvss_score": 7.5,
                "title": "Apache Path Traversal",
                "description": "Path traversal vulnerability"
            }
        )
        state_manager.update_from_event(vuln_event)
        
        assert len(state_manager.state.vulnerabilities) == 1
        vuln = list(state_manager.state.vulnerabilities.values())[0]
        assert vuln.cve_id == "CVE-2021-41773"

    def test_handle_host_compromised(self, state_manager):
        """Test handling HostCompromised event"""
        scope = Scope(engagement_name="Test", targets=["10.0.0.0/24"])
        state_manager.initialize_state(scope)
        
        # Add host first
        host_event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={"ip_address": "10.0.0.1"}
        )
        state_manager.update_from_event(host_event)
        
        host_id = list(state_manager.state.hosts.keys())[0]
        
        # Compromise host
        compromise_event = Event(
            event_type=EventType.HOST_COMPROMISED,
            source_agent_id="test_agent",
            data={
                "host_id": host_id,
                "session_type": "meterpreter",
                "user": "www-data",
                "privileges": "user"
            }
        )
        state_manager.update_from_event(compromise_event)
        
        assert state_manager.state.hosts[host_id].status == "compromised"
        assert len(state_manager.state.sessions) == 1

    def test_handle_credential_discovered(self, state_manager):
        """Test handling CredentialDiscovered event"""
        scope = Scope(engagement_name="Test", targets=["10.0.0.0/24"])
        state_manager.initialize_state(scope)
        
        # Add host first
        host_event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={"ip_address": "10.0.0.1"}
        )
        state_manager.update_from_event(host_event)
        
        host_id = list(state_manager.state.hosts.keys())[0]
        
        # Add credential
        cred_event = Event(
            event_type=EventType.CREDENTIAL_DISCOVERED,
            source_agent_id="test_agent",
            data={
                "source_host_id": host_id,
                "username": "admin",
                "password": "password123"
            }
        )
        state_manager.update_from_event(cred_event)
        
        assert len(state_manager.state.credentials) == 1
        cred = state_manager.state.credentials[0]
        assert cred.username == "admin"


class TestStateManagerQueries:
    """Test state query functionality"""

    def test_query_hosts(self, state_manager):
        """Test querying hosts"""
        scope = Scope(engagement_name="Test", targets=["10.0.0.0/24"])
        state_manager.initialize_state(scope)
        
        # Add multiple hosts
        for i in range(3):
            event = Event(
                event_type=EventType.HOST_FOUND,
                source_agent_id="test_agent",
                data={"ip_address": f"10.0.0.{i+1}"}
            )
            state_manager.update_from_event(event)
        
        # Query all hosts
        results = state_manager.query("hosts", {})
        assert len(results) == 3

    def test_query_hosts_with_filter(self, state_manager):
        """Test querying hosts with filters"""
        scope = Scope(engagement_name="Test", targets=["10.0.0.0/24"])
        state_manager.initialize_state(scope)
        
        # Add hosts with different statuses
        event1 = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={"ip_address": "10.0.0.1"}
        )
        state_manager.update_from_event(event1)
        
        host_id = list(state_manager.state.hosts.keys())[0]
        state_manager.state.hosts[host_id].status = "compromised"
        
        event2 = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={"ip_address": "10.0.0.2"}
        )
        state_manager.update_from_event(event2)
        
        # Query compromised hosts
        results = state_manager.query("hosts", {"status": "compromised"})
        assert len(results) == 1
        assert results[0]["ip_address"] == "10.0.0.1"

    def test_query_services(self, state_manager):
        """Test querying services"""
        scope = Scope(engagement_name="Test", targets=["10.0.0.0/24"])
        state_manager.initialize_state(scope)
        
        # Add host and services
        host_event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={"ip_address": "10.0.0.1"}
        )
        state_manager.update_from_event(host_event)
        
        for port in [80, 443, 22]:
            service_event = Event(
                event_type=EventType.SERVICE_DISCOVERED,
                source_agent_id="test_agent",
                data={
                    "target": "10.0.0.1",
                    "port": port,
                    "protocol": "tcp",
                    "service_name": "test"
                }
            )
            state_manager.update_from_event(service_event)
        
        results = state_manager.query("services", {})
        assert len(results) == 3

    def test_query_vulnerabilities(self, state_manager):
        """Test querying vulnerabilities"""
        scope = Scope(engagement_name="Test", targets=["10.0.0.0/24"])
        state_manager.initialize_state(scope)
        
        # Setup host and service
        host_event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={"ip_address": "10.0.0.1"}
        )
        state_manager.update_from_event(host_event)
        
        service_event = Event(
            event_type=EventType.SERVICE_DISCOVERED,
            source_agent_id="test_agent",
            data={
                "target": "10.0.0.1",
                "port": 80,
                "protocol": "tcp",
                "service_name": "http"
            }
        )
        state_manager.update_from_event(service_event)
        
        service_id = list(state_manager.state.services.keys())[0]
        
        # Add vulnerabilities
        for i in range(2):
            vuln_event = Event(
                event_type=EventType.VULNERABILITY_IDENTIFIED,
                source_agent_id="test_agent",
                data={
                    "service_id": service_id,
                    "title": f"Vulnerability {i}",
                    "description": "Test vulnerability"
                }
            )
            state_manager.update_from_event(vuln_event)
        
        results = state_manager.query("vulnerabilities", {})
        assert len(results) == 2


class TestStateManagerExport:
    """Test state export functionality"""

    def test_export_empty_state(self, state_manager):
        """Test exporting empty state"""
        scope = Scope(engagement_name="Test", targets=["10.0.0.0/24"])
        state_manager.initialize_state(scope)
        
        exported = state_manager.export_state()
        
        assert "scope" in exported
        assert "hosts" in exported
        assert "services" in exported
        assert exported["scope"]["engagement_name"] == "Test"

    def test_export_with_data(self, state_manager):
        """Test exporting state with data"""
        scope = Scope(engagement_name="Test", targets=["10.0.0.0/24"])
        state_manager.initialize_state(scope)
        
        # Add some data
        host_event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={"ip_address": "10.0.0.1"}
        )
        state_manager.update_from_event(host_event)
        
        exported = state_manager.export_state()
        
        assert len(exported["hosts"]) == 1
        assert "10.0.0.1" in str(exported)


class TestStateManagerMetadata:
    """Test metadata updates"""

    def test_metadata_counts(self, state_manager):
        """Test metadata count updates"""
        scope = Scope(engagement_name="Test", targets=["10.0.0.0/24"])
        state_manager.initialize_state(scope)
        
        # Add hosts
        for i in range(3):
            event = Event(
                event_type=EventType.HOST_FOUND,
                source_agent_id="test_agent",
                data={"ip_address": f"10.0.0.{i+1}"}
            )
            state_manager.update_from_event(event)
        
        assert state_manager.state.metadata.total_hosts == 3

    def test_metadata_compromised_count(self, state_manager):
        """Test compromised host count"""
        scope = Scope(engagement_name="Test", targets=["10.0.0.0/24"])
        state_manager.initialize_state(scope)
        
        # Add and compromise a host
        host_event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            data={"ip_address": "10.0.0.1"}
        )
        state_manager.update_from_event(host_event)
        
        host_id = list(state_manager.state.hosts.keys())[0]
        
        compromise_event = Event(
            event_type=EventType.HOST_COMPROMISED,
            source_agent_id="test_agent",
            data={
                "host_id": host_id,
                "session_type": "shell",
                "user": "root",
                "privileges": "root"
            }
        )
        state_manager.update_from_event(compromise_event)
        
        assert state_manager.state.metadata.total_compromised_hosts == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
