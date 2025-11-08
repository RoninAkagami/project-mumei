"""
Unit tests for data models
"""

import pytest
from datetime import datetime
from pydantic import ValidationError

from mumei.shared.models import (
    Event, EventType, Priority,
    Host, Service, Vulnerability, Credential, Session, Evidence,
    GlobalState, Scope, StateMetadata, StateQuery, StateQueryResult
)


class TestEvent:
    """Test Event model"""

    def test_event_creation(self):
        """Test creating a valid event"""
        event = Event(
            event_type=EventType.HOST_FOUND,
            source_agent_id="test_agent",
            priority=Priority.INFO,
            data={"ip_address": "192.168.1.10"}
        )
        
        assert event.event_type == EventType.HOST_FOUND
        assert event.source_agent_id == "test_agent"
        assert event.priority == Priority.INFO
        assert event.data["ip_address"] == "192.168.1.10"
        assert event.event_id is not None
        assert event.timestamp is not None

    def test_event_with_correlation_id(self):
        """Test event with correlation ID"""
        correlation_id = "test-correlation-123"
        event = Event(
            event_type=EventType.STATE_QUERY_REQUEST,
            source_agent_id="test_agent",
            data={},
            correlation_id=correlation_id
        )
        
        assert event.correlation_id == correlation_id

    def test_event_serialization(self):
        """Test event JSON serialization"""
        event = Event(
            event_type=EventType.SERVICE_DISCOVERED,
            source_agent_id="test_agent",
            data={"port": 80, "service": "http"}
        )
        
        json_str = event.model_dump_json()
        assert "event_type" in json_str
        assert "service_discovered" in json_str
        assert "test_agent" in json_str

    def test_event_deserialization(self):
        """Test event JSON deserialization"""
        event_dict = {
            "event_id": "test-123",
            "event_type": "host_found",
            "timestamp": datetime.utcnow().isoformat(),
            "source_agent_id": "test_agent",
            "priority": "INFO",
            "data": {"ip": "10.0.0.1"}
        }
        
        event = Event(**event_dict)
        assert event.event_id == "test-123"
        assert event.event_type == EventType.HOST_FOUND


class TestHost:
    """Test Host model"""

    def test_host_creation(self):
        """Test creating a valid host"""
        host = Host(
            ip_address="192.168.1.10",
            hostname="testhost.local",
            os_type="Linux"
        )
        
        assert host.ip_address == "192.168.1.10"
        assert host.hostname == "testhost.local"
        assert host.os_type == "Linux"
        assert host.status == "discovered"
        assert host.host_id is not None

    def test_host_with_services(self):
        """Test host with linked services"""
        host = Host(
            ip_address="192.168.1.10",
            services=["service-1", "service-2"]
        )
        
        assert len(host.services) == 2
        assert "service-1" in host.services

    def test_host_serialization(self):
        """Test host serialization"""
        host = Host(ip_address="10.0.0.1")
        data = host.model_dump()
        
        assert data["ip_address"] == "10.0.0.1"
        assert "host_id" in data
        assert "discovered_at" in data


class TestService:
    """Test Service model"""

    def test_service_creation(self):
        """Test creating a valid service"""
        service = Service(
            host_id="host-123",
            port=443,
            protocol="tcp",
            service_name="https",
            banner="Apache/2.4.49"
        )
        
        assert service.host_id == "host-123"
        assert service.port == 443
        assert service.protocol == "tcp"
        assert service.service_name == "https"
        assert service.banner == "Apache/2.4.49"

    def test_service_with_vulnerabilities(self):
        """Test service with vulnerabilities"""
        service = Service(
            host_id="host-123",
            port=80,
            protocol="tcp",
            service_name="http",
            vulnerabilities=["vuln-1", "vuln-2"]
        )
        
        assert len(service.vulnerabilities) == 2

    def test_service_validation(self):
        """Test service validation"""
        with pytest.raises(ValidationError):
            Service(
                host_id="host-123",
                port="invalid",  # Should be int
                protocol="tcp",
                service_name="http"
            )


class TestVulnerability:
    """Test Vulnerability model"""

    def test_vulnerability_creation(self):
        """Test creating a vulnerability"""
        vuln = Vulnerability(
            service_id="service-123",
            cve_id="CVE-2021-41773",
            cvss_score=7.5,
            title="Apache Path Traversal",
            description="Path traversal vulnerability",
            exploit_available=True
        )
        
        assert vuln.service_id == "service-123"
        assert vuln.cve_id == "CVE-2021-41773"
        assert vuln.cvss_score == 7.5
        assert vuln.exploit_available is True
        assert vuln.exploited is False

    def test_vulnerability_without_cve(self):
        """Test vulnerability without CVE"""
        vuln = Vulnerability(
            service_id="service-123",
            title="Custom Vulnerability",
            description="Custom finding"
        )
        
        assert vuln.cve_id is None
        assert vuln.cvss_score is None


class TestCredential:
    """Test Credential model"""

    def test_credential_with_password(self):
        """Test credential with plaintext password"""
        cred = Credential(
            username="admin",
            password="password123",
            source_host_id="host-123"
        )
        
        assert cred.username == "admin"
        assert cred.password == "password123"
        assert cred.hash is None

    def test_credential_with_hash(self):
        """Test credential with hash"""
        cred = Credential(
            username="root",
            hash="$6$salt$hash...",
            hash_type="SHA-512",
            source_host_id="host-123"
        )
        
        assert cred.username == "root"
        assert cred.hash is not None
        assert cred.hash_type == "SHA-512"
        assert cred.password is None


class TestSession:
    """Test Session model"""

    def test_session_creation(self):
        """Test creating a session"""
        session = Session(
            host_id="host-123",
            session_type="meterpreter",
            user="www-data",
            privileges="user"
        )
        
        assert session.host_id == "host-123"
        assert session.session_type == "meterpreter"
        assert session.user == "www-data"
        assert session.privileges == "user"
        assert session.active is True


class TestEvidence:
    """Test Evidence model"""

    def test_evidence_creation(self):
        """Test creating evidence"""
        evidence = Evidence(
            evidence_type="screenshot",
            description="Proof of exploitation",
            file_path="/evidence/screenshot.png",
            related_host_id="host-123"
        )
        
        assert evidence.evidence_type == "screenshot"
        assert evidence.description == "Proof of exploitation"
        assert evidence.file_path == "/evidence/screenshot.png"


class TestGlobalState:
    """Test GlobalState model"""

    def test_global_state_creation(self):
        """Test creating global state"""
        scope = Scope(
            engagement_name="Test Engagement",
            targets=["192.168.1.0/24"],
            excluded=["192.168.1.1"]
        )
        
        state = GlobalState(scope=scope)
        
        assert state.scope.engagement_name == "Test Engagement"
        assert len(state.hosts) == 0
        assert len(state.services) == 0
        assert state.metadata is not None

    def test_global_state_with_data(self):
        """Test global state with hosts and services"""
        scope = Scope(
            engagement_name="Test",
            targets=["10.0.0.0/24"]
        )
        
        host = Host(ip_address="10.0.0.1")
        service = Service(
            host_id=host.host_id,
            port=80,
            protocol="tcp",
            service_name="http"
        )
        
        state = GlobalState(
            scope=scope,
            hosts={host.host_id: host},
            services={service.service_id: service}
        )
        
        assert len(state.hosts) == 1
        assert len(state.services) == 1


class TestStateQuery:
    """Test StateQuery model"""

    def test_state_query_creation(self):
        """Test creating a state query"""
        query = StateQuery(
            query_type="hosts",
            filters={"status": "compromised"}
        )
        
        assert query.query_type == "hosts"
        assert query.filters["status"] == "compromised"
        assert query.query_id is not None

    def test_state_query_with_limit(self):
        """Test query with limit"""
        query = StateQuery(
            query_type="vulnerabilities",
            filters={"cvss_score": {"$gte": 7.0}},
            limit=10
        )
        
        assert query.limit == 10


class TestStateQueryResult:
    """Test StateQueryResult model"""

    def test_query_result_creation(self):
        """Test creating query result"""
        result = StateQueryResult(
            query_id="query-123",
            results=[{"host_id": "host-1"}, {"host_id": "host-2"}],
            count=2
        )
        
        assert result.query_id == "query-123"
        assert result.count == 2
        assert len(result.results) == 2


class TestModelValidation:
    """Test model validation and edge cases"""

    def test_invalid_event_type(self):
        """Test invalid event type"""
        with pytest.raises(ValidationError):
            Event(
                event_type="invalid_type",
                source_agent_id="test",
                data={}
            )

    def test_invalid_priority(self):
        """Test invalid priority"""
        with pytest.raises(ValidationError):
            Event(
                event_type=EventType.HOST_FOUND,
                source_agent_id="test",
                priority="INVALID",
                data={}
            )

    def test_missing_required_fields(self):
        """Test missing required fields"""
        with pytest.raises(ValidationError):
            Host()  # Missing ip_address

    def test_invalid_port_number(self):
        """Test invalid port number"""
        with pytest.raises(ValidationError):
            Service(
                host_id="host-123",
                port=99999,  # Invalid port
                protocol="tcp",
                service_name="test"
            )


class TestModelSerialization:
    """Test model serialization and deserialization"""

    def test_event_round_trip(self):
        """Test event serialization round trip"""
        original = Event(
            event_type=EventType.VULNERABILITY_IDENTIFIED,
            source_agent_id="test_agent",
            data={"cve": "CVE-2021-1234"}
        )
        
        # Serialize
        json_str = original.model_dump_json()
        
        # Deserialize
        import json
        data = json.loads(json_str)
        restored = Event(**data)
        
        assert restored.event_type == original.event_type
        assert restored.source_agent_id == original.source_agent_id
        assert restored.data == original.data

    def test_host_round_trip(self):
        """Test host serialization round trip"""
        original = Host(
            ip_address="192.168.1.10",
            hostname="test.local",
            os_type="Linux"
        )
        
        # Serialize
        data = original.model_dump()
        
        # Deserialize
        restored = Host(**data)
        
        assert restored.ip_address == original.ip_address
        assert restored.hostname == original.hostname
        assert restored.host_id == original.host_id

    def test_global_state_serialization(self):
        """Test global state serialization"""
        scope = Scope(
            engagement_name="Test",
            targets=["10.0.0.0/24"]
        )
        
        state = GlobalState(scope=scope)
        
        # Serialize
        json_str = state.model_dump_json()
        
        # Should be valid JSON
        import json
        data = json.loads(json_str)
        
        assert "scope" in data
        assert "hosts" in data
        assert "services" in data
        assert "metadata" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
