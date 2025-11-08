"""
Data models for Project Mumei
All models use Pydantic for validation and serialization
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
from pydantic import BaseModel, Field
import uuid


class EventType(str, Enum):
    """Event types for the Blackboard"""
    SCAN_INITIATED = "scan_initiated"
    SCAN_COMPLETED = "scan_completed"
    HOST_FOUND = "host_found"
    SERVICE_DISCOVERED = "service_discovered"
    VULNERABILITY_IDENTIFIED = "vulnerability_identified"
    HOST_COMPROMISED = "host_compromised"
    CREDENTIAL_DISCOVERED = "credential_discovered"
    PRIVILEGE_ESCALATED = "privilege_escalated"
    EXPLOITATION_FAILED = "exploitation_failed"
    OPERATIONAL_ALERT = "operational_alert"
    STATE_QUERY_REQUEST = "state_query_request"
    STATE_QUERY_RESPONSE = "state_query_response"
    AGENT_HEARTBEAT = "agent_heartbeat"
    EVIDENCE_COLLECTED = "evidence_collected"


class Priority(str, Enum):
    """Event priority levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    CRITICAL = "CRITICAL"


class Event(BaseModel):
    """Base event structure for all Blackboard communications"""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    source_agent_id: str
    priority: Priority = Priority.INFO
    data: Dict[str, Any]
    correlation_id: Optional[str] = None

    class Config:
        use_enum_values = True


class Scope(BaseModel):
    """Penetration test scope definition"""
    engagement_name: str
    targets: List[str]
    excluded: List[str] = []
    rules_of_engagement: Dict[str, Any] = {}
    objectives: List[str] = []
    start_time: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: Optional[str] = None


class Host(BaseModel):
    """Discovered host information"""
    host_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    status: str = "discovered"  # discovered, scanned, compromised
    discovered_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    services: List[str] = []  # Service IDs
    metadata: Dict[str, Any] = {}


class Service(BaseModel):
    """Discovered service information"""
    service_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    host_id: str
    port: int
    protocol: str  # tcp, udp
    service_name: str
    banner: Optional[str] = None
    version: Optional[str] = None
    vulnerabilities: List[str] = []  # Vulnerability IDs
    discovered_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = {}


class Vulnerability(BaseModel):
    """Identified vulnerability information"""
    vulnerability_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    title: str
    description: str
    exploit_available: bool = False
    exploited: bool = False
    discovered_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = {}


class Credential(BaseModel):
    """Discovered credential information"""
    credential_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password: Optional[str] = None
    hash: Optional[str] = None
    hash_type: Optional[str] = None
    source_host_id: str
    discovered_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = {}


class Session(BaseModel):
    """Active session on compromised host"""
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    host_id: str
    session_type: str  # shell, meterpreter, ssh, etc.
    user: str
    privileges: str  # user, root, administrator, etc.
    established_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    active: bool = True
    metadata: Dict[str, Any] = {}


class Evidence(BaseModel):
    """Collected evidence"""
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_type: str  # screenshot, file, log, command_output
    description: str
    file_path: Optional[str] = None
    content: Optional[str] = None
    related_host_id: Optional[str] = None
    related_service_id: Optional[str] = None
    related_vulnerability_id: Optional[str] = None
    collected_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = {}


class StateMetadata(BaseModel):
    """Metadata about the Global State"""
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    last_updated: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    total_hosts: int = 0
    total_services: int = 0
    total_vulnerabilities: int = 0
    total_compromised_hosts: int = 0


class GlobalState(BaseModel):
    """Complete state of the penetration test"""
    scope: Scope
    hosts: Dict[str, Host] = {}
    services: Dict[str, Service] = {}
    vulnerabilities: Dict[str, Vulnerability] = {}
    credentials: List[Credential] = []
    sessions: List[Session] = []
    evidence: List[Evidence] = []
    metadata: StateMetadata = Field(default_factory=StateMetadata)


class StateQuery(BaseModel):
    """Query structure for State Manager requests"""
    query_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_type: str  # hosts, services, vulnerabilities, credentials, sessions
    filters: Dict[str, Any] = {}
    limit: Optional[int] = None


class StateQueryResult(BaseModel):
    """Result of a state query"""
    query_id: str
    results: List[Dict[str, Any]]
    count: int
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
