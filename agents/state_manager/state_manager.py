"""
State Manager Agent - Maintains the Global State of the penetration test
"""

import os
import json
import logging
import redis
from typing import Dict, Any, List, Optional
from datetime import datetime

from mumei.shared.models import (
    GlobalState, Scope, Host, Service, Vulnerability, 
    Credential, Session, Evidence, StateMetadata, Event, EventType
)
from mumei.shared.constants import STATE_KEYS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StateManager:
    """
    Manages the Global State of the penetration test.
    Listens to events and updates state accordingly.
    Provides query API for agents to retrieve context.
    """

    def __init__(self, redis_host: str = "localhost", redis_port: int = 6379):
        """
        Initialize State Manager.

        Args:
            redis_host: Redis server hostname
            redis_port: Redis server port
        """
        self.redis_client = redis.Redis(
            host=redis_host,
            port=redis_port,
            decode_responses=True,
        )
        
        # Test connection
        self.redis_client.ping()
        logger.info(f"Connected to Redis at {redis_host}:{redis_port}")

        # Initialize or load global state
        self.global_state: Optional[GlobalState] = None
        self._load_or_initialize_state()

    def _load_or_initialize_state(self) -> None:
        """Load existing state from Redis or initialize new state"""
        try:
            state_json = self.redis_client.get(STATE_KEYS["GLOBAL_STATE"])
            if state_json:
                state_dict = json.loads(state_json)
                self.global_state = GlobalState(**state_dict)
                logger.info("Loaded existing global state from Redis")
            else:
                # Initialize with empty scope
                self.global_state = GlobalState(
                    scope=Scope(
                        engagement_name="New Engagement",
                        targets=[],
                        excluded=[],
                    )
                )
                self._save_state()
                logger.info("Initialized new global state")
        except Exception as e:
            logger.error(f"Error loading state: {e}")
            raise

    def _save_state(self) -> None:
        """Save global state to Redis"""
        try:
            state_json = self.global_state.model_dump_json()
            self.redis_client.set(STATE_KEYS["GLOBAL_STATE"], state_json)
            logger.debug("Saved global state to Redis")
        except Exception as e:
            logger.error(f"Error saving state: {e}")
            raise

    def update_scope(self, scope: Scope) -> None:
        """
        Update the engagement scope.

        Args:
            scope: New scope configuration
        """
        self.global_state.scope = scope
        self._save_state()
        logger.info(f"Updated scope: {scope.engagement_name}")

    def add_host(self, host: Host) -> None:
        """
        Add or update a host in the global state.

        Args:
            host: Host object to add
        """
        self.global_state.hosts[host.host_id] = host
        self.global_state.metadata.total_hosts = len(self.global_state.hosts)
        self.global_state.metadata.last_updated = datetime.utcnow().isoformat()
        self._save_state()
        logger.info(f"Added host: {host.ip_address} ({host.host_id})")

    def add_service(self, service: Service) -> None:
        """
        Add or update a service in the global state.

        Args:
            service: Service object to add
        """
        self.global_state.services[service.service_id] = service
        
        # Link service to host
        if service.host_id in self.global_state.hosts:
            host = self.global_state.hosts[service.host_id]
            if service.service_id not in host.services:
                host.services.append(service.service_id)
        
        self.global_state.metadata.total_services = len(self.global_state.services)
        self.global_state.metadata.last_updated = datetime.utcnow().isoformat()
        self._save_state()
        logger.info(f"Added service: {service.service_name}:{service.port} on {service.host_id}")

    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """
        Add or update a vulnerability in the global state.

        Args:
            vulnerability: Vulnerability object to add
        """
        self.global_state.vulnerabilities[vulnerability.vulnerability_id] = vulnerability
        
        # Link vulnerability to service
        if vulnerability.service_id in self.global_state.services:
            service = self.global_state.services[vulnerability.service_id]
            if vulnerability.vulnerability_id not in service.vulnerabilities:
                service.vulnerabilities.append(vulnerability.vulnerability_id)
        
        self.global_state.metadata.total_vulnerabilities = len(self.global_state.vulnerabilities)
        self.global_state.metadata.last_updated = datetime.utcnow().isoformat()
        self._save_state()
        logger.info(f"Added vulnerability: {vulnerability.title} ({vulnerability.vulnerability_id})")

    def add_credential(self, credential: Credential) -> None:
        """
        Add a credential to the global state.

        Args:
            credential: Credential object to add
        """
        self.global_state.credentials.append(credential)
        self.global_state.metadata.last_updated = datetime.utcnow().isoformat()
        self._save_state()
        logger.info(f"Added credential: {credential.username} from {credential.source_host_id}")

    def add_session(self, session: Session) -> None:
        """
        Add a session to the global state.

        Args:
            session: Session object to add
        """
        self.global_state.sessions.append(session)
        
        # Update host status to compromised
        if session.host_id in self.global_state.hosts:
            host = self.global_state.hosts[session.host_id]
            host.status = "compromised"
            self.global_state.metadata.total_compromised_hosts = sum(
                1 for h in self.global_state.hosts.values() if h.status == "compromised"
            )
        
        self.global_state.metadata.last_updated = datetime.utcnow().isoformat()
        self._save_state()
        logger.info(f"Added session: {session.session_type} on {session.host_id}")

    def add_evidence(self, evidence: Evidence) -> None:
        """
        Add evidence to the global state.

        Args:
            evidence: Evidence object to add
        """
        self.global_state.evidence.append(evidence)
        self.global_state.metadata.last_updated = datetime.utcnow().isoformat()
        self._save_state()
        logger.info(f"Added evidence: {evidence.evidence_type} - {evidence.description}")

    def get_hosts(self, filters: Optional[Dict[str, Any]] = None) -> List[Host]:
        """
        Get hosts matching filters.

        Args:
            filters: Optional filters (e.g., {"status": "compromised"})

        Returns:
            List of matching hosts
        """
        hosts = list(self.global_state.hosts.values())
        
        if filters:
            for key, value in filters.items():
                hosts = [h for h in hosts if getattr(h, key, None) == value]
        
        return hosts

    def get_services(self, filters: Optional[Dict[str, Any]] = None) -> List[Service]:
        """
        Get services matching filters.

        Args:
            filters: Optional filters (e.g., {"service_name": "http"})

        Returns:
            List of matching services
        """
        services = list(self.global_state.services.values())
        
        if filters:
            for key, value in filters.items():
                services = [s for s in services if getattr(s, key, None) == value]
        
        return services

    def get_vulnerabilities(self, filters: Optional[Dict[str, Any]] = None) -> List[Vulnerability]:
        """
        Get vulnerabilities matching filters.

        Args:
            filters: Optional filters (e.g., {"exploited": False})

        Returns:
            List of matching vulnerabilities
        """
        vulnerabilities = list(self.global_state.vulnerabilities.values())
        
        if filters:
            for key, value in filters.items():
                if key == "cvss_score_gte":
                    vulnerabilities = [
                        v for v in vulnerabilities 
                        if v.cvss_score and v.cvss_score >= value
                    ]
                else:
                    vulnerabilities = [
                        v for v in vulnerabilities 
                        if getattr(v, key, None) == value
                    ]
        
        return vulnerabilities

    def get_credentials(self, filters: Optional[Dict[str, Any]] = None) -> List[Credential]:
        """
        Get credentials matching filters.

        Args:
            filters: Optional filters

        Returns:
            List of matching credentials
        """
        credentials = self.global_state.credentials
        
        if filters:
            for key, value in filters.items():
                credentials = [c for c in credentials if getattr(c, key, None) == value]
        
        return credentials

    def get_sessions(self, filters: Optional[Dict[str, Any]] = None) -> List[Session]:
        """
        Get sessions matching filters.

        Args:
            filters: Optional filters (e.g., {"active": True})

        Returns:
            List of matching sessions
        """
        sessions = self.global_state.sessions
        
        if filters:
            for key, value in filters.items():
                sessions = [s for s in sessions if getattr(s, key, None) == value]
        
        return sessions

    def export_state(self) -> Dict[str, Any]:
        """
        Export the complete global state.

        Returns:
            Global state as dictionary
        """
        return self.global_state.model_dump()

    def process_event(self, event: Event) -> None:
        """
        Process an event and update state accordingly.

        Args:
            event: Event to process
        """
        try:
            if event.event_type == EventType.HOST_FOUND:
                host = Host(**event.data)
                self.add_host(host)
            
            elif event.event_type == EventType.SERVICE_DISCOVERED:
                service = Service(**event.data)
                self.add_service(service)
            
            elif event.event_type == EventType.VULNERABILITY_IDENTIFIED:
                vulnerability = Vulnerability(**event.data)
                self.add_vulnerability(vulnerability)
            
            elif event.event_type == EventType.CREDENTIAL_DISCOVERED:
                credential = Credential(**event.data)
                self.add_credential(credential)
            
            elif event.event_type == EventType.HOST_COMPROMISED:
                session = Session(**event.data)
                self.add_session(session)
            
            elif event.event_type == EventType.EVIDENCE_COLLECTED:
                evidence = Evidence(**event.data)
                self.add_evidence(evidence)
            
            logger.debug(f"Processed {event.event_type} event from {event.source_agent_id}")
        
        except Exception as e:
            logger.error(f"Error processing event {event.event_id}: {e}", exc_info=True)
