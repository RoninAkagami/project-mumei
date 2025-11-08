"""
Constants and configuration values for Project Mumei
"""

# Event channel names for Redis Pub/Sub
CHANNELS = {
    "SCAN_INITIATED": "events:scan_initiated",
    "SCAN_COMPLETED": "events:scan_completed",
    "HOST_FOUND": "events:host_found",
    "SERVICE_DISCOVERED": "events:service_discovered",
    "VULNERABILITY_IDENTIFIED": "events:vulnerability_identified",
    "HOST_COMPROMISED": "events:host_compromised",
    "CREDENTIAL_DISCOVERED": "events:credential_discovered",
    "PRIVILEGE_ESCALATED": "events:privilege_escalated",
    "EXPLOITATION_FAILED": "events:exploitation_failed",
    "OPERATIONAL_ALERT": "events:operational_alert",
    "STATE_QUERY_REQUEST": "events:state_query_request",
    "STATE_QUERY_RESPONSE": "events:state_query_response",
    "AGENT_HEARTBEAT": "events:agent_heartbeat",
    "EVIDENCE_COLLECTED": "events:evidence_collected",
}

# Redis keys for Global State storage
STATE_KEYS = {
    "GLOBAL_STATE": "state:global",
    "HOSTS": "state:hosts",
    "SERVICES": "state:services",
    "VULNERABILITIES": "state:vulnerabilities",
    "CREDENTIALS": "state:credentials",
    "SESSIONS": "state:sessions",
    "EVIDENCE": "state:evidence",
    "METADATA": "state:metadata",
}

# Agent types
AGENT_TYPES = {
    "TACTICAL_COORDINATOR": "tactical_coordinator",
    "SURFACE_MAPPER": "surface_mapper",
    "SERVICE_PROFILER": "service_profiler",
    "EXPLOITATION_ENGINEER": "exploitation_engineer",
    "LATERAL_MOVEMENT": "lateral_movement",
    "STATE_MANAGER": "state_manager",
}

# Timeouts (in seconds)
TIMEOUTS = {
    "EVENT_DELIVERY": 0.1,  # 100ms
    "STATE_UPDATE": 0.5,  # 500ms
    "STATE_QUERY": 0.2,  # 200ms
    "TOOL_EXECUTION": 300,  # 5 minutes
    "AGENT_HEARTBEAT": 30,  # 30 seconds
}

# Retry configuration
RETRY_CONFIG = {
    "MAX_RETRIES": 3,
    "INITIAL_BACKOFF": 1,  # seconds
    "MAX_BACKOFF": 60,  # seconds
    "BACKOFF_MULTIPLIER": 2,
}

# Host status values
HOST_STATUS = {
    "DISCOVERED": "discovered",
    "SCANNED": "scanned",
    "PROFILED": "profiled",
    "COMPROMISED": "compromised",
}

# Service protocols
PROTOCOLS = {
    "TCP": "tcp",
    "UDP": "udp",
}

# Common ports by service
COMMON_PORTS = {
    "HTTP": [80, 8080, 8000, 8888],
    "HTTPS": [443, 8443],
    "SSH": [22],
    "FTP": [21],
    "TELNET": [23],
    "SMTP": [25, 587],
    "DNS": [53],
    "SMB": [139, 445],
    "RDP": [3389],
    "MYSQL": [3306],
    "POSTGRESQL": [5432],
    "MONGODB": [27017],
    "REDIS": [6379],
}
