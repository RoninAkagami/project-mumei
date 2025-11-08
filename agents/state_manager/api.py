"""
FastAPI REST API for State Manager monitoring
"""

import os
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from agents.state_manager.state_manager import StateManager

# Initialize FastAPI app
app = FastAPI(title="Mumei State Manager API", version="1.0.0")

# Initialize State Manager
redis_host = os.getenv("REDIS_HOST", "localhost")
redis_port = int(os.getenv("REDIS_PORT", "6379"))
state_manager = StateManager(redis_host=redis_host, redis_port=redis_port)


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Mumei State Manager",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        state_manager.redis_client.ping()
        return {"status": "healthy", "redis": "connected"}
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(e)}
        )


@app.get("/state")
async def get_full_state():
    """Get the complete global state"""
    try:
        return state_manager.export_state()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/state/metadata")
async def get_metadata():
    """Get state metadata (summary statistics)"""
    try:
        return state_manager.global_state.metadata.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/state/scope")
async def get_scope():
    """Get engagement scope"""
    try:
        return state_manager.global_state.scope.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/state/hosts")
async def get_hosts(
    status: Optional[str] = Query(None, description="Filter by status"),
    os_type: Optional[str] = Query(None, description="Filter by OS type"),
):
    """Get hosts with optional filters"""
    try:
        filters = {}
        if status:
            filters["status"] = status
        if os_type:
            filters["os_type"] = os_type
        
        hosts = state_manager.get_hosts(filters)
        return {
            "count": len(hosts),
            "hosts": [h.model_dump() for h in hosts]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/state/hosts/{host_id}")
async def get_host(host_id: str):
    """Get a specific host by ID"""
    try:
        if host_id not in state_manager.global_state.hosts:
            raise HTTPException(status_code=404, detail="Host not found")
        
        host = state_manager.global_state.hosts[host_id]
        
        # Include related services
        services = [
            state_manager.global_state.services[sid].model_dump()
            for sid in host.services
            if sid in state_manager.global_state.services
        ]
        
        return {
            "host": host.model_dump(),
            "services": services
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/state/services")
async def get_services(
    service_name: Optional[str] = Query(None, description="Filter by service name"),
    port: Optional[int] = Query(None, description="Filter by port"),
    host_id: Optional[str] = Query(None, description="Filter by host ID"),
):
    """Get services with optional filters"""
    try:
        filters = {}
        if service_name:
            filters["service_name"] = service_name
        if port:
            filters["port"] = port
        if host_id:
            filters["host_id"] = host_id
        
        services = state_manager.get_services(filters)
        return {
            "count": len(services),
            "services": [s.model_dump() for s in services]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/state/vulnerabilities")
async def get_vulnerabilities(
    exploited: Optional[bool] = Query(None, description="Filter by exploited status"),
    cvss_score_gte: Optional[float] = Query(None, description="Minimum CVSS score"),
    exploit_available: Optional[bool] = Query(None, description="Filter by exploit availability"),
):
    """Get vulnerabilities with optional filters"""
    try:
        filters = {}
        if exploited is not None:
            filters["exploited"] = exploited
        if cvss_score_gte is not None:
            filters["cvss_score_gte"] = cvss_score_gte
        if exploit_available is not None:
            filters["exploit_available"] = exploit_available
        
        vulnerabilities = state_manager.get_vulnerabilities(filters)
        return {
            "count": len(vulnerabilities),
            "vulnerabilities": [v.model_dump() for v in vulnerabilities]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/state/credentials")
async def get_credentials(
    username: Optional[str] = Query(None, description="Filter by username"),
    source_host_id: Optional[str] = Query(None, description="Filter by source host"),
):
    """Get credentials with optional filters"""
    try:
        filters = {}
        if username:
            filters["username"] = username
        if source_host_id:
            filters["source_host_id"] = source_host_id
        
        credentials = state_manager.get_credentials(filters)
        return {
            "count": len(credentials),
            "credentials": [c.model_dump() for c in credentials]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/state/sessions")
async def get_sessions(
    active: Optional[bool] = Query(None, description="Filter by active status"),
    host_id: Optional[str] = Query(None, description="Filter by host ID"),
):
    """Get sessions with optional filters"""
    try:
        filters = {}
        if active is not None:
            filters["active"] = active
        if host_id:
            filters["host_id"] = host_id
        
        sessions = state_manager.get_sessions(filters)
        return {
            "count": len(sessions),
            "sessions": [s.model_dump() for s in sessions]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/state/evidence")
async def get_evidence(
    evidence_type: Optional[str] = Query(None, description="Filter by evidence type"),
    related_host_id: Optional[str] = Query(None, description="Filter by related host"),
):
    """Get evidence with optional filters"""
    try:
        evidence_list = state_manager.global_state.evidence
        
        if evidence_type:
            evidence_list = [e for e in evidence_list if e.evidence_type == evidence_type]
        if related_host_id:
            evidence_list = [e for e in evidence_list if e.related_host_id == related_host_id]
        
        return {
            "count": len(evidence_list),
            "evidence": [e.model_dump() for e in evidence_list]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/state/export")
async def export_state():
    """Export the complete state for reporting"""
    try:
        state = state_manager.export_state()
        return {
            "exported_at": state_manager.global_state.metadata.last_updated,
            "state": state
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Make state_manager accessible for the agent
def get_state_manager() -> StateManager:
    """Get the state manager instance"""
    return state_manager
