"""
Base Agent class that all specialized agents inherit from
"""

import os
import logging
import subprocess
import json
import threading
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime

from mumei.shared.blackboard import Blackboard
from mumei.shared.models import Event, EventType, Priority, StateQuery
from mumei.shared.constants import CHANNELS, TIMEOUTS
from mumei.shared.llm_client import LLMClient

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    Base class for all Mumei agents.
    Provides common functionality for event handling, state queries, and CLI execution.
    """

    def __init__(
        self,
        agent_id: str,
        agent_type: str,
        blackboard: Optional[Blackboard] = None,
        llm_client: Optional[LLMClient] = None,
    ):
        """
        Initialize base agent.

        Args:
            agent_id: Unique identifier for this agent instance
            agent_type: Type of agent (e.g., "surface_mapper")
            blackboard: Blackboard instance for communication
            llm_client: LLM client for decision-making
        """
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.running = False
        self._shutdown_event = threading.Event()

        # Initialize Blackboard
        if blackboard is None:
            redis_host = os.getenv("REDIS_HOST", "localhost")
            redis_port = int(os.getenv("REDIS_PORT", "6379"))
            redis_password = os.getenv("REDIS_PASSWORD")
            self.blackboard = Blackboard(
                host=redis_host, port=redis_port, password=redis_password
            )
        else:
            self.blackboard = blackboard

        # Initialize LLM client
        if llm_client is None:
            llm_provider = os.getenv("LLM_PROVIDER", "openai")
            llm_model = os.getenv("LLM_MODEL")
            self.llm = LLMClient(provider=llm_provider, model=llm_model)
        else:
            self.llm = llm_client

        # Configuration
        self.config = self._load_config()

        logger.info(f"Initialized agent: {self.agent_id} ({self.agent_type})")

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        return {
            "log_level": os.getenv("LOG_LEVEL", "INFO"),
            "timeout": int(os.getenv("AGENT_TIMEOUT", str(TIMEOUTS["TOOL_EXECUTION"]))),
            "max_retries": int(os.getenv("MAX_RETRIES", "3")),
            "rate_limit_delay": float(os.getenv("RATE_LIMIT_DELAY", "1.0")),
            "stealth_mode": os.getenv("STEALTH_MODE", "false").lower() == "true",
        }

    def publish_event(
        self,
        event_type: EventType,
        data: Dict[str, Any],
        priority: Priority = Priority.INFO,
        correlation_id: Optional[str] = None,
    ) -> Event:
        """
        Publish an event to the Blackboard.

        Args:
            event_type: Type of event
            data: Event data payload
            priority: Event priority level
            correlation_id: Optional correlation ID for request/response

        Returns:
            The published Event object
        """
        event = Event(
            event_type=event_type,
            source_agent_id=self.agent_id,
            priority=priority,
            data=data,
            correlation_id=correlation_id,
        )

        channel = CHANNELS.get(event_type.value.upper())
        if not channel:
            channel = f"events:{event_type.value}"

        self.blackboard.publish(channel, event)
        self.log("DEBUG", f"Published {event_type.value} event: {event.event_id}")

        return event

    def subscribe_to_events(
        self, event_types: List[EventType], callback: Callable[[Event], None]
    ) -> None:
        """
        Subscribe to event types and process with callback.

        Args:
            event_types: List of event types to subscribe to
            callback: Function to call when event is received
        """
        channels = []
        for event_type in event_types:
            channel = CHANNELS.get(event_type.value.upper())
            if not channel:
                channel = f"events:{event_type.value}"
            channels.append(channel)

        self.log("INFO", f"Subscribing to: {', '.join([et.value for et in event_types])}")

        # Run subscription in a separate thread
        def subscribe_thread():
            self.blackboard.subscribe(channels, callback)

        thread = threading.Thread(target=subscribe_thread, daemon=True)
        thread.start()

    def query_state(
        self, query_type: str, filters: Optional[Dict[str, Any]] = None, timeout: float = 5.0
    ) -> Dict[str, Any]:
        """
        Query the State Manager for information.

        Args:
            query_type: Type of query (hosts, services, vulnerabilities, etc.)
            filters: Optional filters for the query
            timeout: Timeout for waiting for response

        Returns:
            Query results as dict
        """
        query = StateQuery(query_type=query_type, filters=filters or {})

        # Publish query request
        self.publish_event(
            EventType.STATE_QUERY_REQUEST,
            data=query.model_dump(),
            correlation_id=query.query_id,
        )

        # Wait for response (simplified - in production, use proper async handling)
        self.log("DEBUG", f"Waiting for state query response: {query.query_id}")

        # For now, return empty result (will be implemented with proper async handling)
        return {"results": [], "count": 0}

    def execute_cli(
        self,
        command: str,
        timeout: Optional[int] = None,
        capture_output: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute a CLI command and return the result.

        Args:
            command: Command to execute
            timeout: Timeout in seconds (uses agent default if not specified)
            capture_output: Whether to capture stdout/stderr

        Returns:
            Dict with returncode, stdout, stderr, and execution time
        """
        if timeout is None:
            timeout = self.config["timeout"]

        self.log("INFO", f"Executing command: {command}")
        start_time = datetime.utcnow()

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
            )

            execution_time = (datetime.utcnow() - start_time).total_seconds()

            output = {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout if capture_output else None,
                "stderr": result.stderr if capture_output else None,
                "execution_time": execution_time,
                "success": result.returncode == 0,
            }

            if result.returncode == 0:
                self.log("DEBUG", f"Command succeeded in {execution_time:.2f}s")
            else:
                self.log("WARN", f"Command failed with code {result.returncode}")

            return output

        except subprocess.TimeoutExpired:
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            self.log("ERROR", f"Command timed out after {timeout}s")
            return {
                "command": command,
                "returncode": -1,
                "stdout": None,
                "stderr": f"Command timed out after {timeout}s",
                "execution_time": execution_time,
                "success": False,
                "timeout": True,
            }

        except Exception as e:
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            self.log("ERROR", f"Command execution failed: {e}")
            return {
                "command": command,
                "returncode": -1,
                "stdout": None,
                "stderr": str(e),
                "execution_time": execution_time,
                "success": False,
                "error": str(e),
            }

    def log(self, level: str, message: str, **kwargs) -> None:
        """
        Log a message with agent context.

        Args:
            level: Log level (DEBUG, INFO, WARN, ERROR, CRITICAL)
            message: Log message
            **kwargs: Additional context to include
        """
        log_data = {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "timestamp": datetime.utcnow().isoformat(),
            "message": message,
            **kwargs,
        }

        log_func = getattr(logger, level.lower(), logger.info)
        log_func(json.dumps(log_data))

    def send_heartbeat(self) -> None:
        """Send a heartbeat event to indicate agent is alive"""
        self.publish_event(
            EventType.AGENT_HEARTBEAT,
            data={
                "agent_id": self.agent_id,
                "agent_type": self.agent_type,
                "status": "running" if self.running else "stopped",
            },
            priority=Priority.DEBUG,
        )

    @abstractmethod
    def run(self) -> None:
        """
        Main agent loop. Must be implemented by subclasses.
        """
        pass

    def shutdown(self) -> None:
        """Gracefully shutdown the agent"""
        self.log("INFO", "Shutting down agent")
        self.running = False
        self._shutdown_event.set()
        self.blackboard.close()
