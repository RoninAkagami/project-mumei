"""
State Manager Agent - Main entry point
Listens to all events and updates global state
"""

import os
import sys
import logging
import threading
import signal
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mumei.shared.blackboard import Blackboard
from mumei.shared.models import Event, EventType
from mumei.shared.constants import CHANNELS
from agents.state_manager.state_manager import StateManager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class StateManagerAgent:
    """
    State Manager Agent that maintains global state and responds to queries
    """

    def __init__(self):
        """Initialize State Manager Agent"""
        redis_host = os.getenv("REDIS_HOST", "localhost")
        redis_port = int(os.getenv("REDIS_PORT", "6379"))

        # Initialize State Manager
        self.state_manager = StateManager(redis_host=redis_host, redis_port=redis_port)

        # Initialize Blackboard
        self.blackboard = Blackboard(host=redis_host, port=redis_port)

        self.running = False
        self._shutdown_event = threading.Event()

        logger.info("State Manager Agent initialized")

    def handle_event(self, event: Event) -> None:
        """
        Handle incoming events and update state.

        Args:
            event: Event to process
        """
        try:
            # Process finding events
            if event.event_type in [
                EventType.HOST_FOUND,
                EventType.SERVICE_DISCOVERED,
                EventType.VULNERABILITY_IDENTIFIED,
                EventType.CREDENTIAL_DISCOVERED,
                EventType.HOST_COMPROMISED,
                EventType.EVIDENCE_COLLECTED,
            ]:
                self.state_manager.process_event(event)

            # Handle state query requests
            elif event.event_type == EventType.STATE_QUERY_REQUEST:
                self.handle_state_query(event)

        except Exception as e:
            logger.error(f"Error handling event {event.event_id}: {e}", exc_info=True)

    def handle_state_query(self, event: Event) -> None:
        """
        Handle state query requests and publish responses.

        Args:
            event: State query request event
        """
        try:
            query_type = event.data.get("query_type")
            filters = event.data.get("filters", {})
            query_id = event.data.get("query_id")

            results = []

            if query_type == "hosts":
                hosts = self.state_manager.get_hosts(filters)
                results = [h.model_dump() for h in hosts]
            elif query_type == "services":
                services = self.state_manager.get_services(filters)
                results = [s.model_dump() for s in services]
            elif query_type == "vulnerabilities":
                vulnerabilities = self.state_manager.get_vulnerabilities(filters)
                results = [v.model_dump() for v in vulnerabilities]
            elif query_type == "credentials":
                credentials = self.state_manager.get_credentials(filters)
                results = [c.model_dump() for c in credentials]
            elif query_type == "sessions":
                sessions = self.state_manager.get_sessions(filters)
                results = [s.model_dump() for s in sessions]

            # Publish response
            response_event = Event(
                event_type=EventType.STATE_QUERY_RESPONSE,
                source_agent_id="state_manager",
                data={
                    "query_id": query_id,
                    "results": results,
                    "count": len(results),
                },
                correlation_id=query_id,
            )

            self.blackboard.publish(
                CHANNELS["STATE_QUERY_RESPONSE"],
                response_event
            )

            logger.debug(f"Responded to query {query_id} with {len(results)} results")

        except Exception as e:
            logger.error(f"Error handling state query: {e}", exc_info=True)

    def run(self) -> None:
        """Main agent loop - subscribe to all events"""
        self.running = True
        logger.info("State Manager Agent starting...")

        # Subscribe to all event channels
        channels = [
            CHANNELS["HOST_FOUND"],
            CHANNELS["SERVICE_DISCOVERED"],
            CHANNELS["VULNERABILITY_IDENTIFIED"],
            CHANNELS["CREDENTIAL_DISCOVERED"],
            CHANNELS["HOST_COMPROMISED"],
            CHANNELS["EVIDENCE_COLLECTED"],
            CHANNELS["STATE_QUERY_REQUEST"],
        ]

        logger.info(f"Subscribing to {len(channels)} event channels")

        try:
            self.blackboard.subscribe(channels, self.handle_event)
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
            self.shutdown()
        except Exception as e:
            logger.error(f"Error in main loop: {e}", exc_info=True)
            self.shutdown()

    def shutdown(self) -> None:
        """Gracefully shutdown the agent"""
        logger.info("Shutting down State Manager Agent")
        self.running = False
        self._shutdown_event.set()
        self.blackboard.close()


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}")
    sys.exit(0)


def main():
    """Main entry point"""
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create and run agent
    agent = StateManagerAgent()

    # Start FastAPI server in a separate thread
    import uvicorn
    from agents.state_manager.api import app

    def run_api():
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

    api_thread = threading.Thread(target=run_api, daemon=True)
    api_thread.start()
    logger.info("FastAPI server started on port 8000")

    # Run agent main loop
    agent.run()


if __name__ == "__main__":
    main()
