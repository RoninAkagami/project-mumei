"""
Tactical Coordinator Agent - Orchestrates the penetration test
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mumei.shared.base_agent import BaseAgent
from mumei.shared.models import Event, EventType, Priority, Scope
from mumei.shared.prompts import get_agent_prompt

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TacticalCoordinator(BaseAgent):
    """
    Tactical Coordinator orchestrates the penetration test.
    Manages scope, monitors agent health, and makes high-level decisions.
    """

    def __init__(self, agent_id: str = "tactical_coordinator_01"):
        """Initialize Tactical Coordinator"""
        super().__init__(agent_id=agent_id, agent_type="tactical_coordinator")

        self.scope: Scope = None
        self.agent_heartbeats: Dict[str, datetime] = {}
        self.engagement_started = False
        self.system_prompt = get_agent_prompt("tactical_coordinator")

        logger.info(f"Tactical Coordinator {agent_id} initialized")

    def load_scope(self, scope_file: str = "config/scope.json") -> Scope:
        """
        Load scope configuration from file.

        Args:
            scope_file: Path to scope configuration file

        Returns:
            Scope object
        """
        try:
            with open(scope_file, 'r') as f:
                scope_data = json.load(f)
            
            self.scope = Scope(**scope_data)
            self.log("INFO", f"Loaded scope: {self.scope.engagement_name}")
            self.log("INFO", f"Targets: {', '.join(self.scope.targets)}")
            
            return self.scope

        except FileNotFoundError:
            self.log("ERROR", f"Scope file not found: {scope_file}")
            raise
        except Exception as e:
            self.log("ERROR", f"Error loading scope: {e}")
            raise

    def validate_scope(self) -> bool:
        """
        Validate that scope is properly configured.

        Returns:
            True if scope is valid
        """
        if not self.scope:
            self.log("ERROR", "No scope loaded")
            return False

        if not self.scope.targets:
            self.log("ERROR", "No targets defined in scope")
            return False

        self.log("INFO", "Scope validation passed")
        return True

    def start_engagement(self) -> None:
        """Start the penetration test engagement"""
        if not self.validate_scope():
            raise ValueError("Invalid scope configuration")

        self.log("INFO", f"Starting engagement: {self.scope.engagement_name}")

        # Publish ScanInitiated event
        self.publish_event(
            EventType.SCAN_INITIATED,
            data={
                "engagement_name": self.scope.engagement_name,
                "targets": self.scope.targets,
                "excluded": self.scope.excluded,
                "rules_of_engagement": self.scope.rules_of_engagement,
                "objectives": self.scope.objectives,
            },
            priority=Priority.CRITICAL,
        )

        self.engagement_started = True
        self.log("INFO", "Engagement started - ScanInitiated event published")

    def handle_event(self, event: Event) -> None:
        """
        Handle incoming events for monitoring.

        Args:
            event: Event to process
        """
        try:
            # Track agent heartbeats
            if event.event_type == EventType.AGENT_HEARTBEAT:
                agent_id = event.data.get("agent_id")
                self.agent_heartbeats[agent_id] = datetime.utcnow()
                self.log("DEBUG", f"Heartbeat from {agent_id}")

            # Monitor for operational issues
            elif event.event_type == EventType.EXPLOITATION_FAILED:
                self.handle_exploitation_failure(event)

            # Log significant events
            elif event.priority == Priority.CRITICAL:
                self.log("INFO", f"Critical event: {event.event_type} from {event.source_agent_id}")

        except Exception as e:
            self.log("ERROR", f"Error handling event: {e}", exc_info=True)

    def handle_exploitation_failure(self, event: Event) -> None:
        """
        Handle exploitation failures and detect patterns.

        Args:
            event: Exploitation failed event
        """
        target = event.data.get("target")
        reason = event.data.get("reason", "Unknown")

        self.log("WARN", f"Exploitation failed on {target}: {reason}")

        # Check for WAF/IDS patterns
        waf_indicators = ["blocked", "forbidden", "waf", "firewall", "rate limit"]
        if any(indicator in reason.lower() for indicator in waf_indicators):
            self.log("WARN", f"Possible WAF/IDS detected on {target}")
            self.publish_event(
                EventType.OPERATIONAL_ALERT,
                data={
                    "alert_type": "waf_detected",
                    "target": target,
                    "reason": reason,
                    "recommendation": "Enable stealth mode or slow down operations",
                },
                priority=Priority.WARN,
            )

    def check_agent_health(self) -> None:
        """Check for inactive agents"""
        current_time = datetime.utcnow()
        timeout = timedelta(seconds=60)  # 60 second timeout

        for agent_id, last_heartbeat in list(self.agent_heartbeats.items()):
            if current_time - last_heartbeat > timeout:
                self.log("WARN", f"Agent {agent_id} appears inactive (no heartbeat for 60s)")
                # Remove from tracking
                del self.agent_heartbeats[agent_id]

    def make_decision(self, situation: str) -> str:
        """
        Use LLM to make tactical decisions.

        Args:
            situation: Description of the current situation

        Returns:
            Decision/recommendation from LLM
        """
        try:
            user_message = f"""
Current Situation:
{situation}

Engagement: {self.scope.engagement_name if self.scope else 'Unknown'}
Targets: {', '.join(self.scope.targets) if self.scope else 'Unknown'}
Rules of Engagement: {json.dumps(self.scope.rules_of_engagement, indent=2) if self.scope else 'Unknown'}

Based on the situation and rules of engagement, what tactical decision should be made?
Provide a clear recommendation with reasoning.
"""

            response = self.llm.chat(
                system_prompt=self.system_prompt,
                user_message=user_message,
                temperature=0.3,  # Lower temperature for more consistent decisions
            )

            self.log("INFO", f"LLM Decision: {response}")
            return response

        except Exception as e:
            self.log("ERROR", f"Error making decision: {e}")
            return "Unable to make decision - manual intervention required"

    def run(self) -> None:
        """Main agent loop"""
        self.running = True
        self.log("INFO", "Tactical Coordinator starting...")

        try:
            # Load scope
            self.load_scope()

            # Subscribe to all events for monitoring
            self.subscribe_to_events(
                [
                    EventType.AGENT_HEARTBEAT,
                    EventType.HOST_FOUND,
                    EventType.SERVICE_DISCOVERED,
                    EventType.VULNERABILITY_IDENTIFIED,
                    EventType.HOST_COMPROMISED,
                    EventType.EXPLOITATION_FAILED,
                    EventType.OPERATIONAL_ALERT,
                ],
                self.handle_event
            )

            # Start engagement
            time.sleep(2)  # Wait for other agents to initialize
            self.start_engagement()

            # Main monitoring loop
            while self.running:
                # Send heartbeat
                self.send_heartbeat()

                # Check agent health
                self.check_agent_health()

                # Sleep
                time.sleep(30)

        except KeyboardInterrupt:
            self.log("INFO", "Received interrupt signal")
        except Exception as e:
            self.log("ERROR", f"Error in main loop: {e}", exc_info=True)
        finally:
            self.shutdown()


def main():
    """Main entry point"""
    agent = TacticalCoordinator()
    agent.run()


if __name__ == "__main__":
    main()
