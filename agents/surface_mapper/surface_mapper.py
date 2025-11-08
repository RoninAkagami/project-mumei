"""
Surface Mapper Agent - Discovers targets and identifies services
"""

import os
import sys
import json
import time
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mumei.shared.base_agent import BaseAgent
from mumei.shared.models import Event, EventType, Priority, Host, Service
from mumei.shared.prompts import get_agent_prompt

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SurfaceMapper(BaseAgent):
    """
    Surface Mapper discovers targets and identifies exposed services.
    Operates in passive or active mode.
    """

    def __init__(self, agent_id: str, mode: str = "active"):
        """
        Initialize Surface Mapper.

        Args:
            agent_id: Unique agent identifier
            mode: "passive" or "active"
        """
        super().__init__(agent_id=agent_id, agent_type="surface_mapper")

        self.mode = mode  # passive or active
        self.scope_targets: List[str] = []
        self.scope_excluded: List[str] = []
        self.discovered_hosts: Dict[str, Host] = {}
        self.system_prompt = get_agent_prompt("surface_mapper")

        logger.info(f"Surface Mapper {agent_id} initialized in {mode} mode")

    def is_in_scope(self, target: str) -> bool:
        """
        Check if a target is within scope.

        Args:
            target: IP address or hostname

        Returns:
            True if target is in scope
        """
        # Check if excluded
        if target in self.scope_excluded:
            return False

        # Simple check - in production, handle CIDR ranges properly
        for scope_target in self.scope_targets:
            if target in scope_target or scope_target in target:
                return True

        return False

    def handle_scan_initiated(self, event: Event) -> None:
        """
        Handle ScanInitiated event and start discovery.

        Args:
            event: ScanInitiated event
        """
        try:
            self.scope_targets = event.data.get("targets", [])
            self.scope_excluded = event.data.get("excluded", [])

            self.log("INFO", f"Received scope: {', '.join(self.scope_targets)}")

            # Start discovery based on mode
            if self.mode == "passive":
                self.passive_discovery()
            else:
                self.active_discovery()

        except Exception as e:
            self.log("ERROR", f"Error handling scan initiated: {e}", exc_info=True)

    def passive_discovery(self) -> None:
        """Perform passive reconnaissance"""
        self.log("INFO", "Starting passive discovery...")

        for target in self.scope_targets:
            try:
                # DNS enumeration
                self.log("INFO", f"Performing DNS enumeration on {target}")

                # Use LLM to decide what commands to run
                user_message = f"""
Target: {target}
Mode: Passive reconnaissance

Perform passive discovery on this target. Use DNS enumeration, subdomain discovery, and OSINT techniques.
Suggest the specific CLI commands to run for passive reconnaissance.
"""

                response = self.llm.chat(
                    system_prompt=self.system_prompt,
                    user_message=user_message,
                    temperature=0.5,
                )

                self.log("INFO", f"LLM suggested approach: {response[:200]}...")

                # Execute DNS lookup
                result = self.execute_cli(f"host {target}")
                if result["success"]:
                    self.parse_dns_output(target, result["stdout"])

                # Try subdomain enumeration (simple version)
                common_subdomains = ["www", "mail", "ftp", "admin", "vpn", "api"]
                for subdomain in common_subdomains:
                    full_domain = f"{subdomain}.{target}"
                    result = self.execute_cli(f"host {full_domain}", timeout=5)
                    if result["success"] and "has address" in result["stdout"]:
                        self.parse_dns_output(full_domain, result["stdout"])

            except Exception as e:
                self.log("ERROR", f"Error in passive discovery for {target}: {e}")

    def active_discovery(self) -> None:
        """Perform active reconnaissance"""
        self.log("INFO", "Starting active discovery...")

        for target in self.scope_targets:
            try:
                self.log("INFO", f"Scanning target: {target}")

                # Use LLM to decide scanning strategy
                user_message = f"""
Target: {target}
Mode: Active reconnaissance

Perform active discovery on this target. Use port scanning and service detection.
Suggest the specific nmap command to run for efficient discovery.
Consider: fast scan, service version detection, and common ports.
"""

                response = self.llm.chat(
                    system_prompt=self.system_prompt,
                    user_message=user_message,
                    temperature=0.5,
                )

                self.log("INFO", f"LLM suggested approach: {response[:200]}...")

                # Perform host discovery first
                self.log("INFO", f"Checking if {target} is alive...")
                ping_result = self.execute_cli(f"ping -c 1 -W 2 {target}", timeout=5)

                if ping_result["success"] or "1 received" in ping_result.get("stdout", ""):
                    # Host is up, publish HostFound event
                    host = Host(
                        ip_address=target,
                        hostname=target if not target.replace(".", "").isdigit() else None,
                        status="discovered",
                    )
                    self.discovered_hosts[host.host_id] = host

                    self.publish_event(
                        EventType.HOST_FOUND,
                        data=host.model_dump(),
                        priority=Priority.INFO,
                    )

                    self.log("INFO", f"Host {target} is alive, starting port scan...")

                    # Perform port scan
                    self.scan_ports(target, host.host_id)
                else:
                    self.log("INFO", f"Host {target} appears to be down")

            except Exception as e:
                self.log("ERROR", f"Error in active discovery for {target}: {e}")

    def scan_ports(self, target: str, host_id: str) -> None:
        """
        Scan ports on a target.

        Args:
            target: Target IP or hostname
            host_id: Host ID for linking services
        """
        try:
            # Fast scan of common ports
            self.log("INFO", f"Scanning common ports on {target}...")

            # Use nmap for service detection
            nmap_cmd = f"nmap -sV -sC --open -T4 -p 21,22,23,25,80,443,445,3306,3389,8080,8443 {target} -oX /tmp/nmap_{host_id}.xml"

            result = self.execute_cli(nmap_cmd, timeout=300)

            if result["success"]:
                # Parse nmap XML output
                self.parse_nmap_output(f"/tmp/nmap_{host_id}.xml", host_id)
            else:
                self.log("WARN", f"Nmap scan failed: {result.get('stderr', 'Unknown error')}")

        except Exception as e:
            self.log("ERROR", f"Error scanning ports on {target}: {e}")

    def parse_dns_output(self, target: str, output: str) -> None:
        """
        Parse DNS lookup output and publish HostFound events.

        Args:
            target: Target domain
            output: DNS command output
        """
        try:
            # Extract IP addresses from output
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = re.findall(ip_pattern, output)

            for ip in ips:
                if self.is_in_scope(ip):
                    host = Host(
                        ip_address=ip,
                        hostname=target,
                        status="discovered",
                    )
                    self.discovered_hosts[host.host_id] = host

                    self.publish_event(
                        EventType.HOST_FOUND,
                        data=host.model_dump(),
                        priority=Priority.INFO,
                    )

                    self.log("INFO", f"Discovered host: {ip} ({target})")

        except Exception as e:
            self.log("ERROR", f"Error parsing DNS output: {e}")

    def parse_nmap_output(self, xml_file: str, host_id: str) -> None:
        """
        Parse nmap XML output and publish ServiceDiscovered events.

        Args:
            xml_file: Path to nmap XML output file
            host_id: Host ID for linking services
        """
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host in root.findall('host'):
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_id = port.get('portid')
                        protocol = port.get('protocol')

                        service_elem = port.find('service')
                        service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                        product = service_elem.get('product', '') if service_elem is not None else ''
                        version = service_elem.get('version', '') if service_elem is not None else ''
                        banner = f"{product} {version}".strip() if product or version else None

                        # Create service object
                        service = Service(
                            host_id=host_id,
                            port=int(port_id),
                            protocol=protocol,
                            service_name=service_name,
                            banner=banner,
                            version=version if version else None,
                        )

                        # Publish ServiceDiscovered event
                        self.publish_event(
                            EventType.SERVICE_DISCOVERED,
                            data=service.model_dump(),
                            priority=Priority.INFO,
                        )

                        self.log("INFO", f"Discovered service: {service_name}:{port_id}/{protocol} on {host_id}")

        except FileNotFoundError:
            self.log("WARN", f"Nmap output file not found: {xml_file}")
        except Exception as e:
            self.log("ERROR", f"Error parsing nmap output: {e}", exc_info=True)

    def run(self) -> None:
        """Main agent loop"""
        self.running = True
        self.log("INFO", f"Surface Mapper starting in {self.mode} mode...")

        try:
            # Subscribe to ScanInitiated events
            self.subscribe_to_events([EventType.SCAN_INITIATED], self.handle_scan_initiated)

            # Main loop - send heartbeats
            while self.running:
                self.send_heartbeat()
                time.sleep(30)

        except KeyboardInterrupt:
            self.log("INFO", "Received interrupt signal")
        except Exception as e:
            self.log("ERROR", f"Error in main loop: {e}", exc_info=True)
        finally:
            self.shutdown()


def main():
    """Main entry point"""
    agent_id = os.getenv("AGENT_ID", "surface_mapper_01")
    mode = os.getenv("AGENT_MODE", "active")

    agent = SurfaceMapper(agent_id=agent_id, mode=mode)
    agent.run()


if __name__ == "__main__":
    main()
