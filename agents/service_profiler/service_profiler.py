"""
Service Profiler Agent - Analyzes services and identifies vulnerabilities
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
from mumei.shared.models import Event, EventType, Priority, Vulnerability
from mumei.shared.prompts import get_agent_prompt

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ServiceProfiler(BaseAgent):
    """
    Service Profiler performs deep analysis of services to identify vulnerabilities.
    Specialized by protocol (HTTP, SMB, databases, etc.)
    """

    def __init__(self, agent_id: str, protocol_filter: Optional[List[str]] = None):
        """
        Initialize Service Profiler.

        Args:
            agent_id: Unique agent identifier
            protocol_filter: List of protocols to handle (e.g., ["http", "https"])
        """
        super().__init__(agent_id=agent_id, agent_type="service_profiler")

        self.protocol_filter = protocol_filter or []
        self.system_prompt = get_agent_prompt("service_profiler")
        self.profiling_timeout = 300  # 5 minutes

        logger.info(f"Service Profiler {agent_id} initialized for protocols: {', '.join(self.protocol_filter)}")

    def should_handle_service(self, service_data: Dict[str, Any]) -> bool:
        """
        Check if this profiler should handle the service.

        Args:
            service_data: Service data from event

        Returns:
            True if service matches protocol filter
        """
        if not self.protocol_filter:
            return True

        service_name = service_data.get("service_name", "").lower()
        port = service_data.get("port")

        # Check if service name matches filter
        for protocol in self.protocol_filter:
            if protocol.lower() in service_name:
                return True

        # Check common ports for protocols
        if "http" in self.protocol_filter or "https" in self.protocol_filter:
            if port in [80, 443, 8080, 8443, 8000, 8888]:
                return True

        if "smb" in self.protocol_filter:
            if port in [139, 445]:
                return True

        if "ssh" in self.protocol_filter:
            if port == 22:
                return True

        return False

    def handle_service_discovered(self, event: Event) -> None:
        """
        Handle ServiceDiscovered event and profile the service.

        Args:
            event: ServiceDiscovered event
        """
        try:
            service_data = event.data

            # Check if we should handle this service
            if not self.should_handle_service(service_data):
                self.log("DEBUG", f"Skipping service {service_data.get('service_name')} (not in filter)")
                return

            self.log("INFO", f"Profiling service: {service_data.get('service_name')} on port {service_data.get('port')}")

            # Profile based on service type
            service_name = service_data.get("service_name", "").lower()
            port = service_data.get("port")

            if "http" in service_name or port in [80, 443, 8080, 8443]:
                self.profile_http_service(service_data)
            elif "smb" in service_name or port in [139, 445]:
                self.profile_smb_service(service_data)
            elif "ssh" in service_name or port == 22:
                self.profile_ssh_service(service_data)
            elif "mysql" in service_name or port == 3306:
                self.profile_mysql_service(service_data)
            else:
                self.profile_generic_service(service_data)

        except Exception as e:
            self.log("ERROR", f"Error handling service discovered: {e}", exc_info=True)

    def profile_http_service(self, service_data: Dict[str, Any]) -> None:
        """Profile HTTP/HTTPS service"""
        try:
            host = service_data.get("host_id")  # This would be IP in practice
            port = service_data.get("port")
            service_id = service_data.get("service_id")

            # Construct URL
            protocol = "https" if port == 443 or port == 8443 else "http"
            # For demo, we'll use a placeholder - in real implementation, query State Manager for IP
            target_url = f"{protocol}://target:{port}"

            self.log("INFO", f"Profiling HTTP service at {target_url}")

            # Use LLM to decide what tools to run
            user_message = f"""
Service: HTTP/HTTPS
Port: {port}
Banner: {service_data.get('banner', 'Unknown')}
Version: {service_data.get('version', 'Unknown')}

Analyze this web service and suggest specific CLI commands to:
1. Identify vulnerabilities
2. Enumerate directories
3. Detect technologies and frameworks
4. Check for common misconfigurations

Provide the exact commands to run.
"""

            response = self.llm.chat(
                system_prompt=self.system_prompt,
                user_message=user_message,
                temperature=0.5,
            )

            self.log("INFO", f"LLM analysis: {response[:300]}...")

            # Run nikto scan
            self.log("INFO", "Running nikto scan...")
            nikto_result = self.execute_cli(
                f"nikto -h {target_url} -Format json -o /tmp/nikto_output.json",
                timeout=self.profiling_timeout
            )

            if nikto_result["success"]:
                self.parse_nikto_output("/tmp/nikto_output.json", service_id)

            # Run gobuster for directory enumeration
            self.log("INFO", "Running gobuster...")
            gobuster_result = self.execute_cli(
                f"gobuster dir -u {target_url} -w /usr/share/wordlists/dirb/common.txt -q -t 10",
                timeout=self.profiling_timeout
            )

            if gobuster_result["success"]:
                self.log("INFO", f"Gobuster found directories: {gobuster_result['stdout'][:200]}")

        except Exception as e:
            self.log("ERROR", f"Error profiling HTTP service: {e}")

    def profile_smb_service(self, service_data: Dict[str, Any]) -> None:
        """Profile SMB service"""
        try:
            host = service_data.get("host_id")
            port = service_data.get("port")
            service_id = service_data.get("service_id")

            self.log("INFO", f"Profiling SMB service on port {port}")

            # Use LLM for analysis
            user_message = f"""
Service: SMB/CIFS
Port: {port}
Banner: {service_data.get('banner', 'Unknown')}

Analyze this SMB service and suggest specific nmap scripts and commands to:
1. Check for EternalBlue (MS17-010)
2. Enumerate shares
3. Identify SMB version vulnerabilities
4. Check for anonymous access

Provide the exact commands to run.
"""

            response = self.llm.chat(
                system_prompt=self.system_prompt,
                user_message=user_message,
                temperature=0.5,
            )

            self.log("INFO", f"LLM analysis: {response[:300]}...")

            # Run SMB vulnerability scan
            self.log("INFO", "Scanning for SMB vulnerabilities...")
            nmap_result = self.execute_cli(
                f"nmap -p {port} --script smb-vuln* target",
                timeout=self.profiling_timeout
            )

            if nmap_result["success"]:
                self.parse_smb_vulns(nmap_result["stdout"], service_id)

        except Exception as e:
            self.log("ERROR", f"Error profiling SMB service: {e}")

    def profile_ssh_service(self, service_data: Dict[str, Any]) -> None:
        """Profile SSH service"""
        try:
            port = service_data.get("port")
            service_id = service_data.get("service_id")
            version = service_data.get("version", "")

            self.log("INFO", f"Profiling SSH service: {version}")

            # Check for known vulnerable SSH versions
            if version:
                # Simple version check (in production, use CVE database)
                if "OpenSSH" in version:
                    version_match = re.search(r'OpenSSH[_\s]+([\d.]+)', version)
                    if version_match:
                        ssh_version = version_match.group(1)
                        self.log("INFO", f"Detected OpenSSH version: {ssh_version}")

                        # Check for known vulnerabilities (simplified)
                        if ssh_version < "7.4":
                            self.publish_vulnerability(
                                service_id=service_id,
                                title="Outdated OpenSSH Version",
                                description=f"OpenSSH {ssh_version} may have known vulnerabilities",
                                cvss_score=5.0,
                            )

        except Exception as e:
            self.log("ERROR", f"Error profiling SSH service: {e}")

    def profile_mysql_service(self, service_data: Dict[str, Any]) -> None:
        """Profile MySQL service"""
        try:
            port = service_data.get("port")
            service_id = service_data.get("service_id")

            self.log("INFO", "Profiling MySQL service...")

            # Run MySQL enumeration
            nmap_result = self.execute_cli(
                f"nmap -p {port} --script mysql-enum,mysql-info target",
                timeout=self.profiling_timeout
            )

            if nmap_result["success"]:
                self.log("INFO", f"MySQL enumeration: {nmap_result['stdout'][:200]}")

        except Exception as e:
            self.log("ERROR", f"Error profiling MySQL service: {e}")

    def profile_generic_service(self, service_data: Dict[str, Any]) -> None:
        """Profile generic service"""
        try:
            service_name = service_data.get("service_name")
            port = service_data.get("port")
            service_id = service_data.get("service_id")

            self.log("INFO", f"Profiling generic service: {service_name}")

            # Use nmap scripts for generic enumeration
            nmap_result = self.execute_cli(
                f"nmap -p {port} -sV --script=default target",
                timeout=self.profiling_timeout
            )

            if nmap_result["success"]:
                self.log("INFO", f"Generic scan results: {nmap_result['stdout'][:200]}")

        except Exception as e:
            self.log("ERROR", f"Error profiling generic service: {e}")

    def parse_nikto_output(self, json_file: str, service_id: str) -> None:
        """Parse nikto JSON output and publish vulnerabilities"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            # Parse nikto findings
            for vuln in data.get("vulnerabilities", []):
                self.publish_vulnerability(
                    service_id=service_id,
                    title=vuln.get("msg", "Unknown vulnerability"),
                    description=vuln.get("description", ""),
                    cvss_score=self.estimate_cvss(vuln.get("msg", "")),
                )

        except FileNotFoundError:
            self.log("WARN", f"Nikto output file not found: {json_file}")
        except Exception as e:
            self.log("ERROR", f"Error parsing nikto output: {e}")

    def parse_smb_vulns(self, nmap_output: str, service_id: str) -> None:
        """Parse nmap SMB vulnerability scan output"""
        try:
            # Check for EternalBlue
            if "MS17-010" in nmap_output or "VULNERABLE" in nmap_output:
                if "ms17-010" in nmap_output.lower():
                    self.publish_vulnerability(
                        service_id=service_id,
                        cve_id="CVE-2017-0144",
                        title="EternalBlue SMB Remote Code Execution",
                        description="SMB service is vulnerable to EternalBlue (MS17-010)",
                        cvss_score=9.3,
                        exploit_available=True,
                    )

        except Exception as e:
            self.log("ERROR", f"Error parsing SMB vulnerabilities: {e}")

    def estimate_cvss(self, vulnerability_description: str) -> float:
        """Estimate CVSS score based on vulnerability description"""
        description_lower = vulnerability_description.lower()

        if any(word in description_lower for word in ["rce", "remote code execution", "command injection"]):
            return 9.0
        elif any(word in description_lower for word in ["sql injection", "authentication bypass"]):
            return 8.0
        elif any(word in description_lower for word in ["xss", "csrf", "directory traversal"]):
            return 6.5
        elif any(word in description_lower for word in ["information disclosure", "weak"]):
            return 5.0
        else:
            return 4.0

    def publish_vulnerability(
        self,
        service_id: str,
        title: str,
        description: str,
        cvss_score: float,
        cve_id: Optional[str] = None,
        exploit_available: bool = False,
    ) -> None:
        """Publish a VulnerabilityIdentified event"""
        try:
            vuln = Vulnerability(
                service_id=service_id,
                cve_id=cve_id,
                cvss_score=cvss_score,
                title=title,
                description=description,
                exploit_available=exploit_available,
            )

            self.publish_event(
                EventType.VULNERABILITY_IDENTIFIED,
                data=vuln.model_dump(),
                priority=Priority.CRITICAL if cvss_score >= 9.0 else Priority.WARN,
            )

            self.log("INFO", f"Published vulnerability: {title} (CVSS: {cvss_score})")

        except Exception as e:
            self.log("ERROR", f"Error publishing vulnerability: {e}")

    def run(self) -> None:
        """Main agent loop"""
        self.running = True
        self.log("INFO", f"Service Profiler starting (protocols: {', '.join(self.protocol_filter)})...")

        try:
            # Subscribe to ServiceDiscovered events
            self.subscribe_to_events([EventType.SERVICE_DISCOVERED], self.handle_service_discovered)

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
    agent_id = os.getenv("AGENT_ID", "service_profiler_01")
    protocol_filter_str = os.getenv("PROTOCOL_FILTER", "http,https")
    protocol_filter = [p.strip() for p in protocol_filter_str.split(",")]

    agent = ServiceProfiler(agent_id=agent_id, protocol_filter=protocol_filter)
    agent.run()


if __name__ == "__main__":
    main()