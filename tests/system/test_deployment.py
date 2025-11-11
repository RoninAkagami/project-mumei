"""
System Test which gives a demo of project-mumei up and running.
Currently testing engagement aganist OWASP Juice shop mirror website.
Requires .env (or) .env.local to be setup in the /tests/system/ directory.
All prerequistsies as listed in SETUP_AND_USAGE.md are to be there.
This file requires redis too!
"""

import subprocess
import json
import os
import shutil
from pathlib import Path

class TestDeployment:
    """Test class for deployment operations"""
    
    def test_write_scope_config(self):
        """Write the scope configuration to the JSON file"""
        scope_data = {
            "engagement_name": "OWASP Juice Shop Demo test",
            "targets": [
                "https://akashop.akamai.com/"
            ],
            "excluded": [],
            "rules_of_engagement": {
                "max_concurrent_scans": 5,
                "rate_limit_delay": 1.0,
                "stealth_mode": False,
                "allowed_hours": {
                    "start": "09:00",
                    "end": "17:00",
                    "timezone": "UTC"
                },
                "destructive_tests_allowed": False,
                "dos_tests_allowed": True
            },
            "objectives": [
                "Identify all exposed services",
                "Discover vulnerabilities with CVSS >= 5.0",
                "Attempt exploitation of critical vulnerabilities",
                "Document evidence of successful compromises"
            ]
        }
        
        config_path = Path("../../config/scope.json")
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump(scope_data, f, indent=2)
        
        print(f"✓ Written scope configuration to {config_path}")
    
    def test_copy_env_file(self):
        """Copy .env.local or .env to ../../.env"""
        target_path = Path("../../.env")
        
        # Try .env.local first, then .env
        for source_name in [".env.local", ".env"]:
            source_path = Path(source_name)
            if source_path.exists():
                shutil.copy(source_path, target_path)
                print(f"✓ Copied {source_name} to {target_path}")
                return
        
        print("⚠ Warning: Neither .env.local nor .env found")
    
    def test_make_scripts_executable(self):
        """Make all scripts in scripts/ directory executable"""
        result = subprocess.run(['chmod', '+x', 'scripts/*.sh'], shell=True)
        if result.returncode == 0:
            print("✓ Made scripts executable")
        else:
            print("✗ Failed to make scripts executable")
    
    def test_run_start_script(self):
        """Run the start.sh script"""
        print("\n--- Running start.sh ---")
        subprocess.run(['./scripts/start.sh'])
    
    def test_run_init_engagement(self):
        """Run the init_engagement.sh script"""
        print("\n--- Running init_engagement.sh ---")
        subprocess.run(['./scripts/init_engagement.sh'])
    
    def test_run_docker_logs(self):
        """Run docker-compose logs with follow, handle Ctrl+C"""
        print("\n--- Running docker-compose logs (Press Ctrl+C to stop) ---")
        try:
            subprocess.run(['docker-compose', 'logs', '-f'])
        except KeyboardInterrupt:
            print("\n\n✓ Received Ctrl+C, stopping services...")
    
    def test_run_stop_script(self):
        """Run the stop.sh script"""
        print("\n--- Running stop.sh ---")
        subprocess.run(['./scripts/stop.sh'])
    
    def test_full_deployment(self):
        """Main execution function running full deployment"""
        print("=== Starting Deployment Process ===\n")
        
        # Step 1: Write scope configuration
        self.test_write_scope_config()
        
        # Step 2: Copy environment file
        self.test_copy_env_file()
        
        # Step 3: Make scripts executable
        self.test_make_scripts_executable()
        
        # Step 4: Start services
        self.test_run_start_script()
        
        # Step 5: Initialize engagement
        self.test_run_init_engagement()
        
        # Step 6: Follow logs (blocks until Ctrl+C)
        self.test_run_docker_logs()
        
        # Step 7: Stop services
        self.test_run_stop_script()
        
        print("\n=== Deployment Process Complete ===")


if __name__ == "__main__":
    # Run the full deployment when executed directly
    deployment = TestDeployment()
    deployment.test_full_deployment()
