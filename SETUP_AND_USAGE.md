# Project Mumei - Setup and Usage Guide

## Overview

Project Mumei is a collaborative multi-agent system for autonomous penetration testing. It uses LLM-powered agents that communicate through a central message bus (Blackboard) and share context through a State Manager.

## Prerequisites

- Docker and Docker Compose
- OpenAI API key or Anthropic API key
- At least 8GB RAM
- Linux/macOS (Windows with WSL2)

## Quick Start

### 1. Clone and Setup

```bash
# Navigate to project directory
cd project-mumei

# Copy environment template
cp .env.example .env

# Edit .env and add your API keys
nano .env
```

### 2. Configure Your Engagement

Edit `config/scope.json` to define your penetration test scope:

```json
{
  "engagement_name": "My Penetration Test",
  "targets": [
    "192.168.1.0/24",
    "testapp.example.com"
  ],
  "excluded": [
    "192.168.1.1"
  ],
  "rules_of_engagement": {
    "max_concurrent_scans": 5,
    "rate_limit_delay": 1.0,
    "stealth_mode": false,
    "destructive_tests_allowed": false
  }
}
```

### 3. Start the System

```bash
# Make scripts executable
chmod +x scripts/*.sh

# Start all services
./scripts/start.sh
```

This will:
- Build Docker images
- Start Redis
- Start State Manager
- Start all agent containers

### 4. Initialize Engagement

```bash
./scripts/init_engagement.sh
```

### 5. Monitor Progress

```bash
# View all logs
docker-compose logs -f

# View specific agent logs
docker-compose logs -f tactical-coordinator
docker-compose logs -f surface-mapper-active
docker-compose logs -f service-profiler-http

# Check State Manager API
curl http://localhost:8000/state/summary | python3 -m json.tool

# View discovered hosts
curl http://localhost:8000/state/hosts | python3 -m json.tool

# View vulnerabilities
curl http://localhost:8000/state/vulnerabilities | python3 -m json.tool
```

### 6. Stop the System

```bash
./scripts/stop.sh
```

This will export the final state and stop all containers.

## Architecture

### Agents

1. **Tactical Coordinator**: Orchestrates the engagement, enforces scope, monitors agent health
2. **Surface Mapper (Passive)**: DNS enumeration, subdomain discovery, OSINT
3. **Surface Mapper (Active)**: Port scanning, service detection with nmap
4. **Service Profiler (HTTP)**: Web vulnerability scanning with nikto, gobuster, sqlmap
5. **Exploitation Engineer**: Weaponizes vulnerabilities using Metasploit and custom exploits
6. **Lateral Movement**: Post-exploitation reconnaissance, credential harvesting, privilege escalation

### Communication Flow

```
Agent → Blackboard (Redis Pub/Sub) → Other Agents
Agent → State Manager → Global State (Redis)
```

### Event Types

- `SCAN_INITIATED`: Engagement started
- `HOST_FOUND`: New target discovered
- `SERVICE_DISCOVERED`: Open port/service identified
- `VULNERABILITY_IDENTIFIED`: Vulnerability found
- `HOST_COMPROMISED`: Target successfully exploited
- `CREDENTIAL_DISCOVERED`: Credentials harvested
- `EXPLOITATION_FAILED`: Exploit attempt failed

## Configuration

### Environment Variables (.env)

```bash
# LLM Configuration
OPENAI_API_KEY=your_key_here
ANTHROPIC_API_KEY=your_key_here
LLM_PROVIDER=openai  # or anthropic
LLM_MODEL=gpt-4

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379

# Agent Configuration
LOG_LEVEL=INFO
AGENT_TIMEOUT=300
MAX_RETRIES=3
```

### Scope Configuration (config/scope.json)

- **targets**: List of IP addresses, CIDR ranges, or hostnames to test
- **excluded**: Targets to exclude from testing
- **rules_of_engagement**: Operational parameters
  - `max_concurrent_scans`: Maximum parallel operations
  - `rate_limit_delay`: Delay between requests (seconds)
  - `stealth_mode`: Enable stealth techniques
  - `destructive_tests_allowed`: Allow destructive tests
  - `dos_tests_allowed`: Allow DoS tests

## API Endpoints

The State Manager exposes a REST API on port 8000:

### Health Check
```bash
GET http://localhost:8000/health
```

### Get Complete State
```bash
GET http://localhost:8000/state
```

### Get State Summary
```bash
GET http://localhost:8000/state/summary
```

### Query Hosts
```bash
GET http://localhost:8000/state/hosts?status=compromised
```

### Query Services
```bash
GET http://localhost:8000/state/services?service_name=http
```

### Query Vulnerabilities
```bash
GET http://localhost:8000/state/vulnerabilities?min_cvss=7.0
```

### Export State
```bash
POST http://localhost:8000/state/export
```

## How It Works

### 1. Discovery Phase

The Tactical Coordinator publishes a `SCAN_INITIATED` event with the scope. Surface Mappers receive this and begin discovery:

- **Passive Mapper**: DNS enumeration, subdomain discovery
- **Active Mapper**: Port scanning with nmap

Each discovered host triggers a `HOST_FOUND` event, and each open service triggers a `SERVICE_DISCOVERED` event.

### 2. Analysis Phase

Service Profilers subscribe to `SERVICE_DISCOVERED` events and analyze services based on their protocol specialization:

- **HTTP Profiler**: Runs nikto, gobuster, checks for web vulnerabilities
- **SMB Profiler**: Checks for EternalBlue, enumerates shares
- **Database Profiler**: Checks for misconfigurations

Identified vulnerabilities trigger `VULNERABILITY_IDENTIFIED` events.

### 3. Exploitation Phase

The Exploitation Engineer subscribes to `VULNERABILITY_IDENTIFIED` events and attempts exploitation:

- Searches for Metasploit modules
- Executes exploits
- Establishes sessions on compromised hosts

Successful compromises trigger `HOST_COMPROMISED` events.

### 4. Post-Exploitation Phase

The Lateral Movement Agent subscribes to `HOST_COMPROMISED` events and performs:

- Internal network discovery
- Credential harvesting
- Privilege escalation attempts
- Lateral movement to other systems

New discoveries create a feedback loop, triggering more `HOST_FOUND` and `SERVICE_DISCOVERED` events.

## LLM-Powered Decision Making

Each agent uses an LLM to make intelligent decisions:

- **Context-Aware**: Agents have detailed system prompts with tool knowledge and methodologies
- **Adaptive**: LLMs analyze situations and suggest appropriate commands
- **Example-Driven**: Prompts include real-world penetration testing scenarios

Example agent decision flow:
1. Receive event (e.g., ServiceDiscovered for Apache 2.4.49)
2. Query LLM with service details
3. LLM suggests: "This version is vulnerable to CVE-2021-41773, run these commands..."
4. Agent executes suggested commands
5. Parse results and publish findings

## CLI-First Approach

Agents primarily use CLI execution:

```python
# Execute any command-line tool
result = self.execute_cli("nmap -sV -p 80,443 target.com")

# Parse output
if result["success"]:
    # Process stdout
    parse_nmap_output(result["stdout"])
```

This allows agents to use the full Kali Linux toolset:
- nmap, masscan for scanning
- nikto, gobuster, sqlmap for web testing
- hydra, john for password attacks
- msfconsole for exploitation

## Scaling

### Horizontal Scaling

Scale specific agent types:

```bash
# Scale Surface Mappers
docker-compose up -d --scale surface-mapper-active=3

# Scale Service Profilers
docker-compose up -d --scale service-profiler-http=2
```

### Adding Custom Agents

1. Create new agent class extending `BaseAgent`
2. Implement `run()` method
3. Subscribe to relevant events
4. Add to docker-compose.yml

## Troubleshooting

### Agents Not Starting

```bash
# Check logs
docker-compose logs agent-name

# Verify Redis is running
docker-compose ps redis

# Check State Manager
curl http://localhost:8000/health
```

### No Events Being Published

```bash
# Check Tactical Coordinator logs
docker-compose logs tactical-coordinator

# Verify scope.json is valid
cat config/scope.json | python3 -m json.tool

# Check Redis connectivity
docker-compose exec redis redis-cli ping
```

### LLM API Errors

```bash
# Verify API key in .env
cat .env | grep API_KEY

# Check agent logs for API errors
docker-compose logs | grep "API"
```

## Security Considerations

⚠️ **WARNING**: This system performs real penetration testing activities.

- Only use on systems you own or have explicit permission to test
- Configure scope carefully to avoid testing unauthorized targets
- Use stealth mode when required
- Monitor for defensive responses (WAF blocks, rate limiting)
- Store API keys securely
- Review rules of engagement before starting

## Best Practices

1. **Start Small**: Test with a single target first
2. **Monitor Closely**: Watch logs during initial runs
3. **Verify Scope**: Double-check scope configuration
4. **Use Stealth Mode**: Enable for production environments
5. **Export State Regularly**: Save state periodically
6. **Review Findings**: Manually verify automated findings

## Example Workflow

```bash
# 1. Setup
cp .env.example .env
nano .env  # Add API keys

# 2. Configure scope
nano config/scope.json

# 3. Start system
./scripts/start.sh

# 4. Monitor in separate terminals
docker-compose logs -f tactical-coordinator
docker-compose logs -f surface-mapper-active
docker-compose logs -f service-profiler-http

# 5. Check progress
watch -n 5 'curl -s http://localhost:8000/state/summary | python3 -m json.tool'

# 6. Export results
curl -X POST http://localhost:8000/state/export > results.json

# 7. Stop system
./scripts/stop.sh
```

## Advanced Usage

### Custom Agent Prompts

Modify agent behavior by editing `mumei/shared/prompts.py`:

```python
SURFACE_MAPPER_PROMPT = """
Your custom instructions here...
"""
```

### Adding New Tools

Update Dockerfiles to include additional tools:

```dockerfile
RUN apt-get install -y your-tool
```

### Custom Event Types

Add new event types in `mumei/shared/models.py`:

```python
class EventType(str, Enum):
    YOUR_CUSTOM_EVENT = "your_custom_event"
```

## Support and Contributing

- Report issues on GitHub
- Contribute new agents or features
- Share custom prompts and workflows

## License

See LICENSE file for details.

## Disclaimer

This tool is for authorized security testing only. Unauthorized access to computer systems is illegal. Users are responsible for complying with all applicable laws and regulations.
