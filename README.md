# Project Mumei
## A Collaborative Multi-Agent System for Autonomous Penetration Testing

> **⚠️ LEGAL WARNING**: This tool is designed for authorized security testing only. Unauthorized access to computer systems is illegal. Users are solely responsible for complying with all applicable laws and regulations.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Agent Types](#agent-types)
- [Technology Stack](#technology-stack)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

Project Mumei revolutionizes penetration testing automation by replacing traditional linear tool chains with a **collaborative multi-agent system**. Unlike conventional approaches where tools run in isolation (nmap → nikto → sqlmap), Mumei employs specialized AI-powered agents that work as a coordinated team, sharing intelligence in real-time to mimic sophisticated human penetration testers.

### The Problem with Traditional Automation

Current penetration testing automation follows a sequential pipeline model where:
- Tools operate in isolation without sharing context
- Intelligence from one tool doesn't guide others
- No dynamic adaptation to discoveries
- Inefficient and fails to simulate complex attack chains

### The Mumei Solution

Project Mumei introduces:
- **Collaborative Agents**: Specialized agents working as a unified team
- **Stateful Awareness**: Live, shared context of the entire engagement
- **Event-Driven Architecture**: Real-time reaction to discoveries
- **LLM-Powered Intelligence**: Context-aware decision making
- **Dynamic Pivoting**: Automatic lateral movement and escalation

---

## ✨ Key Features

### 🤖 LLM-Powered Autonomous Agents
- Each agent uses GPT-4 or Claude for intelligent decision-making
- Comprehensive system prompts with real-world penetration testing scenarios
- Context-aware analysis and adaptive command selection
- Mimics human penetration tester thought processes

### 🔄 Event-Driven Architecture
- Redis Pub/Sub for reliable, low-latency communication
- 14 event types covering all discovery and exploitation activities
- Loose coupling enables independent agent scaling
- Automatic feedback loops for iterative penetration

### 🎯 Centralized State Management
- Real-time Global State maintained in Redis
- Intelligent aggregation of all findings
- REST API for monitoring and queries
- Complete audit trail of engagement activities

### 🛠️ CLI-First Approach
- Direct access to full Kali Linux toolset
- Execute any command-line penetration testing tool
- Real penetration tester workflow
- Flexible and extensible

### 🐳 Containerized Deployment
- Docker images for all components
- Easy horizontal scaling
- Isolated environments
- Simple deployment with Docker Compose

### 📊 Real-Time Monitoring
- FastAPI REST API for state queries
- Live event streaming
- Comprehensive logging
- Health check endpoints

---

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose installed
- OpenAI API key or Anthropic API key
- At least 8GB RAM
- Linux, macOS, or Windows with WSL2

### Installation & Setup

```bash
# 1. Clone the repository
git clone https://github.com/RoninAkagami/project-mumei.git
cd project-mumei

# 2. Configure environment
cp .env.example .env
nano .env  # Add your API keys

# 3. Configure test scope
nano config/scope.json  # Define your targets

# 4. Make scripts executable
chmod +x scripts/*.sh

# 5. Start the system
./scripts/start.sh
```

### Monitor Your Engagement

```bash
# View all logs
docker-compose logs -f

# Check state summary
curl http://localhost:8000/state/summary | python3 -m json.tool

# View discovered hosts
curl http://localhost:8000/state/hosts | python3 -m json.tool

# View vulnerabilities
curl http://localhost:8000/state/vulnerabilities | python3 -m json.tool
```

### Stop the System

```bash
./scripts/stop.sh  # Exports final state and stops all containers
```

---

## 🏗️ Architecture

### Core Philosophy

Project Mumei is built on four fundamental principles:

1. **Collaboration over Linearity**: Agents work as a coordinated team, not a sequential pipeline
2. **Stateful Awareness**: Live, shared context of the entire engagement
3. **Event-Driven Agility**: Real-time reaction to discoveries enabling dynamic pivoting
4. **Focused Scope**: Designed for technical penetration testing objectives

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Tactical Coordinator                      │
│              (Orchestration & Scope Management)              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Blackboard (Redis Pub/Sub)                  │
│                  Central Event Bus for All                   │
│                    Agent Communication                       │
└─────────────────────────────────────────────────────────────┘
         │              │              │              │
         ▼              ▼              ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│   Surface    │ │   Service    │ │ Exploitation │ │   Lateral    │
│   Mapper     │ │   Profiler   │ │  Engineer    │ │  Movement    │
│              │ │              │ │              │ │              │
│ • Passive    │ │ • HTTP       │ │ • Metasploit │ │ • Internal   │
│ • Active     │ │ • SMB        │ │ • Manual     │ │   Recon      │
│ • Discovery  │ │ • Databases  │ │ • Exploits   │ │ • Cred Dump  │
└──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘
         │              │              │              │
         └──────────────┴──────────────┴──────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     State Manager Agent                      │
│                  (Global State + REST API)                   │
│                                                               │
│  • Hosts • Services • Vulnerabilities • Credentials          │
│  • Sessions • Evidence • Real-time Aggregation               │
└─────────────────────────────────────────────────────────────┘
```

### Communication Flow

1. **Event Publication**: Agents publish discoveries to the Blackboard
2. **Event Subscription**: Relevant agents receive and process events
3. **State Updates**: State Manager aggregates all findings
4. **Context Queries**: Agents query State Manager for context
5. **Feedback Loops**: New discoveries trigger additional agent actions

## 🤖 Agent Types

### 1. Tactical Coordinator
**Role**: Orchestration and scope management

- Parses and enforces penetration test scope
- Monitors agent health via heartbeats
- Detects operational issues (WAF blocks, rate limiting)
- Makes high-level pivot decisions
- Publishes `SCAN_INITIATED` events to begin engagements

**Key Capabilities**:
- Scope validation and enforcement
- Rules of engagement compliance
- Agent health monitoring
- Operational security detection

### 2. Surface Mapper (Passive & Active)
**Role**: Target discovery and service identification

**Passive Mode**:
- DNS enumeration and subdomain discovery
- OSINT gathering
- Certificate transparency searches
- No direct target contact

**Active Mode**:
- Port scanning with nmap
- Service version detection
- Banner grabbing
- Network mapping

**Key Capabilities**:
- Discovers hosts → publishes `HOST_FOUND`
- Identifies services → publishes `SERVICE_DISCOVERED`
- Scope-aware scanning
- Stealth mode support

### 3. Service Profiler
**Role**: Deep service analysis and vulnerability identification

**Specializations**:
- **HTTP/HTTPS**: Web vulnerability scanning (nikto, gobuster, sqlmap)
- **SMB/CIFS**: Windows service analysis, EternalBlue detection
- **Databases**: MySQL, PostgreSQL, MongoDB fingerprinting
- **SSH**: Version detection and vulnerability checking

**Key Capabilities**:
- Protocol-specific deep analysis
- Vulnerability scanning and identification
- Technology stack detection
- Publishes `VULNERABILITY_IDENTIFIED` events

### 4. Exploitation Engineer
**Role**: Weaponize vulnerabilities and compromise targets

- Metasploit integration for automated exploitation
- Manual exploitation techniques (SQL injection, command injection, path traversal)
- Exploit selection based on CVE and vulnerability type
- Session management for compromised hosts
- Publishes `HOST_COMPROMISED` events

**Key Capabilities**:
- Automated exploit execution
- Multiple exploitation techniques
- Session establishment and management
- Evidence collection

### 5. Lateral Movement Agent
**Role**: Post-exploitation reconnaissance and pivoting

- Internal network discovery from compromised hosts
- Credential harvesting (config files, /etc/shadow, SSH keys)
- Privilege escalation attempts
- Lateral movement to additional systems
- Creates feedback loops for deeper penetration

**Key Capabilities**:
- Internal reconnaissance
- Credential extraction
- Privilege escalation
- Publishes `CREDENTIAL_DISCOVERED` and new `HOST_FOUND` events

### 6. State Manager Agent
**Role**: Centralized state management and monitoring

- Maintains Global State of entire engagement
- Aggregates all findings from events
- Provides REST API for queries and monitoring
- Links related entities (services to hosts, vulnerabilities to services)
- Exports state for reporting

**Key Capabilities**:
- Real-time state updates
- Intelligent data aggregation
- Query API with filters
- State export for reporting

## 💻 Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Language** | Python 3.11+ | Agent implementation and core logic |
| **Communication** | Redis Pub/Sub | Event-driven message bus (Blackboard) |
| **State Storage** | Redis | Global State persistence |
| **API Framework** | FastAPI | REST API for State Manager |
| **LLM Providers** | OpenAI (GPT-4), Anthropic (Claude) | Agent intelligence and decision-making |
| **Data Validation** | Pydantic | Type-safe data models |
| **Containerization** | Docker, Docker Compose | Isolated agent environments |
| **Base OS** | Kali Linux | Penetration testing tools |
| **Tools** | nmap, nikto, gobuster, sqlmap, Metasploit, hydra, john, hashcat | CLI-based penetration testing |

### Penetration Testing Tools Integrated

- **Network Scanning**: nmap, masscan, unicornscan
- **Web Testing**: nikto, gobuster, dirb, wfuzz, ffuf, sqlmap, wpscan
- **Service Enumeration**: enum4linux, smbclient, rpcclient, snmpwalk
- **Exploitation**: msfconsole, searchsploit, exploit-db
- **Password Attacks**: hydra, medusa, john, hashcat, crackmapexec
- **Post-Exploitation**: nc (netcat), socat, chisel
- **Utilities**: curl, wget, dig, host, whois, nslookup

## 📡 Communication Protocol

### Event Structure

All agents communicate using structured JSON events:

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "event_type": "SERVICE_DISCOVERED",
  "timestamp": "2025-11-07T10:30:00.000Z",
  "source_agent_id": "surface_mapper_active_01",
  "priority": "INFO",
  "data": {
    "target": "192.168.1.10",
    "port": 443,
    "protocol": "tcp",
    "service_name": "https",
    "banner": "Apache/2.4.49 (Ubuntu)",
    "version": "2.4.49"
  },
  "correlation_id": null
}
```

### Event Types

| Event Type | Published By | Subscribed By | Purpose |
|------------|--------------|---------------|---------|
| `SCAN_INITIATED` | Tactical Coordinator | Surface Mappers | Start engagement |
| `HOST_FOUND` | Surface Mapper, Lateral Movement | Surface Mapper, Service Profiler | New target discovered |
| `SERVICE_DISCOVERED` | Surface Mapper | Service Profiler | Open port/service found |
| `VULNERABILITY_IDENTIFIED` | Service Profiler | Exploitation Engineer | Vulnerability detected |
| `HOST_COMPROMISED` | Exploitation Engineer | Lateral Movement | Target exploited |
| `CREDENTIAL_DISCOVERED` | Lateral Movement | All Agents | Credentials found |
| `EXPLOITATION_FAILED` | Exploitation Engineer | Tactical Coordinator | Exploit attempt failed |
| `OPERATIONAL_ALERT` | Tactical Coordinator | All Agents | Operational issue detected |

### Communication Patterns

1. **Publish-Subscribe**: Primary pattern for agent communication
   - Agents publish events to channels
   - Interested agents subscribe to relevant channels
   - Loose coupling, easy scaling

2. **Request-Response**: For State Manager queries
   - Agent publishes `STATE_QUERY_REQUEST` with correlation_id
   - State Manager responds with `STATE_QUERY_RESPONSE`
   - Correlation ID links request and response

## 🔄 Example Attack Flow

### Scenario: Compromising a Web Application

```
1. INITIALIZATION
   Tactical Coordinator → publishes SCAN_INITIATED
   Scope: webapp.target.com

2. DISCOVERY
   Surface Mapper (Active) → scans target
   Discovers: 192.168.1.10:443 (Apache/2.4.49)
   Publishes: HOST_FOUND, SERVICE_DISCOVERED

3. ANALYSIS
   Service Profiler (HTTP) → receives SERVICE_DISCOVERED
   Runs: nikto, gobuster
   Identifies: CVE-2021-41773 (Apache Path Traversal)
   Publishes: VULNERABILITY_IDENTIFIED

4. STATE UPDATE
   State Manager → aggregates findings
   Links: Vulnerability → Service → Host
   Updates: Global State with CVSS 7.5 vulnerability

5. EXPLOITATION
   Exploitation Engineer → receives VULNERABILITY_IDENTIFIED
   LLM Analysis: "Apache 2.4.49 vulnerable to path traversal RCE"
   Executes: Metasploit exploit
   Result: Shell as www-data
   Publishes: HOST_COMPROMISED

6. POST-EXPLOITATION
   Lateral Movement → receives HOST_COMPROMISED
   Actions:
   - Discovers internal network: 10.0.0.0/24
   - Harvests credentials from config files
   - Finds database server: 10.0.0.5:3306
   Publishes: HOST_FOUND (internal), CREDENTIAL_DISCOVERED

7. FEEDBACK LOOP
   Service Profiler (Database) → receives new HOST_FOUND
   Cycle continues with internal targets...
```

### Real-Time State Evolution

```
Initial State:
{
  "hosts": 0,
  "services": 0,
  "vulnerabilities": 0,
  "compromised": 0
}

After Discovery:
{
  "hosts": 1,
  "services": 3,
  "vulnerabilities": 0,
  "compromised": 0
}

After Analysis:
{
  "hosts": 1,
  "services": 3,
  "vulnerabilities": 1,
  "compromised": 0
}

After Exploitation:
{
  "hosts": 1,
  "services": 3,
  "vulnerabilities": 1,
  "compromised": 1
}

After Lateral Movement:
{
  "hosts": 5,
  "services": 12,
  "vulnerabilities": 1,
  "compromised": 1,
  "credentials": 3
}
```

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [SETUP_AND_USAGE.md](SETUP_AND_USAGE.md) | Comprehensive setup and usage guide |
| [QUICK_REFERENCE.md](QUICK_REFERENCE.md) | Quick command reference |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues and solutions |
| [IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md) | Implementation details and architecture |
| [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) | Project summary and statistics |

## 📋 Requirements

### System Requirements
- **OS**: Linux, macOS, or Windows with WSL2
- **RAM**: Minimum 8GB (16GB recommended)
- **Disk**: 20GB free space
- **Network**: Internet connection for LLM API calls

### Software Requirements
- Docker 20.10+
- Docker Compose 2.0+
- Python 3.11+ (for local development)
- OpenAI API key or Anthropic API key

## 📦 Installation

### 1. Clone Repository
```bash
git clone https://github.com/RoninAkagami/project-mumei.git
cd project-mumei
```

### 2. Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit and add your API keys
nano .env
```

Required environment variables:
```bash
# LLM Configuration (choose one)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
LLM_PROVIDER=openai  # or anthropic
LLM_MODEL=gpt-4      # or claude-3-opus-20240229

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379

# Agent Configuration
LOG_LEVEL=INFO
AGENT_TIMEOUT=300
```

### 3. Configure Scope
```bash
# Edit scope configuration
nano config/scope.json
```

Example scope configuration:
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

### 4. Start System
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Start all services
./scripts/start.sh
```

## 🎮 Usage

### Basic Commands

```bash
# Start the system
./scripts/start.sh

# Monitor all logs
docker-compose logs -f

# Monitor specific agent
docker-compose logs -f surface-mapper-active

# Check system status
docker-compose ps

# Stop the system
./scripts/stop.sh
```

### API Endpoints

```bash
# Health check
curl http://localhost:8000/health

# State summary
curl http://localhost:8000/state/summary | python3 -m json.tool

# Query hosts
curl http://localhost:8000/state/hosts | python3 -m json.tool

# Query vulnerabilities (CVSS >= 7.0)
curl "http://localhost:8000/state/vulnerabilities?min_cvss=7.0" | python3 -m json.tool

# Query compromised hosts
curl "http://localhost:8000/state/hosts?status=compromised" | python3 -m json.tool

# Export complete state
curl -X POST http://localhost:8000/state/export > results.json
```

### Scaling Agents

```bash
# Scale Surface Mappers
docker-compose up -d --scale surface-mapper-active=3

# Scale Service Profilers
docker-compose up -d --scale service-profiler-http=2
```

## 🔒 Security & Legal

### ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is designed for authorized security testing only.

- Only use on systems you **own** or have **explicit written permission** to test
- Unauthorized access to computer systems is **illegal**
- Users are **solely responsible** for complying with all applicable laws
- Configure scope carefully to avoid unauthorized testing
- Document all activities for audit trails

### Security Best Practices

1. **Scope Validation**: Always verify scope before starting
2. **Authorization**: Obtain written permission for all targets
3. **Monitoring**: Watch for defensive responses (WAF blocks, rate limiting)
4. **API Keys**: Store API keys securely, never commit to version control
5. **Evidence Handling**: Handle collected evidence with appropriate security
6. **Audit Logging**: Review logs regularly for compliance
7. **Stealth Mode**: Enable when testing production environments

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with inspiration from real-world penetration testing methodologies
- Powered by OpenAI GPT-4 and Anthropic Claude
- Utilizes the excellent Kali Linux tool suite
- Thanks to the security research community

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/RoninAkagami/project-mumei/issues)
- **Documentation**: See docs folder
- **Discussions**: [GitHub Discussions](https://github.com/RoninAkagami/project-mumei/discussions)
- **Contact**: [roninakagami@proton.me](mailto:roninakagami@proton.me)

---

**Project Mumei** - Next-generation autonomous penetration testing through collaborative multi-agent intelligence.

*Built by Sai Nideesh Kotagudem*

*a.k.a Ronin Akagami*
