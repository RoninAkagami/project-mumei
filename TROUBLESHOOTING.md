# Project Mumei - Troubleshooting Guide

## Common Issues and Solutions

### 1. Docker Issues

#### Docker Not Running
**Symptom**: `Cannot connect to the Docker daemon`

**Solution**:
```bash
# Check Docker status
docker info

# Start Docker (Linux)
sudo systemctl start docker

# Start Docker (macOS)
open -a Docker

# Start Docker (Windows)
# Start Docker Desktop from Start Menu
```

#### Permission Denied
**Symptom**: `permission denied while trying to connect to the Docker daemon socket`

**Solution**:
```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker

# Or run with sudo
sudo docker-compose up -d
```

#### Port Already in Use
**Symptom**: `Bind for 0.0.0.0:6379 failed: port is already allocated`

**Solution**:
```bash
# Find process using the port
lsof -i :6379  # Linux/macOS
netstat -ano | findstr :6379  # Windows

# Stop the process or change port in docker-compose.yml
```

### 2. Redis Issues

#### Redis Not Starting
**Symptom**: `Could not connect to Redis at localhost:6379`

**Solution**:
```bash
# Check Redis container
docker-compose ps redis

# View Redis logs
docker-compose logs redis

# Restart Redis
docker-compose restart redis

# Test Redis connection
docker-compose exec redis redis-cli ping
# Should return: PONG
```

#### Redis Connection Timeout
**Symptom**: `Redis connection timeout`

**Solution**:
```bash
# Check if Redis is healthy
docker-compose exec redis redis-cli ping

# Check network connectivity
docker-compose exec tactical-coordinator ping redis

# Restart all services
docker-compose restart
```

### 3. State Manager Issues

#### State Manager Not Responding
**Symptom**: `curl: (7) Failed to connect to localhost port 8000`

**Solution**:
```bash
# Check if State Manager is running
docker-compose ps state-manager

# View State Manager logs
docker-compose logs state-manager

# Check for errors
docker-compose logs state-manager | grep -i error

# Restart State Manager
docker-compose restart state-manager

# Wait for it to be ready
sleep 5
curl http://localhost:8000/health
```

#### State Not Initialized
**Symptom**: `{"detail":"State not initialized"}`

**Solution**:
```bash
# Check if Tactical Coordinator has started
docker-compose logs tactical-coordinator

# Verify scope.json exists and is valid
cat config/scope.json | python3 -m json.tool

# Restart Tactical Coordinator
docker-compose restart tactical-coordinator
```

### 4. LLM API Issues

#### API Key Not Set
**Symptom**: `OPENAI_API_KEY environment variable not set`

**Solution**:
```bash
# Check .env file exists
ls -la .env

# Verify API key is set
cat .env | grep API_KEY

# If missing, add it
echo "OPENAI_API_KEY=your_key_here" >> .env

# Restart services
docker-compose restart
```

#### API Rate Limit
**Symptom**: `Rate limit exceeded`

**Solution**:
```bash
# Reduce concurrent operations in scope.json
nano config/scope.json
# Set "max_concurrent_scans": 2

# Enable rate limiting
# Set "rate_limit_delay": 2.0

# Restart services
docker-compose restart
```

#### Invalid API Key
**Symptom**: `Incorrect API key provided`

**Solution**:
```bash
# Verify API key is correct
cat .env | grep API_KEY

# Test API key manually
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer YOUR_API_KEY"

# Update .env with correct key
nano .env

# Restart services
docker-compose restart
```

### 5. Agent Issues

#### Agent Not Starting
**Symptom**: Agent container exits immediately

**Solution**:
```bash
# Check agent logs
docker-compose logs [agent-name]

# Look for Python errors
docker-compose logs [agent-name] | grep -i "error\|exception"

# Check if dependencies are installed
docker-compose exec [agent-name] pip list

# Rebuild the image
docker-compose build [agent-name]
docker-compose up -d [agent-name]
```

#### Agent Not Publishing Events
**Symptom**: No events appearing in logs

**Solution**:
```bash
# Check if agent is connected to Redis
docker-compose logs [agent-name] | grep -i "redis\|connected"

# Monitor Redis for events
docker-compose exec redis redis-cli
> SUBSCRIBE events:*
# Press Ctrl+C to exit

# Check agent heartbeats
docker-compose logs | grep heartbeat

# Restart the agent
docker-compose restart [agent-name]
```

#### Agent Crashes
**Symptom**: Agent container keeps restarting

**Solution**:
```bash
# View crash logs
docker-compose logs [agent-name] --tail=100

# Check for memory issues
docker stats

# Check for tool errors
docker-compose logs [agent-name] | grep -i "command\|failed"

# Increase timeout in .env
echo "AGENT_TIMEOUT=600" >> .env
docker-compose restart
```

### 6. Network Scanning Issues

#### Nmap Not Found
**Symptom**: `nmap: command not found`

**Solution**:
```bash
# Check if nmap is installed in container
docker-compose exec surface-mapper-active which nmap

# If missing, rebuild image
docker-compose build surface-mapper-active

# Or install manually (temporary)
docker-compose exec surface-mapper-active apt-get update
docker-compose exec surface-mapper-active apt-get install -y nmap
```

#### Permission Denied for Raw Sockets
**Symptom**: `You requested a scan type which requires root privileges`

**Solution**:
```bash
# Add NET_RAW capability in docker-compose.yml
# (Already configured in the provided docker-compose.yml)

# Verify capabilities
docker-compose exec surface-mapper-active capsh --print

# If still failing, run specific scans without raw sockets
# Use -sT instead of -sS in nmap commands
```

#### Scan Timeout
**Symptom**: `Command timed out after 300s`

**Solution**:
```bash
# Increase timeout in .env
echo "AGENT_TIMEOUT=600" >> .env

# Or reduce scan scope
nano config/scope.json
# Reduce target range or use specific IPs

# Restart services
docker-compose restart
```

### 7. Exploitation Issues

#### Metasploit Not Working
**Symptom**: `msfconsole: command not found`

**Solution**:
```bash
# Check if Metasploit is installed
docker-compose exec exploitation-engineer which msfconsole

# Initialize Metasploit database
docker-compose exec exploitation-engineer msfdb init

# Rebuild image if needed
docker-compose build exploitation-engineer
```

#### Exploit Fails
**Symptom**: `Exploitation failed` events

**Solution**:
```bash
# Check exploitation logs
docker-compose logs exploitation-engineer

# Verify target is actually vulnerable
# Manually test the vulnerability

# Check if exploit module exists
docker-compose exec exploitation-engineer msfconsole -q -x "search CVE-XXXX-XXXX; exit"

# Review LLM suggestions
docker-compose logs exploitation-engineer | grep "LLM"
```

### 8. Configuration Issues

#### Invalid Scope Configuration
**Symptom**: `JSON decode error` or scope validation fails

**Solution**:
```bash
# Validate JSON syntax
cat config/scope.json | python3 -m json.tool

# Check for common issues:
# - Missing commas
# - Trailing commas
# - Unquoted strings
# - Invalid IP ranges

# Use the example as template
cp config/scope.json config/scope.json.backup
# Edit carefully
nano config/scope.json
```

#### Environment Variables Not Loading
**Symptom**: Agents using default values instead of .env

**Solution**:
```bash
# Verify .env file location (must be in project root)
ls -la .env

# Check .env format (no spaces around =)
cat .env

# Restart services to reload environment
docker-compose down
docker-compose up -d

# Verify environment in container
docker-compose exec tactical-coordinator env | grep -E "REDIS|LLM|AGENT"
```

### 9. Performance Issues

#### System Running Slow
**Symptom**: High CPU/memory usage, slow responses

**Solution**:
```bash
# Check resource usage
docker stats

# Reduce concurrent operations
nano config/scope.json
# Set "max_concurrent_scans": 2

# Scale down agents
docker-compose up -d --scale surface-mapper-active=1

# Add resource limits in docker-compose.yml
# resources:
#   limits:
#     cpus: '1.0'
#     memory: 2G
```

#### Redis Memory Issues
**Symptom**: Redis using too much memory

**Solution**:
```bash
# Check Redis memory usage
docker-compose exec redis redis-cli INFO memory

# Clear old data if needed
docker-compose exec redis redis-cli FLUSHDB

# Restart engagement
./scripts/stop.sh
./scripts/start.sh
```

### 10. Data Issues

#### No Hosts Discovered
**Symptom**: State shows 0 hosts after scanning

**Solution**:
```bash
# Check if Surface Mapper is running
docker-compose logs surface-mapper-active

# Verify targets are reachable
ping [target-ip]

# Check scope configuration
cat config/scope.json

# Monitor for HostFound events
docker-compose exec redis redis-cli
> SUBSCRIBE events:host_found

# Check for errors
docker-compose logs surface-mapper-active | grep -i error
```

#### No Vulnerabilities Found
**Symptom**: Services discovered but no vulnerabilities

**Solution**:
```bash
# Check if Service Profiler is running
docker-compose logs service-profiler-http

# Verify tools are working
docker-compose exec service-profiler-http nikto -Version

# Check if services match profiler filters
curl http://localhost:8000/state/services | python3 -m json.tool

# Monitor for VulnerabilityIdentified events
docker-compose exec redis redis-cli
> SUBSCRIBE events:vulnerability_identified
```

#### State Not Updating
**Symptom**: State Manager shows old data

**Solution**:
```bash
# Check State Manager logs
docker-compose logs state-manager | grep -i "update\|event"

# Verify events are being published
docker-compose exec redis redis-cli
> SUBSCRIBE events:*

# Check Redis connection
docker-compose exec state-manager redis-cli -h redis ping

# Restart State Manager
docker-compose restart state-manager
```

## Debugging Commands

### View All Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f [service-name]

# Last 100 lines
docker-compose logs --tail=100 [service-name]

# Follow with grep
docker-compose logs -f | grep -i "error\|warning"
```

### Check Service Status
```bash
# All services
docker-compose ps

# Specific service
docker-compose ps [service-name]

# Detailed inspect
docker inspect [container-name]
```

### Execute Commands in Containers
```bash
# Open shell
docker-compose exec [service-name] bash

# Run single command
docker-compose exec [service-name] [command]

# Check environment
docker-compose exec [service-name] env

# Check network
docker-compose exec [service-name] ping redis
```

### Monitor Redis
```bash
# Connect to Redis CLI
docker-compose exec redis redis-cli

# Monitor all commands
> MONITOR

# Subscribe to all events
> PSUBSCRIBE events:*

# Check keys
> KEYS *

# Get state
> GET state:global
```

### Check State Manager API
```bash
# Health check
curl http://localhost:8000/health

# State summary
curl http://localhost:8000/state/summary | python3 -m json.tool

# Specific queries
curl "http://localhost:8000/state/hosts?status=compromised" | python3 -m json.tool
curl "http://localhost:8000/state/vulnerabilities?min_cvss=7.0" | python3 -m json.tool
```

## Complete Reset

If all else fails, perform a complete reset:

```bash
# 1. Stop everything
docker-compose down

# 2. Remove volumes (WARNING: deletes all data)
docker-compose down -v

# 3. Remove images
docker-compose down --rmi all

# 4. Clean Docker system
docker system prune -a

# 5. Rebuild from scratch
docker-compose build --no-cache

# 6. Start fresh
./scripts/start.sh
```

## Getting Help

### Check Logs First
Always start by checking logs:
```bash
docker-compose logs [service-name] | grep -i "error\|exception\|failed"
```

### Verify Configuration
Check all configuration files:
```bash
# Environment
cat .env

# Scope
cat config/scope.json | python3 -m json.tool

# Docker Compose
docker-compose config
```

### Test Components Individually
Test each component:
```bash
# Redis
docker-compose exec redis redis-cli ping

# State Manager
curl http://localhost:8000/health

# Agent connectivity
docker-compose exec tactical-coordinator ping redis
```

### Enable Debug Logging
```bash
# Set debug level in .env
echo "LOG_LEVEL=DEBUG" >> .env

# Restart services
docker-compose restart

# View debug logs
docker-compose logs -f | grep DEBUG
```

## Prevention Tips

1. **Always validate configuration files** before starting
2. **Check Docker resources** are sufficient
3. **Monitor logs** during first run
4. **Start with small scope** for testing
5. **Verify API keys** are correct
6. **Keep Docker updated** to latest version
7. **Review documentation** before making changes
8. **Backup .env and config files** before editing
9. **Test in lab environment** first
10. **Document any custom changes**

## Still Having Issues?

1. Check all documentation files
2. Review the SETUP_AND_USAGE.md guide
3. Verify system requirements are met
4. Try the complete reset procedure
5. Check Docker and system logs
6. Verify network connectivity
7. Test with minimal configuration
8. Review error messages carefully

Remember: Most issues are configuration-related. Double-check your .env and config/scope.json files!
