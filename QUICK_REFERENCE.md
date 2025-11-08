# Project Mumei - Quick Reference

## Essential Commands

### System Control
```bash
# Start system
./scripts/start.sh

# Stop system
./scripts/stop.sh

# Initialize engagement
./scripts/init_engagement.sh

# View all logs
docker-compose logs -f

# View specific agent
docker-compose logs -f [agent-name]
```

### Monitoring
```bash
# System status
docker-compose ps

# State summary
curl http://localhost:8000/state/summary | python3 -m json.tool

# Discovered hosts
curl http://localhost:8000/state/hosts | python3 -m json.tool

# Found vulnerabilities
curl http://localhost:8000/state/vulnerabilities | python3 -m json.tool

# Compromised hosts
curl "http://localhost:8000/state/hosts?status=compromised" | python3 -m json.tool

# Active sessions
curl "http://localhost:8000/state/sessions?active=true" | python3 -m json.tool

# Export complete state
curl -X POST http://localhost:8000/state/export > state_export.json
```

### Agent Names
- `redis` - Message bus
- `state-manager` - Global state management
- `tactical-coordinator` - Orchestration
- `surface-mapper-passive` - Passive reconnaissance
- `surface-mapper-active` - Active scanning
- `service-profiler-http` - Web vulnerability scanning
- `exploitation-engineer` - Exploitation
- `lateral-movement` - Post-exploitation (if configured)

### Scaling
```bash
# Scale Surface Mappers
docker-compose up -d --scale surface-mapper-active=3

# Scale Service Profilers
docker-compose up -d --scale service-profiler-http=2
```

## Configuration Files

### .env
```bash
OPENAI_API_KEY=your_key
ANTHROPIC_API_KEY=your_key
LLM_PROVIDER=openai
LLM_MODEL=gpt-4
LOG_LEVEL=INFO
```

### config/scope.json
```json
{
  "engagement_name": "Test Name",
  "targets": ["192.168.1.0/24"],
  "excluded": ["192.168.1.1"],
  "rules_of_engagement": {
    "max_concurrent_scans": 5,
    "stealth_mode": false
  }
}
```

## Event Types

- `SCAN_INITIATED` - Engagement started
- `HOST_FOUND` - Target discovered
- `SERVICE_DISCOVERED` - Port/service found
- `VULNERABILITY_IDENTIFIED` - Vulnerability detected
- `HOST_COMPROMISED` - Target exploited
- `CREDENTIAL_DISCOVERED` - Credentials found
- `PRIVILEGE_ESCALATED` - Privileges elevated
- `EXPLOITATION_FAILED` - Exploit failed
- `OPERATIONAL_ALERT` - Operational issue
- `AGENT_HEARTBEAT` - Agent health check
- `EVIDENCE_COLLECTED` - Evidence gathered

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/state` | GET | Complete state |
| `/state/summary` | GET | State summary |
| `/state/hosts` | GET | Query hosts |
| `/state/services` | GET | Query services |
| `/state/vulnerabilities` | GET | Query vulnerabilities |
| `/state/credentials` | GET | Get credentials |
| `/state/sessions` | GET | Query sessions |
| `/state/export` | POST | Export state |

## Troubleshooting

### Agents not starting
```bash
docker-compose logs [agent-name]
docker-compose ps
docker-compose restart [agent-name]
```

### Redis connection issues
```bash
docker-compose exec redis redis-cli ping
docker-compose restart redis
```

### State Manager not responding
```bash
curl http://localhost:8000/health
docker-compose logs state-manager
docker-compose restart state-manager
```

### LLM API errors
```bash
# Check API key
cat .env | grep API_KEY

# Check agent logs
docker-compose logs | grep -i "api"
```

### No events being published
```bash
# Check Tactical Coordinator
docker-compose logs tactical-coordinator

# Verify scope
cat config/scope.json | python3 -m json.tool

# Check Redis
docker-compose exec redis redis-cli
> SUBSCRIBE events:*
```

## File Locations

- **Agents**: `agents/[agent-name]/`
- **Shared Code**: `mumei/shared/`
- **Config**: `config/`
- **Scripts**: `scripts/`
- **Specs**: `.kiro/specs/mumei-multi-agent-pentest/`
- **Evidence**: `evidence/` (created at runtime)
- **Logs**: `docker-compose logs`

## Common Workflows

### Basic Scan
```bash
# 1. Configure
nano config/scope.json

# 2. Start
./scripts/start.sh

# 3. Monitor
docker-compose logs -f

# 4. Check results
curl http://localhost:8000/state/summary | python3 -m json.tool

# 5. Export
curl -X POST http://localhost:8000/state/export > results.json

# 6. Stop
./scripts/stop.sh
```

### Debug Agent
```bash
# View logs
docker-compose logs -f surface-mapper-active

# Restart agent
docker-compose restart surface-mapper-active

# Execute command in container
docker-compose exec surface-mapper-active bash

# Check environment
docker-compose exec surface-mapper-active env
```

### Monitor Progress
```bash
# Terminal 1: All logs
docker-compose logs -f

# Terminal 2: State summary (auto-refresh)
watch -n 5 'curl -s http://localhost:8000/state/summary | python3 -m json.tool'

# Terminal 3: Specific agent
docker-compose logs -f exploitation-engineer
```

## Performance Tips

1. **Adjust concurrency**: Edit `max_concurrent_scans` in scope.json
2. **Scale agents**: Use `docker-compose up -d --scale`
3. **Enable stealth**: Set `stealth_mode: true` for slower, stealthier scans
4. **Filter logs**: Use `docker-compose logs [agent] | grep [pattern]`
5. **Resource limits**: Add resource limits in docker-compose.yml

## Security Checklist

- [ ] Verify scope configuration
- [ ] Confirm authorization for all targets
- [ ] Review rules of engagement
- [ ] Enable stealth mode if needed
- [ ] Monitor for defensive responses
- [ ] Document all activities
- [ ] Export state regularly
- [ ] Secure API keys
- [ ] Review findings before reporting

## Quick Debugging

```bash
# Is Docker running?
docker info

# Are containers up?
docker-compose ps

# Is Redis working?
docker-compose exec redis redis-cli ping

# Is State Manager responding?
curl http://localhost:8000/health

# Are agents publishing events?
docker-compose exec redis redis-cli
> SUBSCRIBE events:*

# Check agent environment
docker-compose exec [agent-name] env | grep -E "REDIS|LLM|AGENT"

# Rebuild everything
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Support

- **Documentation**: See SETUP_AND_USAGE.md
- **Architecture**: See README.md
- **Implementation**: See IMPLEMENTATION_COMPLETE.md
- **Specs**: See .kiro/specs/mumei-multi-agent-pentest/

## Legal Notice

⚠️ Only use on authorized targets. Unauthorized access is illegal.
