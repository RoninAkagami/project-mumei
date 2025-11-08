# Project Mumei - Deployment Checklist

## Pre-Deployment Checklist

### ✅ System Requirements
- [ ] Docker installed and running
- [ ] Docker Compose installed
- [ ] At least 8GB RAM available
- [ ] At least 20GB disk space
- [ ] Network connectivity
- [ ] Linux/macOS/Windows with WSL2

### ✅ API Keys
- [ ] OpenAI API key obtained (or Anthropic)
- [ ] API key has sufficient credits
- [ ] API key tested and working

### ✅ Configuration
- [ ] `.env` file created from `.env.example`
- [ ] API keys added to `.env`
- [ ] LLM provider configured (openai/anthropic)
- [ ] LLM model specified (gpt-4/claude-3-opus)
- [ ] Log level set appropriately

### ✅ Scope Definition
- [ ] `config/scope.json` reviewed
- [ ] Target systems specified
- [ ] Excluded systems listed
- [ ] Rules of engagement defined
- [ ] Authorization obtained for all targets

### ✅ Legal & Authorization
- [ ] Written authorization obtained
- [ ] Scope approved by stakeholders
- [ ] Rules of engagement agreed upon
- [ ] Legal compliance verified
- [ ] Incident response plan in place

## Deployment Steps

### Step 1: Initial Setup
```bash
# Clone or navigate to project
cd project-mumei

# Copy environment template
cp .env.example .env

# Edit .env with your API keys
nano .env
```

**Verify**:
- [ ] `.env` file exists
- [ ] API keys are set
- [ ] No syntax errors in `.env`

### Step 2: Configure Scope
```bash
# Edit scope configuration
nano config/scope.json
```

**Verify**:
- [ ] Valid JSON syntax
- [ ] Targets are correct
- [ ] Exclusions are listed
- [ ] Rules of engagement set

**Validate**:
```bash
cat config/scope.json | python3 -m json.tool
```

### Step 3: Build Images
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Build Docker images
docker-compose build
```

**Verify**:
- [ ] All images built successfully
- [ ] No build errors
- [ ] Images appear in `docker images`

### Step 4: Start System
```bash
# Start all services
./scripts/start.sh
```

**Verify**:
- [ ] Redis started
- [ ] State Manager started
- [ ] All agents started
- [ ] No error messages

**Check Status**:
```bash
docker-compose ps
```

All services should show "Up" status.

### Step 5: Verify Health
```bash
# Check State Manager
curl http://localhost:8000/health

# Check Redis
docker-compose exec redis redis-cli ping

# Check logs
docker-compose logs --tail=50
```

**Verify**:
- [ ] State Manager returns healthy
- [ ] Redis responds with PONG
- [ ] No error messages in logs
- [ ] Agents are connected

### Step 6: Initialize Engagement
```bash
# Initialize the engagement
./scripts/init_engagement.sh
```

**Verify**:
- [ ] Scope loaded successfully
- [ ] Tactical Coordinator started
- [ ] ScanInitiated event published

### Step 7: Monitor Operation
```bash
# Monitor all logs
docker-compose logs -f

# Or monitor specific agents
docker-compose logs -f tactical-coordinator
docker-compose logs -f surface-mapper-active
```

**Monitor For**:
- [ ] HostFound events
- [ ] ServiceDiscovered events
- [ ] VulnerabilityIdentified events
- [ ] No error messages

### Step 8: Check Progress
```bash
# Check state summary
curl http://localhost:8000/state/summary | python3 -m json.tool

# Check discovered hosts
curl http://localhost:8000/state/hosts | python3 -m json.tool

# Check vulnerabilities
curl http://localhost:8000/state/vulnerabilities | python3 -m json.tool
```

**Verify**:
- [ ] Hosts being discovered
- [ ] Services being identified
- [ ] State updating correctly

## During Operation

### Monitoring Checklist
- [ ] Monitor logs continuously
- [ ] Check for error messages
- [ ] Verify agents are active
- [ ] Watch for defensive responses
- [ ] Monitor resource usage
- [ ] Check API rate limits

### Health Checks
```bash
# Every 5 minutes
curl http://localhost:8000/health

# Check agent heartbeats
docker-compose logs | grep heartbeat | tail -20

# Check resource usage
docker stats
```

### Troubleshooting
If issues occur:
1. Check TROUBLESHOOTING.md
2. Review agent logs
3. Verify Redis connectivity
4. Check API key validity
5. Restart affected services

## Post-Operation

### Step 1: Export Results
```bash
# Export final state
curl -X POST http://localhost:8000/state/export > results_$(date +%Y%m%d_%H%M%S).json

# Or use stop script (exports automatically)
./scripts/stop.sh
```

**Verify**:
- [ ] State exported successfully
- [ ] JSON file is valid
- [ ] All findings captured

### Step 2: Review Findings
```bash
# View results
cat results_*.json | python3 -m json.tool | less

# Count findings
cat results_*.json | jq '.hosts | length'
cat results_*.json | jq '.vulnerabilities | length'
```

**Review**:
- [ ] All hosts discovered
- [ ] All services identified
- [ ] Vulnerabilities documented
- [ ] Evidence collected

### Step 3: Stop System
```bash
# Graceful shutdown
./scripts/stop.sh
```

**Verify**:
- [ ] All containers stopped
- [ ] State exported
- [ ] No errors during shutdown

### Step 4: Cleanup (Optional)
```bash
# Remove containers
docker-compose down

# Remove volumes (WARNING: deletes data)
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

## Validation Checklist

### Before Deployment
- [ ] All tests pass: `pytest`
- [ ] Configuration validated
- [ ] Authorization obtained
- [ ] Scope approved
- [ ] Team notified

### During Deployment
- [ ] All services started
- [ ] Health checks pass
- [ ] Agents connected
- [ ] Events flowing
- [ ] State updating

### After Deployment
- [ ] Results exported
- [ ] Findings reviewed
- [ ] Evidence collected
- [ ] System stopped cleanly
- [ ] Documentation updated

## Security Checklist

### Pre-Deployment Security
- [ ] API keys secured
- [ ] Scope validated
- [ ] Authorization verified
- [ ] Network isolated
- [ ] Logging enabled

### During Operation Security
- [ ] Monitor for defensive responses
- [ ] Stay within scope
- [ ] Respect rate limits
- [ ] Document all actions
- [ ] Handle evidence securely

### Post-Operation Security
- [ ] Secure results
- [ ] Clean up artifacts
- [ ] Remove temporary files
- [ ] Secure API keys
- [ ] Archive logs

## Compliance Checklist

### Legal Compliance
- [ ] Written authorization obtained
- [ ] Scope documented
- [ ] Rules of engagement signed
- [ ] Incident response plan ready
- [ ] Legal counsel consulted

### Operational Compliance
- [ ] Scope enforced
- [ ] Exclusions respected
- [ ] Time windows observed
- [ ] Destructive tests controlled
- [ ] DoS tests avoided

### Documentation Compliance
- [ ] All actions logged
- [ ] Findings documented
- [ ] Evidence preserved
- [ ] Timeline recorded
- [ ] Report prepared

## Emergency Procedures

### If System Becomes Unstable
1. Stop all agents: `docker-compose stop`
2. Export current state
3. Review logs for errors
4. Fix issues
5. Restart: `./scripts/start.sh`

### If Defensive Response Detected
1. Pause operations: `docker-compose pause`
2. Review logs
3. Adjust strategy
4. Enable stealth mode
5. Resume: `docker-compose unpause`

### If Scope Violation Suspected
1. **STOP IMMEDIATELY**: `./scripts/stop.sh`
2. Export state
3. Review all targets
4. Verify scope
5. Report to stakeholders

## Success Criteria

### Deployment Success
- [ ] All services running
- [ ] No errors in logs
- [ ] Agents communicating
- [ ] State updating
- [ ] API responding

### Operation Success
- [ ] Targets discovered
- [ ] Services identified
- [ ] Vulnerabilities found
- [ ] Evidence collected
- [ ] No scope violations

### Completion Success
- [ ] Results exported
- [ ] Findings documented
- [ ] System stopped cleanly
- [ ] Data secured
- [ ] Report ready

## Quick Reference

### Start System
```bash
./scripts/start.sh
```

### Check Status
```bash
docker-compose ps
curl http://localhost:8000/health
```

### View Logs
```bash
docker-compose logs -f
```

### Check Progress
```bash
curl http://localhost:8000/state/summary | python3 -m json.tool
```

### Stop System
```bash
./scripts/stop.sh
```

### Emergency Stop
```bash
docker-compose down
```

## Support

If you encounter issues:
1. Check TROUBLESHOOTING.md
2. Review logs: `docker-compose logs`
3. Verify configuration
4. Check documentation
5. Review error messages

## Final Checklist

Before declaring deployment complete:
- [ ] System deployed successfully
- [ ] All health checks pass
- [ ] Monitoring in place
- [ ] Team notified
- [ ] Documentation updated
- [ ] Backup plan ready
- [ ] Emergency procedures reviewed
- [ ] Success criteria met

---

**Deployment Status**: Ready for Production  
**Last Updated**: November 7, 2025  
**Version**: 1.0  

✅ **SYSTEM READY FOR DEPLOYMENT**
