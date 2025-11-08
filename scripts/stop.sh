#!/bin/bash
# Shutdown script for Project Mumei

set -e

echo "========================================="
echo "  Project Mumei - Stopping System"
echo "========================================="
echo ""

# Export final state before shutdown
echo "Exporting final state..."
curl -s -X POST http://localhost:8000/state/export -o final_state_$(date +%Y%m%d_%H%M%S).json || true

echo "Stopping all containers..."
docker-compose down

echo ""
echo "========================================="
echo "  System Stopped Successfully!"
echo "========================================="
echo ""
