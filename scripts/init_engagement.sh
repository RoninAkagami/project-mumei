#!/bin/bash
# Initialize a penetration test engagement

set -e

echo "========================================="
echo "  Project Mumei - Initialize Engagement"
echo "========================================="
echo ""

# Check if scope file exists
if [ ! -f config/scope.json ]; then
    echo "ERROR: config/scope.json not found!"
    echo "Please create a scope configuration file."
    exit 1
fi

# Display scope
echo "Engagement Scope:"
echo "-----------------"
cat config/scope.json | python3 -m json.tool
echo ""

# Confirm with user
read -p "Start engagement with this scope? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Engagement cancelled."
    exit 0
fi

# Check if system is running
if ! docker-compose ps | grep -q "Up"; then
    echo "ERROR: System is not running!"
    echo "Please start the system first: ./scripts/start.sh"
    exit 1
fi

# Trigger Tactical Coordinator to start scan
echo ""
echo "Initializing engagement..."
echo "The Tactical Coordinator will parse the scope and initiate scanning."
echo ""

# In a full implementation, we would send a message to trigger the coordinator
# For now, the coordinator automatically loads scope.json on startup

echo "Engagement initialized!"
echo ""
echo "Monitor progress:"
echo "  - View logs: docker-compose logs -f tactical-coordinator"
echo "  - Check state: curl http://localhost:8000/state/summary"
echo "  - View all logs: docker-compose logs -f"
echo ""
