#!/bin/bash
# Startup script for Project Mumei

set -e

echo "========================================="
echo "  Project Mumei - Starting System"
echo "========================================="
echo ""

# Check if .env file exists
if [ ! -f .env ]; then
    echo "ERROR: .env file not found!"
    echo "Please copy .env.example to .env and configure it."
    exit 1
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker is not running!"
    echo "Please start Docker and try again."
    exit 1
fi

# Build images
echo "Building Docker images..."
docker-compose build

# Start Redis first
echo ""
echo "Starting Redis..."
docker-compose up -d redis

# Wait for Redis to be ready
echo "Waiting for Redis to be ready..."
sleep 5

# Check Redis health
until docker-compose exec -T redis redis-cli ping > /dev/null 2>&1; do
    echo "Waiting for Redis..."
    sleep 2
done
echo "Redis is ready!"

# Start State Manager
echo ""
echo "Starting State Manager..."
docker-compose up -d state-manager

# Wait for State Manager to be ready
echo "Waiting for State Manager to be ready..."
sleep 5

# Check State Manager health
until curl -s http://localhost:8000/health > /dev/null 2>&1; do
    echo "Waiting for State Manager..."
    sleep 2
done
echo "State Manager is ready!"

# Start all other agents
echo ""
echo "Starting all agents..."
docker-compose up -d

# Wait a bit for agents to initialize
sleep 5

# Show status
echo ""
echo "========================================="
echo "  System Status"
echo "========================================="
docker-compose ps

echo ""
echo "========================================="
echo "  System Started Successfully!"
echo "========================================="
echo ""
echo "State Manager API: http://localhost:8000"
echo "View logs: docker-compose logs -f"
echo "Stop system: ./scripts/stop.sh"
echo ""
