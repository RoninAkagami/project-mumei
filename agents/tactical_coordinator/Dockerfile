FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY mumei/ ./mumei/
COPY agents/tactical_coordinator/ ./agents/tactical_coordinator/

# Create config directory
RUN mkdir -p /app/config

# Set Python path
ENV PYTHONPATH=/app

# Run Tactical Coordinator
CMD ["python", "agents/tactical_coordinator/tactical_coordinator.py"]
