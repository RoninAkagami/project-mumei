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
COPY agents/state_manager/ ./agents/state_manager/

# Create directories
RUN mkdir -p /app/config /app/evidence

# Set Python path
ENV PYTHONPATH=/app

# Expose API port
EXPOSE 8000

# Run State Manager
CMD ["python", "agents/state_manager/main.py"]
