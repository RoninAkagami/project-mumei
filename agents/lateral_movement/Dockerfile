FROM kalilinux/kali-rolling

WORKDIR /app

# Install Python and post-exploitation tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    netcat-traditional \
    iproute2 \
    iputils-ping \
    exploitdb \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# Copy application code
COPY mumei/ ./mumei/
COPY agents/lateral_movement/ ./agents/lateral_movement/

# Create config directory
RUN mkdir -p /app/config

# Set Python path
ENV PYTHONPATH=/app

# Run Lateral Movement Agent
CMD ["python3", "agents/lateral_movement/lateral_movement.py"]
