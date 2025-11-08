FROM kalilinux/kali-rolling

WORKDIR /app

# Install Python, Metasploit, and exploitation tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    metasploit-framework \
    exploitdb \
    sqlmap \
    hydra \
    john \
    hashcat \
    netcat-traditional \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Initialize Metasploit database
RUN msfdb init || true

# Copy requirements
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# Copy application code
COPY mumei/ ./mumei/
COPY agents/exploitation_engineer/ ./agents/exploitation_engineer/

# Create directories
RUN mkdir -p /app/config /app/evidence

# Set Python path
ENV PYTHONPATH=/app

# Run Exploitation Engineer
CMD ["python3", "agents/exploitation_engineer/exploitation_engineer.py"]
