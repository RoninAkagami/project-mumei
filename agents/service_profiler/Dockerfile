FROM kalilinux/kali-rolling

WORKDIR /app

# Install Python and penetration testing tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    nikto \
    gobuster \
    sqlmap \
    wpscan \
    sslscan \
    whatweb \
    enum4linux \
    smbclient \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# Copy application code
COPY mumei/ ./mumei/
COPY agents/service_profiler/ ./agents/service_profiler/

# Create config directory
RUN mkdir -p /app/config

# Set Python path
ENV PYTHONPATH=/app

# Run Service Profiler
CMD ["python3", "agents/service_profiler/service_profiler.py"]
