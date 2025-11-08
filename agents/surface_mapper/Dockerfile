FROM kalilinux/kali-rolling

WORKDIR /app

# Install Python and penetration testing tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    dnsutils \
    host \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# Copy application code
COPY mumei/ ./mumei/
COPY agents/surface_mapper/ ./agents/surface_mapper/

# Create config directory
RUN mkdir -p /app/config

# Set Python path
ENV PYTHONPATH=/app

# Run Surface Mapper
CMD ["python3", "agents/surface_mapper/surface_mapper.py"]
