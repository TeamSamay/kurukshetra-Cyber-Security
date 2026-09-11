# Multi-stage lightweight Honeypot Container
FROM python:3.11-slim

# Set work directory
WORKDIR /app

# Prevent Python from writing .pyc and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iputils-ping \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Install python requirements
COPY requirements.txt .
RUN pip install --default-timeout=120 --retries 5 --no-cache-dir -r requirements.txt

# Copy honeypot codebase
COPY honeypot /app/honeypot
COPY main.py /app/main.py
COPY mock_backend.py /app/mock_backend.py
COPY generate_report.py /app/generate_report.py

# Create logs & reports directory
RUN mkdir -p /app/logs /app/reports

# Expose Honeypot ports (SSH: 2222, Web/API: 8080, Backend: 8000)
EXPOSE 2222 8080 8000

# Run honeypot orchestrator
CMD ["python", "main.py"]
