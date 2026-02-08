FROM python:3.11-slim
LABEL version="3.9.1"

# Environment variables (prevent .pyc files and enable unbuffered output)
ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies + Node.js in a single layer
# Clean up immediately to minimize image size
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ curl build-essential \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy requirements first for layer caching
COPY requirements.txt .

# Install Python dependencies with no cache
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code (respects .dockerignore)
COPY . .

# Setup entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Install Janitor package with no cache
RUN pip install --no-cache-dir .

ENTRYPOINT ["/entrypoint.sh"]