FROM python:3.11-slim

# 1. Install System Dependencies + Node.js
RUN apt-get update && apt-get install -y \
    gcc g++ curl python3-dev build-essential \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. Set Python path for absolute imports
ENV PYTHONPATH=/app

# 3. Install Python dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy source code (Respects .dockerignore)
COPY . .

# 5. Setup Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 6. Install the Janitor package
RUN pip install .

ENTRYPOINT ["/entrypoint.sh"]