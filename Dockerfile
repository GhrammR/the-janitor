FROM python:3.11-slim

# 1. Install System Dependencies + Node.js
RUN apt-get update && apt-get install -y \
    gcc g++ curl python3-dev build-essential \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3. Copy source code (Respects .dockerignore)
COPY . .

# 4. Setup Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 5. Install the Janitor package
RUN pip install .

ENTRYPOINT ["/entrypoint.sh"]