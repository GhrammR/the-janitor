# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# 1. Install System Dependencies + Node.js (Includes NPM)
# gcc/g++ are required for tree-sitter C-bindings
RUN apt-get update && apt-get install -y \
    gcc g++ \
    curl && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# 2. Install Python dependencies (Cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3. Copy the rest of the code AND the entrypoint script
COPY . .

# 4. Make the entrypoint executable
# (Check if file exists to be safe, though COPY puts it there)
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 5. Install the tool in editable mode
RUN pip install -e .

# 6. Define the final wrapper as the entry point
ENTRYPOINT ["/entrypoint.sh"]