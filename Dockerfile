
FROM node:20-bookworm-slim

# Install Python, pip, and tools needed by scanners
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    python3-pip \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Node.js production dependencies
COPY Backend/package*.json ./Backend/
WORKDIR /app/Backend
RUN npm ci --omit=dev

# Create Linux Python environment
RUN python3 -m venv /opt/venv

ENV PATH="/opt/venv/bin:${PATH}"
ENV PYTHON_PATH="/opt/venv/bin/python"
ENV GITLEAKS_PATH="/usr/local/bin/gitleaks"
ENV NODE_ENV="production"

# Install Python scanners
COPY Backend/python-scanner/requirements.txt ./python-scanner/
RUN pip install --no-cache-dir -r ./python-scanner/requirements.txt

# Install Gitleaks
RUN ARCH="$(dpkg --print-architecture)" && \
    case "$ARCH" in \
      amd64) GITLEAKS_ARCH="x64" ;; \
      arm64) GITLEAKS_ARCH="arm64" ;; \
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;; \
    esac && \
    curl -sSfL \
      "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${GITLEAKS_ARCH}.tar.gz" \
      -o /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    rm /tmp/gitleaks.tar.gz

# Copy backend source
COPY Backend/ ./

# Create runtime directories
RUN mkdir -p uploads reports temp

EXPOSE 5000

CMD ["node", "server.js"]
