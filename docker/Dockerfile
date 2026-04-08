FROM python:3.11-slim

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Install gitnexus (local tool — adjust path if binary is elsewhere)
# If gitnexus is distributed as an npm package or binary, install here:
# RUN npm install -g gitnexus
# Or copy the binary:
# COPY --from=gitnexus-build /usr/local/bin/gitnexus /usr/local/bin/gitnexus

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install semgrep
RUN pip install --no-cache-dir semgrep

COPY . .

# Create output directories
RUN mkdir -p pentest_logs/checkpoints pentest_logs/audit_trail pentest_logs/output

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s \
    CMD python -c "import core.state; print('ok')" || exit 1

ENTRYPOINT ["python", "main.py"]
