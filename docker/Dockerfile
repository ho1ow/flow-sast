# ─────────────────────────────────────────────────────────────────────────────
# flow-sast — Main application image
# Base: python:3.11-slim
#
# Tools installed:
#   - Semgrep      (pip)          — SAST taint analysis
#   - Gitleaks     (binary)       — secret detection  
#   - GitNexus     (npm -g)       — code-graph query + context
#   - Node.js LTS  (NodeSource)   — required by GitNexus
#   - Python deps  (requirements.txt)
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: dependency builder ───────────────────────────────────────────────
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Install Python deps into a prefix dir (for copy to final stage)
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Install Semgrep (needs build tools on some wheels)
RUN pip install --no-cache-dir --prefix=/install semgrep


# ── Stage 2: final runtime image ─────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="flow-sast"
LABEL org.opencontainers.image.description="Automated SAST + AI Verification Pipeline"
LABEL org.opencontainers.image.source="https://github.com/ho1ow/flow-sast"
LABEL org.opencontainers.image.version="1.0.0"

# ── System packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        wget \
        ca-certificates \
        gnupg \
        file \
    && rm -rf /var/lib/apt/lists/*

# ── Node.js LTS (required by GitNexus) ───────────────────────────────────────
ARG NODE_MAJOR=22
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && node --version \
    && npm --version

# ── Gitleaks: secret scanner ──────────────────────────────────────────────────
ARG GITLEAKS_VERSION=8.21.2
RUN set -eux; \
    ARCH=$(uname -m); \
    case "$ARCH" in \
        x86_64)  GITLEAKS_ARCH="x64" ;; \
        aarch64) GITLEAKS_ARCH="arm64" ;; \
        *)       GITLEAKS_ARCH="x64" ;; \
    esac; \
    curl -sSL \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" \
        -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /tmp gitleaks \
    && mv /tmp/gitleaks /usr/local/bin/gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && gitleaks version

# ── GitNexus: code-graph query tool (npm package) ────────────────────────────
RUN npm install -g gitnexus \
    && gitnexus --version

# ── Python packages from builder stage ───────────────────────────────────────
COPY --from=builder /install /usr/local

# ── App source ────────────────────────────────────────────────────────────────
WORKDIR /app

# Copy source (excluding docker/, .env, reports via .dockerignore)
COPY . .

# Create output directories
RUN mkdir -p \
        reports \
        pentest_logs/audit_trail \
        pentest_logs/checkpoints \
    && chmod -R 777 reports pentest_logs

# ── Non-root user ─────────────────────────────────────────────────────────────
RUN groupadd --gid 1001 flowsast \
    && useradd --uid 1001 --gid 1001 --no-create-home flowsast \
    && chown -R flowsast:flowsast /app

USER flowsast

# ── Health check ──────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import phases; print('ok')" || exit 1

# ── Runtime defaults (override in docker-compose or CLI) ─────────────────────
# --repo is mounted via volume at /repo
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
