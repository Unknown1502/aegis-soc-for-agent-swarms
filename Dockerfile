# ============================================================================
# AEGIS - container image for the API + guard runtime.
# Multi-stage build: builds the React dashboard first, then bundles it into
# the Python image so a single container serves API + static UI on port 8088.
# ============================================================================

# --- Stage 1: build the dashboard ------------------------------------------
FROM node:20-alpine AS dashboard-build
WORKDIR /dashboard
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY dashboard/ ./
# Bake the API URL into the bundle at build time. In production we serve
# both the API and the dashboard from the same origin, so VITE_AEGIS_API
# points at the empty string (i.e. relative paths against current host).
RUN echo "VITE_AEGIS_API=" > .env.production
RUN npm run build

# --- Stage 2: AEGIS Python runtime -----------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    AEGIS_API_HOST=0.0.0.0 \
    AEGIS_API_PORT=8088 \
    AEGIS_ENV=production \
    AEGIS_LOG_LEVEL=INFO

WORKDIR /app

# Build deps (kept minimal; only what wheels need)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first for layer caching
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install .

# Copy source
COPY aegis/ ./aegis/
COPY eval/ ./eval/

# Copy built dashboard into a known location the API will serve
COPY --from=dashboard-build /dashboard/dist /app/dashboard-dist

# Healthcheck against the public status endpoint (works without auth)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8088/api/status > /dev/null || exit 1

EXPOSE 8088

# Run AEGIS - guards enabled by default
CMD ["python", "-m", "aegis.cli", "serve", "--host", "0.0.0.0", "--port", "8088"]
