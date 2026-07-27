FROM python:3.12-slim AS base

WORKDIR /app

# Install build dependencies only long enough to build the wheel, then discard them.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[api]"

# Non-root user for the runtime container.
RUN useradd --create-home --uid 1000 chitragupta
USER chitragupta

EXPOSE 8000

# Runs the FastAPI control plane by default. Override the command to run
# the CLI instead, e.g.:
#   docker run --rm chitragupta-protocol chitragupta demo --all
CMD ["python", "-m", "uvicorn", "chitragupta.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
