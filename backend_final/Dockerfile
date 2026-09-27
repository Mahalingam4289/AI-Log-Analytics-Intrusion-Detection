FROM python:3.11-slim

WORKDIR /app

# System deps needed by scikit-learn / pandas wheels build fallback
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Models, data, and the SQLite DB are generated on first run and should
# persist across container restarts — mount a volume at /app/saved_models,
# /app/data, and /app/database in production (see docker-compose.yml).
RUN mkdir -p saved_models database

EXPOSE 8000

ENV SENTINEL_REQUIRE_AUTH=true \
    SENTINEL_LOG_SOURCE=simulated \
    SENTINEL_USE_REDIS=false

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
