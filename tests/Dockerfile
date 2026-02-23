FROM python:3.12-slim

# System deps: curl/jq for E2E bash scripts, libpq-dev for psycopg2,
# postgresql-client for native psql in E2E tests
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl jq libpq-dev postgresql-client && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/test-requirements.txt
RUN pip install --no-cache-dir -r /tmp/test-requirements.txt

WORKDIR /workspace
ENTRYPOINT ["bash", "/workspace/scripts/run-tests.sh"]
