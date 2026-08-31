FROM python:3.11-slim

# sqlite3 CLI: the credential-storage tests read the stored MD5 hash directly
# from the database via `docker exec <container> sqlite3 ...` to confirm that
# VULN-03 is present and intact.
RUN apt-get update \
 && apt-get install -y --no-install-recommends sqlite3 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /data

# NOTE: this image deliberately keeps the weaknesses it exists to teach — it
# runs as root with Flask debug mode on, which is VULN-11 itself. It is bound
# to 127.0.0.1 in docker-compose.insecure.yml and must never be exposed. The
# hardened image (app/secure) is the one that demonstrates correct posture,
# including a non-root user and a healthcheck.

EXPOSE 5000

# Initialise DB and start on first run
CMD ["python", "-c", \
     "from app import app, init_db;\
      import os;\
      os.makedirs('/data', exist_ok=True);\
      ctx = app.app_context();\
      ctx.push();\
      init_db();\
      ctx.pop();\
      app.run(host='0.0.0.0', port=5000, debug=True)"]
