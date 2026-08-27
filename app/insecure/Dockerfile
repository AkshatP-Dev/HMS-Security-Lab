FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /data
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
