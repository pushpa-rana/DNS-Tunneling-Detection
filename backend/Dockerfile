FROM python:3.11-slim

WORKDIR /app

# Install system dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and default data/model directories
COPY . .

# Set environment defaults
ENV ENVIRONMENT=production
ENV HOST=0.0.0.0
ENV PORT=8001
ENV PYTHONUNBUFFERED=1

EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/api/health')" || exit 1

CMD ["python", "run_backend.py"]
