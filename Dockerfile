FROM python:3.11-slim

WORKDIR /app

# System deps for asyncssh
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p logs configs

CMD ["python", "-m", "honeypot.main", "configs/config.yaml"]
