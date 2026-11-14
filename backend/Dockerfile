FROM python:3.12-slim

RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 10000

CMD ["sh", "-c", "python -c 'from database import create_tables; create_tables(); from app import init_db; init_db()' && exec gunicorn --bind 0.0.0.0:${PORT:-10000} app:app"]
