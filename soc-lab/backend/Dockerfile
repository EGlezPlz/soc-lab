FROM python:3.12-slim

# Instalar docker CLI (para docker exec hacia los contenedores de las herramientas)
RUN apt-get update && apt-get install -y \
    docker.io \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
