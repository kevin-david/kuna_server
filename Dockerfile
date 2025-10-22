FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY kuna_server.py .

CMD ["python", "kuna_server.py"]
