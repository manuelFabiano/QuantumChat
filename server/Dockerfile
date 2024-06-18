FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt requirements.txt
COPY server.py server.py

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["python", "server.py"]
