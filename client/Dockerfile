FROM python:3.9-slim

WORKDIR /client

COPY requirements.txt ../client/requirements.txt
COPY client.py ../client/client.py
COPY kyberpy ../client/kyberpy

RUN pip3 install --no-cache-dir -r requirements.txt



CMD ["bash"]
