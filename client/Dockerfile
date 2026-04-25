FROM python:3.10-slim

WORKDIR /app

COPY . .

RUN pip install requests cryptography

CMD ["python", "client.py"]