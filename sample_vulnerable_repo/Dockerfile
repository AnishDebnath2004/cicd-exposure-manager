FROM python:3.11-slim

EXPOSE 8000

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

USER 10001

CMD ["python", "main.py"]