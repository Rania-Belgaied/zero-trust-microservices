FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY collectors.py .
COPY scorer.py .
COPY main.py .
EXPOSE 9090
CMD ["python", "main.py"]