FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY src /app/src
ENV PYTHONPATH=/app
CMD ["python", "-m", "src.Worker.worker"]
