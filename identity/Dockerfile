FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY identity/ identity/
EXPOSE 8082
CMD ["uvicorn", "identity.issuer:app", "--host", "0.0.0.0", "--port", "8082"]
