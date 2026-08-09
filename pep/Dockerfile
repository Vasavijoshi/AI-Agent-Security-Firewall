FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY pep/ pep/
COPY policy/ policy/
COPY risk/ risk/
COPY dlp/ dlp/
COPY threat_intel/ threat_intel/
COPY identity/__init__.py identity/tokens.py identity/
EXPOSE 8080 8081
CMD ["uvicorn", "pep.proxy:app", "--host", "0.0.0.0", "--port", "8080"]
