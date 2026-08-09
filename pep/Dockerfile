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
# WHY 8079 (the admin/quarantine port) is not listed here: it's bound to 127.0.0.1 inside the
# container (pep/proxy.py's lifespan), so EXPOSE-ing it would be misleading — nothing outside this
# container's own network namespace can reach it regardless. Reach it via `docker compose exec pep
# curl http://localhost:8079/admin/...`.
EXPOSE 8080 8081
CMD ["uvicorn", "pep.proxy:app", "--host", "0.0.0.0", "--port", "8080"]
