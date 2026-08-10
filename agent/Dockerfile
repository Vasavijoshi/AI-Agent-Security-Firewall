FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent/ agent/
# WHY attacks/ is copied into the agent image (M3): A4 and A9 specifically require running as the
# actual deployed agent container and calling the real identity/PEP services over agent-net — see
# each script's own module docstring. `docker compose exec agent python -m attacks.a4` (or
# attacks.run_all) needs the attacks package present inside this image to do that.
COPY attacks/ attacks/
CMD ["python", "-m", "agent.main"]
