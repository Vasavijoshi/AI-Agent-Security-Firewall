FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent/ agent/
# WHY attacks/ is copied into the agent image (M3): A4 and A9 specifically require running as the
# actual deployed agent container and calling the real identity/PEP services over agent-net — see
# each script's own module docstring. `docker compose run --rm agent python -m attacks.a4` (or
# attacks.run_all) needs the attacks package present inside this image to do that.
COPY attacks/ attacks/
# WHY the same pep/policy/risk/dlp/threat_intel/identity.tokens copy pep/Dockerfile has (found by
# an actual first live dispatch attempt, not review): attacks/common.py's run_locally() supplement
# imports pep.pipeline/pep.proxy/pep.quarantine/risk.scorer for real — a genuine in-process replay
# using the real pipeline code, not a fabricated decision (see attacks/common.py's own module
# docstring). Those packages were never copied into this image before this fix, so every attack
# script's import failed the moment it was actually dispatched into a real `agent`/`finance-agent`/
# `support-agent` container with `ModuleNotFoundError: No module named 'pep'` — undetected until
# then because nothing had actually run `docker compose run agent python -m attacks.aN` against
# this exact image before.
COPY pep/ pep/
COPY policy/ policy/
COPY risk/ risk/
COPY dlp/ dlp/
COPY threat_intel/ threat_intel/
COPY identity/__init__.py identity/tokens.py identity/
CMD ["python", "-m", "agent.main"]
