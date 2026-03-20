# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  HTB Machine: AskMeAnything – REALISTIC EDITION v2                      ║
# ║  Author : Denis Sanchez Leyva | Vertex Coders LLC                       ║
# ║  Difficulty : Easy-Medium  |  Category: Web/Linux/AI                    ║
# ║                                                                          ║
# ║  Attack chain:                                                           ║
# ║    1. robots.txt → /internal/status                                     ║
# ║    2. /static/backups/app.conf.bak → api_key + password hint            ║
# ║    3. /api/admin/config (X-API-Key) → sudo policy disclosure            ║
# ║    4. ARIA Chat → Prompt Injection → leak aria_svc creds → SSH          ║
# ║    5. sudo run_task.py → Python module hijack → root                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# ── Stage 1: Download the model (cached layer, only re-runs if changed) ───
FROM python:3.11-slim AS model-downloader

WORKDIR /model-cache

# Install only what's needed to pull the model
RUN pip install --no-cache-dir huggingface_hub transformers

# Pre-download Qwen2.5-0.5B-Instruct (~500 MB) at build time
# This keeps the final image self-contained; no internet needed at runtime
RUN python - <<'EOF'
from huggingface_hub import snapshot_download
snapshot_download(
    repo_id="Qwen/Qwen2.5-0.5B-Instruct",
    local_dir="/model-cache/Qwen2.5-0.5B-Instruct",
    ignore_patterns=["*.bin"],
)
print("[+] Model downloaded successfully.")
EOF


# ── Stage 2: Runtime image ────────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="Denis Sanchez Leyva | Vertex Coders LLC"
LABEL htb.difficulty="Easy-Medium"
LABEL htb.category="Web/Linux/AI"
LABEL htb.version="2.0"

WORKDIR /app

# 1. System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        sudo \
    && rm -rf /var/lib/apt/lists/*

# 2a. Install torch CPU-only FIRST (separado para evitar conflicto con --index-url)
RUN pip install --no-cache-dir \
        torch==2.4.1 \
        --index-url https://download.pytorch.org/whl/cpu

# 2b. Install resto de dependencias Python (sin --index-url)
RUN pip install --no-cache-dir \
        flask \
        gunicorn \
        transformers==4.45.2 \
        accelerate \
        safetensors

# 3. Copy pre-downloaded model from build stage
COPY --from=model-downloader /model-cache/Qwen2.5-0.5B-Instruct \
     /opt/aria/model/Qwen2.5-0.5B-Instruct

# 4. Update LLM_MODEL_NAME to use local path (no HuggingFace download at runtime)
ENV LLM_MODEL_NAME="/opt/aria/model/Qwen2.5-0.5B-Instruct"

# 5. Create directory structure for the challenge
RUN mkdir -p /opt/aria/tasks/modules /opt/aria/config && \
    echo "Qwen/Qwen2.5-0.5B-Instruct" > /opt/aria/config/system_prompt.txt

# 6. Create the vulnerable maintenance script (Python module hijack vector)
RUN printf '%s\n' \
    '#!/usr/bin/env python3' \
    'import sys, os' \
    'sys.path.insert(0, "/opt/aria/tasks/modules")' \
    'print("[*] Executing maintenance task...")' \
    'try:' \
    '    import aria_cleaner' \
    '    aria_cleaner.run_maintenance()' \
    'except ImportError:' \
    '    print("[!] No modules found in /opt/aria/tasks/modules.")' \
    > /opt/aria/tasks/run_task.py && \
    chmod +x /opt/aria/tasks/run_task.py

# 7. Create unprivileged user + sudo policy (the privesc vector)
RUN useradd -m -u 1000 -s /bin/bash htbuser && \
    echo "htbuser ALL=(ALL) NOPASSWD: /opt/aria/tasks/run_task.py" \
        > /etc/sudoers.d/htbuser && \
    chmod 440 /etc/sudoers.d/htbuser

# 8. Plant flags
RUN echo "HTB{pr0mpt_1nj3ct10n_1s_r34l_d4ng3r}"  > /home/htbuser/user.txt && \
    echo "HTB{askm3nyth1ng_r34l1st1c_v2_4ppr0v3d}" > /root/root.txt && \
    chown htbuser:htbuser /home/htbuser/user.txt && \
    chmod 400 /home/htbuser/user.txt /root/root.txt

# 9. Copy application
COPY app.py /app/app.py

# 10. Fix ownership
RUN chown -R htbuser:htbuser /app /opt/aria

# 11. Drop to unprivileged user
USER htbuser

EXPOSE 5000

# 12. Gunicorn: 1 worker + 4 threads
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--threads", "4", \
     "--timeout", "180", \
     "app:app"]
