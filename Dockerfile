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

# ── Stage 1: Download the model ───────────────────────────────────────────
FROM python:3.11-slim AS model-downloader

WORKDIR /model-cache

RUN pip install --no-cache-dir huggingface_hub transformers

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

# 1. System dependencies + OpenSSH
RUN apt-get update && apt-get install -y --no-install-recommends \
        sudo \
        openssh-server \
    && rm -rf /var/lib/apt/lists/*

# 2. Configure SSH
RUN mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# 3a. Install torch CPU-only
RUN pip install --no-cache-dir \
        torch==2.4.1 \
        --index-url https://download.pytorch.org/whl/cpu

# 3b. Install rest of Python deps
RUN pip install --no-cache-dir \
        flask \
        gunicorn \
        transformers==4.45.2 \
        accelerate \
        safetensors

# 4. Copy pre-downloaded model
COPY --from=model-downloader /model-cache/Qwen2.5-0.5B-Instruct \
     /opt/aria/model/Qwen2.5-0.5B-Instruct

# 5. Set model path env
ENV LLM_MODEL_NAME="/opt/aria/model/Qwen2.5-0.5B-Instruct"

# 6. Create directory structure
RUN mkdir -p /opt/aria/tasks/modules /opt/aria/config && \
    echo "Qwen/Qwen2.5-0.5B-Instruct" > /opt/aria/config/system_prompt.txt

# 7. Create vulnerable maintenance script (Python module hijack vector)
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

# 8. Create htbuser with correct password + sudo policy
RUN useradd -m -u 1000 -s /bin/bash htbuser && \
    echo "htbuser:Service2026!AMC" | chpasswd && \
    echo "htbuser ALL=(ALL) NOPASSWD: /opt/aria/tasks/run_task.py" \
        > /etc/sudoers.d/htbuser && \
    chmod 440 /etc/sudoers.d/htbuser

# 9. Plant flags (MD5 format — HTB standard)
RUN echo "130d44e1376493212c187abd3047c373" > /home/htbuser/user.txt && \
    echo "1cd55876411049351002598b4a2fa229" > /root/root.txt && \
    chown htbuser:htbuser /home/htbuser/user.txt && \
    chmod 400 /home/htbuser/user.txt /root/root.txt

# 10. Copy application
COPY app.py /app/app.py

# 11. Fix ownership
RUN chown -R htbuser:htbuser /app /opt/aria

# 12. Startup script — runs SSH + Gunicorn together
RUN printf '%s\n' \
    '#!/bin/bash' \
    'service ssh start' \
    'exec gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 4 --timeout 180 app:app' \
    > /start.sh && chmod +x /start.sh

EXPOSE 22 5000

# 13. Run as root so SSH can start, Gunicorn handles the app
CMD ["/start.sh"]
