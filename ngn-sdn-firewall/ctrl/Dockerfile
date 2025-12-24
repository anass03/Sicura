FROM python:3.8-slim

ENV PYTHONUNBUFFERED=1

# Tools for networking commands used by the startup script
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Pinned controller dependencies (compatible with Python < 3.11)
RUN pip install --no-cache-dir \
    ryu==4.34 \
    eventlet==0.30.2 \
    greenlet==1.1.2

WORKDIR /shared

# Kathará will execute the node startup script; default to a shell for manual exec.
CMD ["bash"]
