FROM kathara/base

RUN apt-get update && \
    apt-get install -y --no-install-recommends mosquitto && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
