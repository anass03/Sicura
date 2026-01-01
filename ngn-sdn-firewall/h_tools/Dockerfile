FROM kathara/base

RUN apt-get update && \
    apt-get install -y --no-install-recommends \\
      mosquitto-clients curl iproute2 netcat-traditional \\
      nmap hping3 tcpdump jq && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*
