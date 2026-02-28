# OpenSecAgent - Docker image
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r opensecagent && useradd -r -g opensecagent opensecagent

WORKDIR /app

COPY pyproject.toml requirements.txt ./
COPY opensecagent ./opensecagent
COPY config ./config

RUN pip install --no-cache-dir -e .

RUN mkdir -p /var/lib/opensecagent /var/log/opensecagent /etc/opensecagent && \
    chown -R opensecagent:opensecagent /var/lib/opensecagent /var/log/opensecagent

ENV OPENSECAGENT_CONFIG=/etc/opensecagent/config.yaml
ENV PYTHONUNBUFFERED=1

USER opensecagent

VOLUME ["/var/lib/opensecagent", "/var/log/opensecagent", "/etc/opensecagent"]

ENTRYPOINT ["python", "-m", "opensecagent.main"]
CMD ["--config", "/etc/opensecagent/config.yaml"]
