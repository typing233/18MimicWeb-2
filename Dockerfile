FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY config/ config/

RUN pip install --no-cache-dir -e . && \
    mkdir -p /app/logs

ENV MIMICWEB_INSTANCE_ID=""
ENV MIMICWEB_CONFIG="config/routes-docker.yaml"

EXPOSE 8080

CMD ["sh", "-c", "python -m mimicweb.main -c ${MIMICWEB_CONFIG}"]
