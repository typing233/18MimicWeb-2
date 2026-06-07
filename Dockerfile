FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY config/ config/

RUN pip install --no-cache-dir -e . && \
    mkdir -p /app/logs

ENV MIMICWEB_INSTANCE_ID=""

EXPOSE 8080

CMD ["python", "-m", "mimicweb.main", "-c", "config/routes.yaml"]
