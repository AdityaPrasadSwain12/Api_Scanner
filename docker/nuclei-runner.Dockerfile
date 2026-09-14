FROM projectdiscovery/nuclei:v3.11.0 AS nuclei
FROM alpine/git:2.49.1 AS templates
RUN git clone --depth 1 --branch v10.4.7 https://github.com/projectdiscovery/nuclei-templates.git /templates
FROM python:3.12.11-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ENGINE=nuclei
WORKDIR /runner
RUN groupadd --gid 10003 runner && useradd --uid 10003 --gid runner --create-home runner
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --chown=10003:10003 --from=templates /templates /opt/nuclei-templates
COPY requirements.txt ./
RUN pip install --no-cache-dir fastapi==0.116.1 uvicorn==0.35.0 pydantic==2.11.7 httpx==0.28.1 structlog==25.4.0
COPY --chown=10003:10003 app ./app
COPY --chown=10003:10003 engine_runner ./engine_runner
USER 10003:10003
ENTRYPOINT []
CMD ["uvicorn", "engine_runner.main:app", "--host", "0.0.0.0", "--port", "8091"]
