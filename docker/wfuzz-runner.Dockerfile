# Wfuzz 3.1.1 still imports Python's removed `imp` module, so its isolated
# compatibility runner intentionally stays on Python 3.11.
FROM python:3.11.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ENGINE=wfuzz
WORKDIR /runner
RUN apt-get update && apt-get install -y --no-install-recommends gcc libcurl4-openssl-dev libssl-dev && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10004 runner && useradd --uid 10004 --gid runner --create-home runner
RUN pip install --no-cache-dir setuptools==80.9.0 fastapi==0.116.1 uvicorn==0.35.0 pydantic==2.11.7 httpx==0.28.1 structlog==25.4.0 \
    "wfuzz @ https://github.com/xmendez/wfuzz/archive/refs/tags/v3.1.1.tar.gz"
COPY --chown=10004:10004 app ./app
COPY --chown=10004:10004 engine_runner ./engine_runner
COPY --chown=10004:10004 docker/payloads /opt/payloads
USER 10004:10004
CMD ["uvicorn", "engine_runner.main:app", "--host", "0.0.0.0", "--port", "8092"]
