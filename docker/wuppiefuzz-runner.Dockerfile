FROM debian:trixie-slim AS tool
ARG WUPPIEFUZZ_SHA256=52da710725029126a157c9c621e03dd4167cb82756ed8b26caa01d17ac0e9673
ADD --checksum=sha256:${WUPPIEFUZZ_SHA256} https://github.com/TNO-S3/WuppieFuzz/releases/download/v1.7.1/wuppiefuzz-x86_64-unknown-linux-gnu.tar.xz /tmp/wuppiefuzz.tar.xz
RUN apt-get update && apt-get install -y --no-install-recommends xz-utils \
    && mkdir /out && tar -xJf /tmp/wuppiefuzz.tar.xz -C /out --strip-components=1 \
    wuppiefuzz-x86_64-unknown-linux-gnu/wuppiefuzz && chmod 0755 /out/wuppiefuzz
FROM python:3.12.11-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ENGINE=wuppiefuzz
WORKDIR /runner
RUN groupadd --gid 10005 runner && useradd --uid 10005 --gid runner --create-home runner
COPY --from=tool /out/wuppiefuzz /usr/local/bin/wuppiefuzz
RUN pip install --no-cache-dir fastapi==0.116.1 uvicorn==0.35.0 pydantic==2.11.7 httpx==0.28.1 structlog==25.4.0
COPY --chown=10005:10005 app ./app
COPY --chown=10005:10005 engine_runner ./engine_runner
USER 10005:10005
CMD ["uvicorn", "engine_runner.main:app", "--host", "0.0.0.0", "--port", "8093"]
