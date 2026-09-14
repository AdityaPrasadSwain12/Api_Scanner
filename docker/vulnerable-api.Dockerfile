FROM python:3.12.11-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN groupadd --gid 10002 fixture && useradd --uid 10002 --gid fixture --create-home fixture
COPY requirements.txt ./
RUN pip install --no-cache-dir fastapi==0.116.1 uvicorn==0.35.0
COPY vulnerable_test_api ./vulnerable_test_api
USER 10002:10002
EXPOSE 8001
CMD ["uvicorn", "vulnerable_test_api.main:app", "--host", "0.0.0.0", "--port", "8001"]

