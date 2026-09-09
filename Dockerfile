FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd -r stc && useradd -r -g stc -d /app -s /sbin/nologin stc

COPY pyproject.toml /app/pyproject.toml
COPY app /app/app
COPY scripts /app/scripts
COPY policies /app/policies
COPY LEARNINGS.md /app/LEARNINGS.md

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e .

RUN mkdir -p /app/data && chown -R stc:stc /app

USER stc

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
