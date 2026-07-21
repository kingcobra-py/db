FROM python:3.11-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 DATA_ROOT=/data
RUN apt-get update && apt-get install --no-install-recommends -y p7zip-full unar ca-certificates tini && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 10001 scanner && useradd --uid 10001 --gid scanner --create-home --shell /usr/sbin/nologin scanner
WORKDIR /app
COPY requirements.txt .
RUN pip install --requirement requirements.txt
COPY *.py ./
COPY templates ./templates
COPY static ./static
RUN mkdir -p /data/inbox /data/work /data/output && chown -R scanner:scanner /app /data && chmod 700 /data /data/inbox /data/work /data/output
USER scanner
ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["python","main_pipeline.py"]
