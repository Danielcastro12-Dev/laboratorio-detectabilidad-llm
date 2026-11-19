FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

RUN groupadd --gid 1000 llmlab && \
    useradd --uid 1000 --gid llmlab --shell /bin/false --create-home llmlab

WORKDIR /workspace
RUN mkdir -p /workspace/output && chown -R llmlab:llmlab /workspace

USER llmlab:llmlab
