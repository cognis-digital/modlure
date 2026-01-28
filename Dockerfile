FROM python:3.12-slim
LABEL org.opencontainers.image.title="cognis-modpot"
LABEL org.opencontainers.image.source="https://github.com/cognis-digital/modpot"
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
ENTRYPOINT ["modpot"]
