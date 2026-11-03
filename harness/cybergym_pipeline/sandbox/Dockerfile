# cdb-cybergym-sandbox:28.5.2-v2. Independent of cdb-agent/cvefactory.
# v2 supports local Docker roots that are themselves on overlay storage.
# No syntax directive: the worker's built-in Dockerfile frontend is sufficient
# and does not need to download docker/dockerfile before using cached bases.
# Build context is harness/: docker build -f cybergym_pipeline/sandbox/Dockerfile .
FROM docker:28.5.2-dind@sha256:2a232a42256f70d78e3cc5d2b5d6b3276710a0de0596c145f627ecfae90282ac AS docker-engine
# The base repository digest (not an image ID) pins the Ubuntu manifest.
FROM ubuntu:22.04@sha256:0a9887931b0e38af2e3487ed39e29436b0535c4f3f52e57745baaf79d1898956

ENV DEBIAN_FRONTEND=noninteractive \
    DOCKER_HOST=unix:///var/run/docker.sock \
    DOCKER_BUILDKIT=1 \
    COMPOSE_DOCKER_CLI_BUILD=1 \
    PIP_INDEX_URL=https://pkg.pjlab.org.cn/repository/pypi-proxy/simple/ \
    PIP_TRUSTED_HOST=pkg.pjlab.org.cn \
    UV_DEFAULT_INDEX=https://pkg.pjlab.org.cn/repository/pypi-proxy/simple/ \
    NPM_CONFIG_REGISTRY=http://100.102.49.114:19091/repository/npm-public/ \
    GOPROXY=http://100.102.49.114:19091/repository/go-public,direct \
    GOSUMDB=sum.golang.google.cn \
    PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

ARG APT_MIRROR=http://100.102.49.114:19091/repository/ubuntu
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG http_proxy
ARG https_proxy
ARG no_proxy
RUN sed -i -E "s#https?://(archive|security).ubuntu.com/ubuntu#${APT_MIRROR}#g" \
      /etc/apt/sources.list && \
    apt-get update -o Acquire::Retries=2 && \
    apt-get install -y --no-install-recommends \
      bash ca-certificates curl wget git git-lfs jq \
      python3 python3-pip python3-venv \
      patch file socat gcc g++ make pkg-config \
      iproute2 iptables iputils-ping netcat-openbsd dnsutils \
      kmod xz-utils zstd tar gzip rsync sqlite3 fuse-overlayfs dnsmasq-base \
      ripgrep vim less tmux procps sudo tini && \
    rm -rf /var/lib/apt/lists/*

# One consistent Docker release for engine, CLI, Compose and Buildx. Do not add
# Ubuntu docker.io or the obsolete docker-compose Python package.
COPY --from=docker-engine /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-engine /usr/local/bin/dockerd /usr/local/bin/dockerd
COPY --from=docker-engine /usr/local/bin/docker-init /usr/local/bin/docker-init
COPY --from=docker-engine /usr/local/bin/docker-proxy /usr/local/bin/docker-proxy
COPY --from=docker-engine /usr/local/bin/containerd /usr/local/bin/containerd
COPY --from=docker-engine /usr/local/bin/containerd-shim-runc-v2 /usr/local/bin/containerd-shim-runc-v2
COPY --from=docker-engine /usr/local/bin/ctr /usr/local/bin/ctr
COPY --from=docker-engine /usr/local/bin/runc /usr/local/bin/runc
COPY --from=docker-engine /usr/local/libexec/docker/cli-plugins/ /usr/local/libexec/docker/cli-plugins/

# Reuse the existing large Node/Claude installation; it is not duplicated in
# this repository or replaced in the legacy cdb-agent image.
COPY agent_image/node/ /opt/node/
COPY cybergym_pipeline/sandbox/sandbox-init /usr/local/bin/cybergym-sandbox-init
COPY cybergym_pipeline/sandbox/exec-wrapper /usr/local/bin/cybergym-exec
COPY cybergym_pipeline/sandbox/kill-exec /usr/local/bin/cybergym-kill
COPY cybergym_pipeline/sandbox/preflight.py /usr/local/lib/cybergym/preflight.py
RUN chmod 0755 /usr/local/bin/cybergym-sandbox-init \
      /usr/local/bin/cybergym-exec /usr/local/bin/cybergym-kill && \
    groupadd --system --gid 1000 agent && \
    useradd --create-home --uid 1000 --gid agent --shell /bin/bash agent && \
    printf 'agent ALL=(root) NOPASSWD:ALL\n' > /etc/sudoers.d/cybergym-agent && \
    chmod 0440 /etc/sudoers.d/cybergym-agent && \
    mkdir -p /workspace /run/cybergym-exec && \
    chown -R agent:agent /workspace /home/agent /run/cybergym-exec && \
    git lfs install --system && \
    docker --version && docker compose version && docker buildx version && \
    node --version && claude --version

LABEL org.opencontainers.image.title="CyberDockerBench CyberGym sandbox" \
      org.opencontainers.image.version="28.5.2-v2" \
      bench.cyberdockerbench.family="cybergym" \
      bench.cyberdockerbench.docker-version="28.5.2"
WORKDIR /workspace
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/usr/local/bin/cybergym-sandbox-init"]
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=6 \
  CMD docker info --format '{{.ServerVersion}}' >/dev/null 2>&1 || exit 1
