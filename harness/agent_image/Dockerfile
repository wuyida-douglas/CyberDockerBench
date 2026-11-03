# Versioned all-in-one CyberDockerBench sandbox: Docker Engine + ordinary Claude Code.
FROM docker:28-dind AS docker-engine
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    DOCKER_HOST=unix:///var/run/docker.sock \
    DOCKER_BUILDKIT=1 \
    COMPOSE_DOCKER_CLI_BUILD=1 \
    PIP_INDEX_URL=https://pkg.pjlab.org.cn/repository/pypi-proxy/simple/ \
    PIP_TRUSTED_HOST=pkg.pjlab.org.cn \
    PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

ARG APT_MIRROR=http://100.102.49.114:19091/repository/ubuntu
RUN sed -i -E \
      -e "s@https?://(archive|security).ubuntu.com/ubuntu@${APT_MIRROR}@g" \
      /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      bash ca-certificates curl wget git git-lfs jq \
      python3 python3-pip python3-venv \
      patch file socat gcc g++ make pkg-config \
      iproute2 iptables iputils-ping netcat-openbsd dnsutils \
      kmod xz-utils zstd tar gzip rsync sqlite3 \
      ripgrep vim less tmux procps sudo && \
    update-alternatives --set iptables /usr/sbin/iptables-legacy && \
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy && \
    rm -rf /var/lib/apt/lists/*

# Use one Docker release for daemon, CLI, Compose and Buildx, without Ubuntu's
# conflicting docker.io/docker-compose packages.
COPY --from=docker-engine /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-engine /usr/local/bin/dockerd /usr/local/bin/dockerd
COPY --from=docker-engine /usr/local/bin/docker-init /usr/local/bin/docker-init
COPY --from=docker-engine /usr/local/bin/docker-proxy /usr/local/bin/docker-proxy
COPY --from=docker-engine /usr/local/bin/containerd /usr/local/bin/containerd
COPY --from=docker-engine /usr/local/bin/containerd-shim-runc-v2 /usr/local/bin/containerd-shim-runc-v2
COPY --from=docker-engine /usr/local/bin/ctr /usr/local/bin/ctr
COPY --from=docker-engine /usr/local/bin/runc /usr/local/bin/runc
COPY --from=docker-engine /usr/local/libexec/docker/cli-plugins/ /usr/local/libexec/docker/cli-plugins/
COPY node/ /opt/node/
COPY sandbox-init /usr/local/bin/cdb-sandbox-init
COPY cdb-exec /usr/local/bin/cdb-exec
COPY cdb-kill-exec /usr/local/bin/cdb-kill-exec
RUN chmod 0755 /usr/local/bin/cdb-sandbox-init /usr/local/bin/cdb-exec /usr/local/bin/cdb-kill-exec && \
    groupadd --system --gid 1000 agent && \
    useradd --create-home --uid 1000 --gid agent --shell /bin/bash agent && \
    printf 'agent ALL=(root) NOPASSWD:ALL\n' > /etc/sudoers.d/cdb-agent && \
    chmod 0440 /etc/sudoers.d/cdb-agent && \
    mkdir -p /workspace /opt/cdb-network-plugin && chown -R agent:agent /workspace && \
    python3 -m pip install --no-cache-dir requests beautifulsoup4 lxml pytest PyYAML==6.0.2 && \
    git lfs install --system && \
    docker --version && docker compose version && docker buildx version && \
    node --version && claude --version

# controller binds each task's public workspace at the same absolute path.
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/docker-init", "--", "/usr/local/bin/cdb-sandbox-init"]
