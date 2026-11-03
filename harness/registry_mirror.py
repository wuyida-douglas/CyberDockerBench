"""kkRepo Docker Hub proxy configuration for isolated task daemons.

Docker Hub images use kkRepo by default. The retired GPFS cache is opt-in only.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from urllib.parse import urlsplit

DEFAULT_WORKER = "root@100.96.153.163"
DEFAULT_PORT = 5000
DATA_ROOT = "/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/docker"


def _env(environ: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if environ is None else environ


def worker_host(environ: Mapping[str, str] | None = None) -> str:
    worker = _env(environ).get("CDB_WORKER", DEFAULT_WORKER).strip()
    return worker.split("@")[-1].strip()


def mirror_url(environ: Mapping[str, str] | None = None) -> str:
    """Legacy cache is opt-in; normal runs use kkRepo only."""
    env = _env(environ)
    for key in ("CDB_REGISTRY_MIRROR", "CYBERGYM_REGISTRY_MIRROR"):
        value = env.get(key, "").strip()
        if value:
            return value.split(",")[0].strip()
    if env.get("CDB_ENABLE_HUB_CACHE") != "1":
        return ""
    listed = [item.strip() for item in env.get("CDB_REGISTRY_MIRRORS", "").split(",") if item.strip()]
    if listed:
        return listed[0]
    host = worker_host(env)
    return f"http://{host}:{DEFAULT_PORT}" if host else ""


def mirror_host(url: str) -> str:
    return urlsplit(url).hostname or ""


def direct_registry_hosts(environ: Mapping[str, str] | None = None) -> tuple[str, ...]:
    host = mirror_host(mirror_url(environ))
    return (host, "100.102.49.114") if host else ("100.102.49.114",)


def apply_mirror(config: dict, environ: Mapping[str, str] | None = None) -> str:
    """Allow direct kkRepo HTTP; optionally configure the legacy cache."""
    url = mirror_url(environ)
    hostport = urlsplit(url).netloc
    if url:
        config["registry-mirrors"] = [url]
    insecure = [item for item in config.get("insecure-registries") or [] if item != hostport]
    for endpoint in (hostport, "100.102.49.114:19091"):
        if endpoint:
            insecure.append(endpoint)
    config["insecure-registries"] = insecure
    return url
