"""Load trusted deployment settings without putting them in command arguments.

Explicit process settings take precedence. If no egress proxy was supplied, a
worker-side proxy-env.sh may be parsed for its simple ``export NAME=value``
entries. Arbitrary shell commands are never executed by this loader. The network
plugin configures package mirrors; this loader handles the separate HTTP proxy.
"""
from __future__ import annotations

import os
import re
import shlex
from pathlib import Path

PROXY_KEYS = frozenset(("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                        "http_proxy", "https_proxy", "all_proxy", "no_proxy"))
MODEL_KEYS = frozenset(("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN",
                        "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN",
                        "CLAUDE_CODE_STREAM_TIMEOUT", "CLAUDE_CODE_MAX_CONTEXT_TOKENS"))
SETTING_KEYS = PROXY_KEYS | MODEL_KEYS | frozenset((
    "CYBERGYM_NETWORK_PLUGIN", "CYBERGYM_SANDBOX_IMAGE", "CYBERGYM_REGISTRY_MIRROR",
    "CYBERGYM_EXTRA_NO_PROXY", "CYBERGYM_GIT_SMOKE_URL", "CYBERGYM_DIND_MTU",
    "CYBERGYM_SMOKE_BASE_IMAGE_ARCHIVE", "CYBERGYM_LOAD_PROXY_ENV",
    "GIT_SSL_CAINFO", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS",
    "GIT_CONFIG_COUNT",
))
DEFAULT_PROXY_FILES = (
    Path("/mnt/shared-storage-user/datafactory-share/wuyida/netproxy/proxy-env.sh"),
    Path("/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/netproxy/proxy-env.sh"),
)


def parse_proxy_exports(text: str) -> dict[str, str]:
    """Read static exports, allowing only references to already-read variables."""
    values: dict[str, str] = {}
    for number, original in enumerate(text.splitlines(), 1):
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)", line)
        if not match:
            raise ValueError(f"unsupported proxy-env line {number}; expected a static export")
        key, expression = match.groups()
        if key not in PROXY_KEYS:
            raise ValueError(f"unsupported setting {key!r} in proxy environment")
        try:
            words = shlex.split(expression, posix=True)
        except ValueError as exc:
            raise ValueError(f"invalid proxy-env line {number}: {exc}") from exc
        if len(words) != 1:
            raise ValueError(f"proxy-env line {number} must be one scalar value")
        word = words[0]
        # This intentionally supports only $NAME, not command substitution or
        # arbitrary shell expansion. Credentials stay in the returned mapping.
        if re.search(r"\$\{|\$\(|`|[;<>|&\n\r]", word) or word.startswith("~"):
            raise ValueError(f"unsupported shell expansion in proxy-env line {number}")
        word = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)",
                      lambda item: values.get(item.group(1), os.environ.get(item.group(1), "")), word)
        if "$" in word:
            raise ValueError(f"unsupported expansion in proxy-env line {number}")
        values[key] = word
    return values


def load_runtime_settings(environ: dict[str, str] | None = None, *,
                          load_proxy: bool = True) -> dict[str, str]:
    source = os.environ if environ is None else environ
    settings = {key: source[key] for key in SETTING_KEYS if source.get(key)}
    if not load_proxy or settings.get("CYBERGYM_LOAD_PROXY_ENV", "1") == "0":
        settings.pop("CYBERGYM_LOAD_PROXY_ENV", None)
        return settings
    configured = source.get("CYBERGYM_PROXY_ENV_FILE")
    paths = [Path(configured)] if configured else list(DEFAULT_PROXY_FILES)
    if not any(source.get(key) for key in PROXY_KEYS - {"NO_PROXY", "no_proxy"}):
        for path in paths:
            if not path.is_file():
                continue
            if path.is_symlink() or not path.resolve().is_file():
                raise ValueError(f"proxy environment must be a regular file: {path}")
            for key, value in parse_proxy_exports(path.read_text(encoding="utf-8")).items():
                settings.setdefault(key, value)
            break
    settings.pop("CYBERGYM_LOAD_PROXY_ENV", None)
    return settings
