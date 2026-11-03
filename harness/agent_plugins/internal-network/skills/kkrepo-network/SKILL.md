---
name: kkrepo-network
description: Configure Docker builds and container downloads in the CyberDockerBench sandbox. Use when writing Dockerfiles or Compose, installing apt/apk/yum/dnf/pip/uv/npm/Go/Maven/RubyGems/CPAN/Composer dependencies, or diagnosing base-image pulls, proxy, NO_PROXY, DNS, Hash Sum mismatch, and NO_PUBKEY errors.
---

# Sandbox source downloads, package mirrors and proxy

This is deployment-specific network guidance for the current task sandbox. Use
ordinary Docker, Compose, shell, and package-manager commands. Do not look for
worker administration, host image caches, external transfer machines, factory
MCP tools, or `prepare_environment` / `install_environment`; they are not part
of this task.

**The supplied `src/` may be incomplete or inconsistent.** Inspect it, verify
that it actually implements the described vulnerable version, and repair or
replace missing parts as needed. You may use `git clone`, `git fetch`, `curl`,
`wget`, upstream archives, package registries, and any other ordinary source
retrieval command. Prefer the original project/version over a
lookalike replacement. Never treat the initial source tree as read-only or as
the only permitted source of code. The final modified source tree and all added
build context are graded; the grader does not restore the initial `src/`.

Do not change application versions or behavior merely to avoid a download, and
do not substitute an unrelated application or simulated vulnerability output.

## 1. Separate three kinds of network access

1. **Package mirrors**: kkRepo is a package repository and Docker Hub proxy,
   not a general HTTP proxy. Access `http://100.102.49.114:19091` directly.
   The runtime Docker adapter handles the `docker-hub/` prefix automatically.
   PyPI uses `https://pkg.pjlab.org.cn/repository/pypi-proxy/simple/`.
2. **Other external downloads**: original source archives, Git repositories,
   vendor sites, and missing upstream packages use the proxy already supplied
   as `HTTP_PROXY` / `HTTPS_PROXY` (and lowercase equivalents). Do not guess or
   hardcode a proxy URL, and do not write its value or credentials into a file.
3. **Task-internal services**: `localhost`, `127.0.0.1`, `client`, `db`, and
   other Compose service names must connect directly, not through the proxy.

Docker builds do not automatically receive the shell proxy. Forward proxy
variables as build args, or pass them explicitly to a container only when that
process needs an external download. Keep internal mirrors and service names in
`NO_PROXY` / `no_proxy`; preserve the existing value instead of overwriting it.

```text
100.102.49.114,pkg.pjlab.org.cn,localhost,127.0.0.1,client,db
```

Add the actual service names used by your Compose file. `NO_PROXY` does not
select a package mirror: configure the package manager separately.

## 2. Package endpoint reference

Use only the ecosystems needed by the task. Set these in the image or project
configuration so later builds, `solution.sh`, and tests can reuse them.

| Content | Endpoint |
| --- | --- |
| Debian current | `http://100.102.49.114:19091/repository/debian` |
| Debian security | `http://100.102.49.114:19091/repository/debian-security` |
| Debian squeeze/wheezy/jessie/stretch/buster/bullseye | `http://100.102.49.114:19091/repository/debian-archive` |
| Security for those EOL Debian releases | `http://100.102.49.114:19091/repository/debian-archive-security` |
| Debian backports, only if required | `http://100.102.49.114:19091/repository/debian-archive-backports` |
| Ubuntu | `http://100.102.49.114:19091/repository/ubuntu` |
| Ubuntu ports | `http://100.102.49.114:19091/repository/ubuntu-ports` |
| Alpine | `http://100.102.49.114:19091/repository/alpine` |
| yum general / EPEL | `http://100.102.49.114:19091/repository/yum-public` / `yum-epel` |
| old EPEL | `http://100.102.49.114:19091/repository/yum-epel-archive` |
| CentOS Stream / vault | `http://100.102.49.114:19091/repository/yum-centos-stream` / `yum-centos-vault` |
| Fedora / old Fedora | `http://100.102.49.114:19091/repository/yum-fedora` / `yum-fedora-archive` |
| Rocky / AlmaLinux | `http://100.102.49.114:19091/repository/yum-rocky` / `yum-almalinux` |
| pip and uv | `https://pkg.pjlab.org.cn/repository/pypi-proxy/simple/` |
| npm, yarn, pnpm | `http://100.102.49.114:19091/repository/npm-public/` |
| Go modules | `http://100.102.49.114:19091/repository/go-public,direct` |
| Go checksums | `sum.golang.google.cn` |
| Maven central | `http://100.102.49.114:19091/repository/maven-public` |
| RubyGems / CPAN | `http://100.102.49.114:19091/repository/rubygems-aliyun/` / `cpan` |
| Composer packages | `https://mirrors.aliyun.com/composer/` |
| `composer.phar` | `http://100.102.49.114:19091/repository/composer-files/composer.phar` |

Keep the original upstream URL for third-party APT repositories, ordinary
source downloads, and GitHub content. Those use the supplied HTTP proxy, not a
guessed package-repository path. Docker Hub base images are resolved by the
runtime adapter through kkRepo's `docker-hub/` namespace.

## 3. Base images and Dockerfiles

For `FROM` and Compose `image:`, keep the exact original Docker Hub
image/tag/digest and use ordinary `docker pull`, `docker build`,
`docker buildx build`, or `docker compose`. The task Docker adapter resolves
Docker Hub through kkRepo automatically. No `docker login`, host-cache lookup,
or manual image-name rewrite is needed. Third-party registries keep their
original addresses and their own credentials if required.

Package mirrors do not replace daemon registry access: the adapter handles
base images, while package downloads inside `RUN` still need the mirrors below.

Do not inspect a host cache, transfer images through another machine, restart
the daemon, or replace a missing image with a different application/version.
If a specific image cannot be pulled, report its full reference and the exact
daemon error rather than repeatedly trying unrelated registries.

Configure package mirrors **inside every build stage that downloads**, before
its first install. Read `/etc/os-release` in that stage; do not assume the
sandbox's distro or release. Preserve the base image's version and architecture.

A Debian/Ubuntu Dockerfile can adapt this pattern before `apt-get install`:

```dockerfile
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG http_proxy
ARG https_proxy
ARG no_proxy

RUN set -eu; \
    . /etc/os-release; \
    K=http://100.102.49.114:19091/repository; \
    DEB="$K/debian"; SEC="$K/debian-security"; \
    case "${VERSION_CODENAME:-}" in \
      squeeze|wheezy|jessie|stretch|buster|bullseye) \
        DEB="$K/debian-archive"; SEC="$K/debian-archive-security"; \
        printf '%s\n' 'Acquire::Check-Valid-Until "false";' \
          > /etc/apt/apt.conf.d/99-sandbox-archive ;; \
    esac; \
    find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) \
      -exec sed -i -E \
        -e "s|https?://[^/]+/debian-security|$SEC|g" \
        -e "s|https?://[^/]+/debian|$DEB|g" \
        -e "s#https?://(archive|security).ubuntu.com/ubuntu#$K/ubuntu#g" \
        -e "s|https?://old-releases.ubuntu.com/ubuntu|$K/ubuntu|g" {} +; \
    apt-get update -o Acquire::Retries=2; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*
```

For EOL Debian, use the internal archive and disable nonexistent `-updates`
entries. If its signatures are unavailable through this internal archive,
`[trusted=yes]` may be scoped to those archive entries only; never globally
disable authentication. Do not convert third-party vendor repositories into
Debian repositories.

Alpine preserves its existing release path and changes only the host:

```dockerfile
RUN sed -i -E 's|https?://[^/]+/alpine|http://100.102.49.114:19091/repository/alpine|g' \
      /etc/apk/repositories && apk add --no-cache curl
```

For RPM distros, edit the actual `.repo` `baseurl` to the matching repository
above. Preserve `$basearch`, `$contentdir`, release version, and other variables;
disable the old `metalink`/`mirrorlist`. Do not switch distributions or releases.

## 4. Language package managers

When needed, persist these settings in the final image, not only in a temporary
shell used during development:

```dockerfile
ENV PIP_INDEX_URL=https://pkg.pjlab.org.cn/repository/pypi-proxy/simple/ \
    PIP_TRUSTED_HOST=pkg.pjlab.org.cn \
    UV_DEFAULT_INDEX=https://pkg.pjlab.org.cn/repository/pypi-proxy/simple/ \
    NPM_CONFIG_REGISTRY=http://100.102.49.114:19091/repository/npm-public/ \
    GOPROXY=http://100.102.49.114:19091/repository/go-public,direct \
    GOSUMDB=sum.golang.google.cn
```

- Check explicit pip `--index-url`, `.npmrc`, Go env/flags, and lockfile
  `resolved` URLs: they can override these settings. Do not change locked
  dependency versions or disable checksum verification.
- Go: run `go env GOPROXY GOSUMDB` in the actual build stage and make one
  bounded `go mod download` attempt before the full build.
- Composer: `composer config -g repos.packagist composer https://mirrors.aliyun.com/composer/`.
  Download `composer.phar` from the table above and verify `composer --version`.
- Maven: set an internal central mirror in the settings file actually used by
  `mvn -s`, `settings.xml`, or `MAVEN_CONFIG`. Remove stale `<proxy>` entries;
  inspect `mvn help:effective-settings` if a build still uses an old proxy.
  Do not print repository credentials.
- `solution.sh` and tests may run after this Skill is no longer mounted. Their
  required mirrors and dependencies must already be declared in the submitted
  Dockerfile, image configuration, scripts, or test environment.

## 5. Compose and running containers

Pass proxy values by variable name, without embedding their values:

```yaml
services:
  client:
    build:
      context: .
      args:
        HTTP_PROXY: ${HTTP_PROXY:-}
        HTTPS_PROXY: ${HTTPS_PROXY:-}
        NO_PROXY: ${NO_PROXY:-}
        http_proxy: ${http_proxy:-}
        https_proxy: ${https_proxy:-}
        no_proxy: ${no_proxy:-}
```

These are build-time settings. Do not automatically inject the proxy into the
application's runtime environment. A separate test process that needs external
packages can receive `-e HTTP_PROXY -e HTTPS_PROXY -e NO_PROXY` (and lowercase
forms), with all Compose service names included in `NO_PROXY`.

For a one-off installation in a running container, pass only the needed proxy
variables to `docker exec`, install the package, then synchronize persistent
changes into the Dockerfile/Compose project. Do not rely on shell state from a
previous `docker exec`; each invocation starts a new shell.

## 6. Diagnose the first concrete error

Do not repeatedly probe mirrors. Read the actual package/image, URL, HTTP status,
and first useful error; then make one targeted change and verify it with the
real build or install command.

- **`FROM` / `image:` fails**: this is a registry/daemon issue, not an APT or
  kkRepo issue. Record the image reference and exact pull error.
- **`Hash Sum mismatch` or truncated Debian packages**: verify the correct
  current/archive repositories and that no old official source remains.
- **`NO_PUBKEY` for a vendor repository**: fetch its official signing key via
  the supplied proxy, dearmor it into a separate keyring, and use `signed-by=`.
  Do not globally disable signature checks.
- **Connection timeout**: distinguish kkRepo direct access, external proxy
  access, and `http://client` / Compose-service access. They are different paths.
- **kkRepo fails**: test one known repository URL with
  `curl --noproxy '*' --fail --connect-timeout 5 --max-time 20 <url>`.
  If it is unreachable, report the exact URL/error; do not alter the application.
- **404 / package not found**: check release, architecture, repository component,
  and whether that exact package/version exists. HTTP 200 alone is not proof.
- **Maven/Go still uses an old endpoint**: inspect the effective settings and
  explicit flags rather than adding another environment variable blindly.

Keep necessary dependencies, versions, signatures, and application behavior.
If correct configuration still fails, report an infrastructure error with the
exact dependency and output; do not hide it by replacing the implementation.
