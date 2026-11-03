# Shared launch for CVE-Factory, WebExploit and CyberGym.
# Develop on wuyida-01. Run tasks on the worker below. Update this address
# when the worker pod IP changes; the three run-*.sh scripts all use it.
CDB_WORKER="${CDB_WORKER:-wuyida-swift443-nvme-16gpu-v2-cfcd2.wuyida+root.ailab-safeshared.pod@h.pjlab.org.cn}"

on_worker() {
    local have_nvme=0
    if [[ "${CDB_NVME_PRESENT:-}" == yes ]]; then
        have_nvme=1
    elif [[ -z "${CDB_NVME_PRESENT:-}" ]] && mountpoint -q /nvme; then
        have_nvme=1
    fi
    # wuyida-01 has no /nvme. Do not start Docker here.
    if [[ -z "${CDB_ON_WORKER:-}" && "$have_nvme" -eq 0 ]]; then
        local remote argument
        remote="cd $(printf '%q' "$ROOT") && CDB_ON_WORKER=1 CDB_MODEL_ENV_FILE=$(printf %q "${CDB_MODEL_ENV_FILE:-}") CDB_MODEL=$(printf '%q' "${CDB_MODEL:-}") exec $(printf '%q' "$0")"
        for argument in "$@"; do
            remote+=" $(printf '%q' "$argument")"
        done
        if [[ "${CDB_WORKER_SSH:-exec}" == print ]]; then
            printf 'ssh %s %s\n' "$CDB_WORKER" "$remote"
            return 0
        fi
        printf 'wuyida-01 -> %s\n' "$CDB_WORKER" >&2
        exec ssh -o BatchMode=yes -o ConnectTimeout=10 "$CDB_WORKER" "$remote"
    fi
    if [[ "$have_nvme" -eq 0 ]]; then
        printf 'worker %s has no /nvme; refusing to run\n' "$CDB_WORKER" >&2
        exit 1
    fi
    export CDB_ON_WORKER=1
    export CDB_LOCAL_DOCKER_DATA=1
    export CDB_DOCKER_DATA_ROOT=/nvme/cyberdockerbench/docker-data
    export CDB_STORAGE_DRIVER=overlay2
    # CyberGym agent sandboxes: put the inner dockerd data-root on real xfs so
    # it can use kernel overlay2 (the worker's own root is overlayfs, which
    # forces fuse-overlayfs).
    export CYBERGYM_DOCKER_ROOT_BASE=/nvme/cyberdockerbench/cybergym-docker
    # kkRepo is the default Docker Hub proxy. The legacy cache is opt-in.
    if [[ "${CDB_ENABLE_HUB_CACHE:-0}" == 1 ]]; then
        # A pod IP, not an SSH alias (which may resolve to the bastion).
        local worker_host
        worker_host="$(hostname -I | awk '{print $1}')"
        export CDB_REGISTRY_MIRROR="http://${worker_host}:5000"
        export CDB_REGISTRY_MIRRORS="$CDB_REGISTRY_MIRROR"
        export CYBERGYM_REGISTRY_MIRROR="$CDB_REGISTRY_MIRROR"
    else
        unset CDB_REGISTRY_MIRROR CDB_REGISTRY_MIRRORS CYBERGYM_REGISTRY_MIRROR
    fi
    if [[ "${CDB_WORKER_SSH:-exec}" != print ]]; then
        mkdir -p "$CDB_DOCKER_DATA_ROOT"
        test -w "$CDB_DOCKER_DATA_ROOT"
        mkdir -p "$CYBERGYM_DOCKER_ROOT_BASE"
        test -w "$CYBERGYM_DOCKER_ROOT_BASE"
        if [[ "${CDB_ENABLE_HUB_CACHE:-0}" == 1 ]]; then
            bash "$ROOT/harness/registry/ensure-registry.sh"
        fi
    fi
}

# Keep the batch console log inside the batch directory, next to the tasks.
capture_batch_log() {
    local batch_dir="$1"
    local log
    mkdir -p "$batch_dir"
    log="$batch_dir/$(basename "$batch_dir").launch.log"
    exec > >(tee -a "$log") 2>&1
}
