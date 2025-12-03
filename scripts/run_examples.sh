#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ensure_bpf_bundle() {
    if [[ -n ${WARDEN_BPF_DIST_DIR:-} ]]; then
        return
    fi

    local prebuilt_dir="$ROOT_DIR/prebuilt"
    if [[ ! -f "$prebuilt_dir/manifest.json" ]]; then
        echo "== building local eBPF bundle =="
        "$ROOT_DIR/scripts/build-bpf.sh"
    fi

    export WARDEN_BPF_DIST_DIR="$prebuilt_dir"
}

warden() {
    if command -v cargo-warden >/dev/null 2>&1; then
        cargo warden "$@"
    else
        cargo run --bin cargo-warden -- "$@"
    fi
}

run_network_build() {
    warden run -- cargo build -p warden-network-build
}

run_spawn_bash() {
    warden run -- cargo build -p warden-spawn-bash
}

run_fs_outside_workspace() {
    warden run -- cargo build -p warden-fs-outside-workspace
}

run_network_fs_demo() {
    warden run -- cargo build -p warden-network-fs-demo
}

run_git_clone_https() {
    local output
    if [[ ${WARDEN_EXAMPLE_REMOTE+x} ]]; then
        output=$(WARDEN_EXAMPLE_REMOTE="$WARDEN_EXAMPLE_REMOTE" warden run -- cargo build -p warden-git-clone-https 2>&1)
    else
        output=$(warden run -- cargo build -p warden-git-clone-https 2>&1)
    fi
    printf '%s\n' "$output"
    if ! grep -q "git clone blocked as expected" <<<"$output"; then
        echo "expected git clone denial message not found" >&2
        exit 1
    fi
}

print_header() {
    local flag_ref=$1
    local name=$2
    if [[ ${!flag_ref:-1} -eq 0 ]]; then
        printf '\n'
    fi
    printf '== %s ==\n' "$name"
    printf -v "$flag_ref" '%s' '0'
}

run_example() {
    local key=$1
    local flag_ref=$2
    case "$key" in
        network-build)
            print_header "$flag_ref" "network-build"
            run_network_build
            ;;
        spawn-bash)
            print_header "$flag_ref" "spawn-bash"
            run_spawn_bash
            ;;
        fs-outside-workspace)
            print_header "$flag_ref" "fs-outside-workspace"
            run_fs_outside_workspace
            ;;
        network-fs-demo)
            print_header "$flag_ref" "network-fs-demo"
            run_network_fs_demo
            ;;
        ex_git_clone_https)
            print_header "$flag_ref" "ex_git_clone_https"
            run_git_clone_https
            ;;
        ex_proc_macro_hog)
            print_header "$flag_ref" "ex_proc_macro_hog"
            WARDEN_EXAMPLE_EXPECT_WARNING=1 cargo build -p warden-proc-macro-hog
            ;;
        *)
            echo "unknown example: $key" >&2
            echo "available examples: network-build spawn-bash fs-outside-workspace ex_git_clone_https ex_proc_macro_hog" >&2
            exit 1
            ;;
    esac
}

main() {
    ensure_bpf_bundle

    local first=1
    if [[ $# -gt 0 ]]; then
        for example in "$@"; do
            run_example "$example" first
        done
    else
        for example in network-build spawn-bash fs-outside-workspace network-fs-demo ex_git_clone_https ex_proc_macro_hog; do
            run_example "$example" first
        done
    fi
}

main "$@"
