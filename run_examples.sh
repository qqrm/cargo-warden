#!/usr/bin/env bash
set -euo pipefail

declare -A EXAMPLE_DIRS=(
    [network-build]="network-build"
    [spawn-bash]="spawn-bash"
    [fs-outside-workspace]="fs-outside-workspace"
    [ex_proc_macro_hog]="proc-macro-hog"
)

EXAMPLE_ORDER=(
    network-build
    spawn-bash
    fs-outside-workspace
    ex_proc_macro_hog
)

run_example() {
    local label="$1"
    local dir="$2"

    if [[ "${ran_any:-0}" -eq 1 ]]; then
        printf '\n'
    fi

    printf '== %s ==\n' "$label"
    (
        cd "examples/$dir"
        if [[ "$label" == "ex_proc_macro_hog" ]]; then
            WARDEN_EXAMPLE_EXPECT_WARNING=1 cargo build
        else
            cargo build
        fi
    )
    ran_any=1
}

if [[ $# -gt 0 ]]; then
    for example in "$@"; do
        dir=${EXAMPLE_DIRS[$example]:-}
        if [[ -z "${dir:-}" ]]; then
            printf 'error: unknown example "%s"\n' "$example" >&2
            printf 'available examples: %s\n' "${EXAMPLE_ORDER[*]}" >&2
            exit 1
        fi
        run_example "$example" "$dir"
    done
else
    for example in "${EXAMPLE_ORDER[@]}"; do
        run_example "$example" "${EXAMPLE_DIRS[$example]}"
    done
fi

run_network_build() {
    cargo build -p warden-network-build
}

run_spawn_bash() {
    cargo build -p warden-spawn-bash
}

run_fs_outside_workspace() {
    cargo build -p warden-fs-outside-workspace
}

run_git_clone_https() {
    local output
    if [[ ${WARDEN_EXAMPLE_REMOTE+x} ]]; then
        output=$(WARDEN_EXAMPLE_REMOTE="$WARDEN_EXAMPLE_REMOTE" cargo build -p warden-git-clone-https 2>&1)
    else
        output=$(cargo build -p warden-git-clone-https 2>&1)
    fi
    printf '%s\n' "$output"
    if ! grep -q "git clone blocked as expected" <<<"$output"; then
        echo "expected git clone denial message not found" >&2
        exit 1
    fi
}

print_header() {
    local first_flag_ref=$1
    local name=$2
    if [[ ${!first_flag_ref} -eq 0 ]]; then
        printf '\n'
    else
        printf ''
    fi
    printf '== %s ==\n' "$name"
    printf -v "$first_flag_ref" '%s' '0'
}

run_example() {
    local key=$1
    case "$key" in
        network-build)
            print_header first_flag "network-build"
            run_network_build
            ;;
        spawn-bash)
            print_header first_flag "spawn-bash"
            run_spawn_bash
            ;;
        fs-outside-workspace)
            print_header first_flag "fs-outside-workspace"
            run_fs_outside_workspace
            ;;
        ex_git_clone_https)
            print_header first_flag "ex_git_clone_https"
            run_git_clone_https
            ;;
        *)
            echo "unknown example: $key" >&2
            exit 1
            ;;
    esac
}

main() {
    first_flag=1
    if [[ $# -gt 0 ]]; then
        for example in "$@"; do
            run_example "$example"
        done
    else
        for example in network-build spawn-bash fs-outside-workspace ex_git_clone_https; do
            run_example "$example"
        done
    fi
}

main "$@"
