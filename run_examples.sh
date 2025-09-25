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
