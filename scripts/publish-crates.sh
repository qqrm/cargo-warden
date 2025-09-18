#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]]; then
  echo "CARGO_REGISTRY_TOKEN is required" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to compute the publish order" >&2
  exit 1
fi

if ! command -v tsort >/dev/null 2>&1; then
  echo "tsort is required to compute the publish order" >&2
  exit 1
fi

ROOT_DIR=$(git rev-parse --show-toplevel)
cd "$ROOT_DIR"

PUBLISH_INTERVAL="${PUBLISH_INTERVAL_SECONDS:-45}"
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --interval)
      if [[ $# -lt 2 ]]; then
        echo "--interval requires a value" >&2
        exit 1
      fi
      PUBLISH_INTERVAL="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

metadata_file=$(mktemp)
trap 'rm -f "$metadata_file"' EXIT

cargo metadata --format-version 1 --locked >"$metadata_file"

mapfile -t package_lines < <(
  jq -r '
    def is_publishable:
      if .publish == null then true
      elif .publish == false then false
      elif (.publish | type) == "boolean" then .publish
      elif (.publish | type) == "array" then (.publish | length > 0)
      else true
      end;

    . as $root
    | $root.workspace_members as $members
    | [ $root.packages[]
        | select(.id as $id | $members | index($id))
        | select(is_publishable)
      ]
    | map({key: .id, value: {name: .name, version: .version}})
    | from_entries
    | to_entries[]
    | "\(.value.name)\t\(.value.version)\t\(.key)"
  ' "$metadata_file"
)

declare -A inbound
declare -A dependents

if [[ ${#package_lines[@]} -eq 0 ]]; then
  echo "No publishable workspace members found" >&2
  exit 1
fi

declare -A versions
declare -A ids
packages=()

for line in "${package_lines[@]}"; do
  IFS=$'\t' read -r name version pkg_id <<<"$line"
  versions["$name"]="$version"
  ids["$name"]="$pkg_id"
  packages+=("$name")
done

mapfile -t edge_lines < <(
  jq -r '
    def is_publishable:
      if .publish == null then true
      elif .publish == false then false
      elif (.publish | type) == "boolean" then .publish
      elif (.publish | type) == "array" then (.publish | length > 0)
      else true
      end;

    . as $root
    | $root.workspace_members as $members
    | [ $root.packages[]
        | select(.id as $id | $members | index($id))
        | select(is_publishable)
      ] as $workspace_array
    | ($workspace_array
        | map({key: .id, value: {name: .name}})
        | from_entries) as $workspace
    | $root.resolve.nodes[]
    | select(.id as $id | $workspace | has($id))
    | . as $node
    | $workspace[$node.id].name as $name
    | $node.dependencies[]?
    | select($workspace[.]? != null)
    | [$name, $workspace[.].name]
    | @tsv
  ' "$metadata_file"
)

for pkg in "${packages[@]}"; do
  inbound["$pkg"]=0
  dependents["$pkg"]=""
done

for edge in "${edge_lines[@]}"; do
  IFS=$'\t' read -r dependent dependency <<<"$edge"
  if [[ -z "$dependent" || -z "$dependency" ]]; then
    continue
  fi
  inbound["$dependent"]=$((inbound["$dependent"] + 1))
  if [[ -n "${dependents[$dependency]}" ]]; then
    dependents["$dependency"]+=" $dependent"
  else
    dependents["$dependency"]="$dependent"
  fi
done

queue=()
for pkg in "${packages[@]}"; do
  if [[ ${inbound[$pkg]} -eq 0 ]]; then
    queue+=("$pkg")
  fi
done

ordered_packages=()
while [[ ${#queue[@]} -gt 0 ]]; do
  current="${queue[0]}"
  queue=("${queue[@]:1}")
  ordered_packages+=("$current")
  for dependent in ${dependents[$current]}; do
    inbound["$dependent"]=$((inbound["$dependent"] - 1))
    if [[ ${inbound[$dependent]} -eq 0 ]]; then
      queue+=("$dependent")
    fi
  done
done

declare -A seen
for pkg in "${ordered_packages[@]}"; do
  seen["$pkg"]=1
done

for pkg in "${packages[@]}"; do
  if [[ -z "${seen[$pkg]:-}" ]]; then
    ordered_packages+=("$pkg")
  fi
done


is_published() {
  local crate_name="$1"
  local crate_version="$2"
  if curl -sfS "https://crates.io/api/v1/crates/${crate_name}/${crate_version}" \
    >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

declare -i index=0
count=${#ordered_packages[@]}

for crate in "${ordered_packages[@]}"; do
  ((++index))
  version="${versions[$crate]}"
  echo "==> Processing ${crate} v${version}" >&2
  if is_published "$crate" "$version"; then
    echo "    Skipping ${crate} v${version}: already published" >&2
    continue
  fi

  publish_args=(publish --locked --package "$crate")
  if [[ "$DRY_RUN" == true ]]; then
    publish_args+=(--dry-run)
  fi

  echo "    Publishing ${crate} v${version}" >&2
  cargo "${publish_args[@]}"

  if [[ "$DRY_RUN" == false && $index -lt $count ]]; then
    echo "    Waiting ${PUBLISH_INTERVAL} seconds for crate propagation" >&2
    sleep "$PUBLISH_INTERVAL"
  fi

done

