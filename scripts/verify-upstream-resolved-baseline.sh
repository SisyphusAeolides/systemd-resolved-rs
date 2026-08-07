#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE="$ROOT/compat/upstream-systemd"
WORK="$(mktemp -d -t resolved-upstream-baseline.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

for required in repository release commit baseline.json resolve-source.sha256 resolve-tests.sha256 surfaces.txt; do
    [[ -s "$BASELINE/$required" ]] || {
        printf 'Missing upstream baseline file: %s\n' "$BASELINE/$required" >&2
        exit 1
    }
done

repository=$(cat "$BASELINE/repository")
release=$(cat "$BASELINE/release")
commit=$(cat "$BASELINE/commit")

[[ $repository == https://github.com/systemd/systemd.git ]] || {
    printf 'Unexpected upstream repository: %s\n' "$repository" >&2
    exit 1
}
[[ $release =~ ^v[0-9]+$ ]] || {
    printf 'Unexpected upstream release: %s\n' "$release" >&2
    exit 1
}
[[ $commit =~ ^[0-9a-f]{40}$ ]] || {
    printf 'Unexpected upstream commit: %s\n' "$commit" >&2
    exit 1
}

python3 - "$BASELINE/baseline.json" "$repository" "$release" "$commit" <<'PY'
import json
import sys

path, repository, release, commit = sys.argv[1:]
data = json.load(open(path, encoding="utf-8"))
if data.get("repository") != repository:
    raise SystemExit("baseline repository JSON mismatch")
if data.get("release") != release:
    raise SystemExit("baseline release JSON mismatch")
if data.get("commit") != commit:
    raise SystemExit("baseline commit JSON mismatch")
PY

git clone --filter=blob:none --no-checkout "$repository" "$WORK/systemd"
git -C "$WORK/systemd" fetch --depth 1 origin "$commit"
git -C "$WORK/systemd" checkout --detach "$commit"
[[ $(git -C "$WORK/systemd" rev-parse HEAD) == "$commit" ]] || {
    printf 'Fetched upstream commit does not match the baseline.\n' >&2
    exit 1
}
git -C "$WORK/systemd" fetch --tags --force
[[ $(git -C "$WORK/systemd" rev-list -n1 "$release") == "$commit" ]] || {
    printf 'Release %s no longer resolves to %s.\n' "$release" "$commit" >&2
    exit 1
}

(
    cd "$WORK/systemd"
    sha256sum --check --strict "$BASELINE/resolve-source.sha256"
    sha256sum --check --strict "$BASELINE/resolve-tests.sha256"
)

python3 - "$WORK/systemd" "$BASELINE/surfaces.txt" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
manifest = Path(sys.argv[2])
recorded = [line for line in manifest.read_text(encoding="utf-8").splitlines() if line]
if recorded != sorted(set(recorded)):
    raise SystemExit("upstream surface manifest is not sorted and unique")
missing = [path for path in recorded if not (root / path).is_file()]
if missing:
    raise SystemExit("missing upstream surfaces: " + ", ".join(missing[:20]))
actual = []
for path in sorted((root / "src" / "resolve").rglob("*")):
    if path.is_file():
        actual.append(path.relative_to(root).as_posix())
for path in sorted((root / "test").rglob("*")):
    if not path.is_file():
        continue
    relative = path.relative_to(root).as_posix()
    lowered = path.name.lower()
    if "TEST-75-RESOLVED" in relative or any(
        token in lowered for token in ("resolved", "resolve", "mdns", "dnssd")
    ):
        actual.append(relative)
actual = sorted(set(actual))
if recorded != actual:
    missing_recorded = sorted(set(actual) - set(recorded))
    stale_recorded = sorted(set(recorded) - set(actual))
    raise SystemExit(
        "upstream surface manifest differs; unrecorded="
        + repr(missing_recorded[:20])
        + " stale="
        + repr(stale_recorded[:20])
    )
PY

if [[ -d "$BASELINE/interfaces" ]]; then
    while IFS= read -r -d '' local_file; do
        basename=${local_file##*/}
        upstream_file="$WORK/systemd/src/resolve/$basename"
        [[ -f $upstream_file ]] || {
            printf 'Pinned interface file disappeared upstream: %s\n' "$basename" >&2
            exit 1
        }
        cmp --silent "$local_file" "$upstream_file" || {
            printf 'Pinned interface file differs: %s\n' "$basename" >&2
            exit 1
        }
    done < <(find "$BASELINE/interfaces" -maxdepth 1 -type f -print0 | sort -z)
fi

printf 'Verified systemd-resolved baseline %s at %s.\n' "$release" "$commit"
