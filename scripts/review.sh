#!/usr/bin/env bash
# Review the current changes in neovim and print the user's notes back.
#
#   scripts/review.sh            # working tree against HEAD
#   scripts/review.sh HEAD~3     # working tree against HEAD~3
#   scripts/review.sh v0.1..HEAD # any range git diff understands
#
# The review window opens in kitty (or a new tmux window), blocks until nvim
# exits, then prints the notes written in REVIEW.md.

set -euo pipefail

die() {
    local code=${2:-2}
    printf 'review: %s\n' "$1" >&2
    exit "$code"
}

root=$(git rev-parse --show-toplevel 2>/dev/null) || die "not a git repository"
base=${1:-HEAD}
git rev-parse --verify --quiet "$base^{commit}" >/dev/null || die "cannot resolve '$base'"

mapfile -t files < <(git diff --name-only --diff-filter=ACMR "$base" --)
if [[ "$base" != *..* ]]; then
    # New files are invisible to git diff until they are staged.
    while IFS= read -r path; do
        [ -n "$path" ] && files+=("$path")
    done < <(git ls-files --others --exclude-standard)
fi
[ "${#files[@]}" -eq 0 ] && { printf 'nothing to review against %s\n' "$base"; exit 0; }

name=$(basename "$root")
ws=${REVIEW_WORKSPACE:-/tmp/opencode/review/$name-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$ws/old"
review_md=$ws/REVIEW.md
manifest=$ws/manifest.json
jsonl=$ws/files.jsonl

printf '# Review: %s (base %s)\n\n' "$name" "$base" >"$review_md"
printf 'Оставь замечания под заголовком файла или хунка. `:qa` — вернуть их агенту,\n' >>"$review_md"
printf '`<CR>` на хункe — перейти к коду, `]f`/`[f` — следующий/предыдущий файл.\n\n' >>"$review_md"

: >"$jsonl"
kept=0
for path in "${files[@]}"; do
    size=$(stat -c %s "$root/$path" 2>/dev/null || printf 0)
    if [ "$size" -gt 2097152 ]; then
        printf 'skipping large file: %s\n' "$path" >&2
        continue
    fi

    mkdir -p "$ws/old/$(dirname "$path")"
    if git cat-file -e "$base:$path" 2>/dev/null; then
        git show "$base:$path" >"$ws/old/$path"
        hunks=$(git diff -U0 --no-color "$base" -- "$path" |
            awk '/^@@/ {
                split($3, a, ",");
                gsub(/\+/, "", a[1]);
                start = a[1] + 0;
                count = (a[2] == "" ? 1 : a[2]) + 0;
                if (count == 0) count = 1;
                printf "%d %d\n", start, start + count - 1;
            }')
    else
        : >"$ws/old/$path"
        lines=$(awk 'END { print NR }' "$root/$path")
        if [ "$lines" -eq 0 ]; then
            printf 'skipping empty new file: %s\n' "$path" >&2
            continue
        fi
        hunks=$(printf '1 %s\n' "$lines")
    fi
    [ -n "$hunks" ] || continue
    kept=$((kept + 1))

    printf '## %s\n\n' "$path" >>"$review_md"
    while read -r start end; do
        printf '### hunk %s-%s\n\n' "$start" "$end" >>"$review_md"
    done <<<"$hunks"

    hunks_json=$(printf '%s\n' "$hunks" |
        jq -R -s 'split("\n") | map(select(length > 0) | split(" ") | {start: (.[0] | tonumber), end: (.[1] | tonumber)})')
    jq -c -n --arg rel "$path" --arg path "$root/$path" --arg old "$ws/old/$path" --argjson hunks "$hunks_json" \
        '{rel: $rel, path: $path, old: $old, hunks: $hunks}' >>"$jsonl"
done

if [ "$kept" -eq 0 ]; then
    printf 'nothing to review against %s after skips\n' "$base"
    exit 0
fi

jq -n --arg workspace "$ws" --arg root "$root" --arg base "$base" \
    --slurpfile files "$jsonl" \
    '{workspace: $workspace, root: $root, base: $base, files: $files}' >"$manifest"

if [ -n "${REVIEW_DRY_RUN:-}" ]; then
    printf '%s\n' "$ws"
    exit 0
fi

export REVIEW_LUA="$root/scripts/review.lua"
export REVIEW_MANIFEST="$manifest"

if command -v kitty >/dev/null 2>&1; then
    kitty --class review --title "review: $name ($base)" \
        nvim -c 'lua dofile(vim.env.REVIEW_LUA)' \
        -c 'lua ReviewSetup(vim.env.REVIEW_MANIFEST)'
elif [ -n "${TMUX:-}" ]; then
    tmux new-window -n review \
        "nvim -c 'lua dofile(vim.env.REVIEW_LUA)' -c 'lua ReviewSetup(vim.env.REVIEW_MANIFEST)'"
else
    die "need kitty or a tmux session to open the review window" 3
fi

if [ -s "$ws/comments.md" ]; then
    cat "$ws/comments.md"
else
    printf 'no review comments\n'
fi
printf '\nreview workspace: %s\n' "$ws"
