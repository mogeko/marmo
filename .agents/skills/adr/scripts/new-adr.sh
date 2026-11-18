#!/bin/sh
# Create the next ADR from docs/decisions/0000-template.md.
# Usage: new-adr.sh <kebab-slug> ["Short title"]
set -eu

if [ $# -lt 1 ]; then
    echo "usage: $0 <kebab-slug> [\"Short title\"]" >&2
    exit 64
fi

slug=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr ' _' '--' | tr -cd 'a-z0-9-')
if [ -z "$slug" ]; then
    echo "error: slug must contain at least one letter or digit" >&2
    exit 64
fi

title=${2:-$(printf '%s' "$slug" | tr '-' ' ')}
root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
dir="$root/docs/decisions"
template="$dir/0000-template.md"

if [ ! -f "$template" ]; then
    echo "error: template not found: $template" >&2
    exit 1
fi

last=$(find "$dir" -maxdepth 1 -name '[0-9][0-9][0-9][0-9]-*.md' -exec basename {} \; \
    | sed 's/-.*//' | sort -n | tail -1)
n=$(printf '%s' "${last:-0}" | sed 's/^0*//')
n=${n:-0}
next=$(printf '%04d' $((n + 1)))
file="$dir/$next-$slug.md"

if [ -e "$file" ]; then
    echo "error: already exists: $file" >&2
    exit 1
fi

today=$(date +%Y-%m-%d)
sed -e "s/ADR-NNNN/ADR-$next/" \
    -e "s/^# ADR-$next: Title/# ADR-$next: $title/" \
    -e "s/YYYY-MM-DD/$today/" \
    "$template" > "$file"

echo "$file"
