#!/usr/bin/env bash

# Rename /internal folders to /external
find . -type d -name 'internal' -print0 |
    while IFS= read -r -d '' d; do
        mv "$d" "${d//internal/external}"
    done

# Rename '/internal/' imports in .go files to '/external/'
grep -rl --include \*.go '/internal\/' . | xargs sed -i '' 's/\/internal\//\/external\//g'

# Rename '/internal' imports in .go files to '/external'
grep -rl --include \*.go '/internal"' . | xargs sed -i '' 's/\/internal"/\/external"/g'

