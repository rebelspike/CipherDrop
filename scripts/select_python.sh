#!/bin/sh
# Print the first Python interpreter >=3.11 (prefer recent versioned binaries).
# Supports Homebrew Intel/Apple Silicon, python.org installations, and PATH.
for name in python3.14 python3.13 python3.12 python3.11 python3; do
  candidate=$(command -v "$name" 2>/dev/null || true)
  if [ -n "$candidate" ] && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' >/dev/null 2>&1; then
    printf '%s\n' "$candidate"
    exit 0
  fi
done
for prefix in /opt/homebrew/bin /usr/local/bin /Library/Frameworks/Python.framework/Versions/3.14/bin /Library/Frameworks/Python.framework/Versions/3.13/bin /Library/Frameworks/Python.framework/Versions/3.12/bin /Library/Frameworks/Python.framework/Versions/3.11/bin; do
  for name in python3.14 python3.13 python3.12 python3.11 python3; do
    candidate="$prefix/$name"
    if [ -x "$candidate" ] && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      exit 0
    fi
  done
done
exit 0
