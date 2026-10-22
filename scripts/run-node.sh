#!/bin/sh
if command -v node >/dev/null 2>&1; then
  exec node "$@"
elif [ -x "/Applications/Antigravity.app/Contents/MacOS/Antigravity" ]; then
  ELECTRON_RUN_AS_NODE=1 exec "/Applications/Antigravity.app/Contents/MacOS/Antigravity" "$@"
else
  echo "Error: Node.js runtime not found." >&2
  exit 1
fi
