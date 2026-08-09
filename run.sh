#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ ! -f "$ROOT/secure-log-scan.jar" ]]; then "$ROOT/build.sh" >/dev/null; fi
java \
  --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED \
  --add-exports java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED \
  --add-exports java.base/jdk.internal.org.objectweb.asm.tree.analysis=ALL-UNNAMED \
  -jar "$ROOT/secure-log-scan.jar" "$@"
