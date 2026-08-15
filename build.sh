#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
rm -rf "$ROOT/out" "$ROOT/secure-log-scan.jar"
mkdir -p "$ROOT/out"
javac -Xlint:all -Werror \
  --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED \
  --add-exports java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED \
  --add-exports java.base/jdk.internal.org.objectweb.asm.tree.analysis=ALL-UNNAMED \
  -d "$ROOT/out" $(find "$ROOT/src/main/java" -name '*.java' | sort)
jar --create --file "$ROOT/secure-log-scan.jar" --main-class securelogscan.SecureLogScan -C "$ROOT/out" .
echo "$ROOT/secure-log-scan.jar"
