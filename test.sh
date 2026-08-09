#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"

cleanup() {
  rm -rf "$ROOT/demo-out" "$ROOT/test-out" "$ROOT/test-out21" "$ROOT/sanitized-only-out" \
         "$ROOT/possible-only-out" "$ROOT/safe-only-out" "$ROOT/model-out" "$ROOT/model-scan-out" \
         "$ROOT/test-fixtures.jar" "$ROOT/dep-out" "$ROOT/app-out" "$ROOT/empty-app-out" \
         "$ROOT/dep-fixtures.jar" "$ROOT/boot-fixture.jar" "$ROOT/war-fixture.war" \
         "$ROOT/mr-base-out" "$ROOT/mr21-out" "$ROOT/mr-app-out" "$ROOT/mr-fixture.jar" \
         "$ROOT/dupe-app-out" "$ROOT/dupe-dep-out" "$ROOT/dupe-dependency.jar" \
         "$ROOT/module-out" "$ROOT/test-dependency-module.jar" \
         "$ROOT/async-api-out" "$ROOT/async-out" "$ROOT/async-out21" "$ROOT/diagnostics-out" \
         "$ROOT/exception-out" "$ROOT/.dependency-jar-root" "$ROOT/.boot-root" "$ROOT/.war-root" "$ROOT/.mr-root" "$ROOT/.test-tmp"
}
trap cleanup EXIT

"$ROOT/build.sh" >/dev/null
cleanup
mkdir -p "$ROOT/demo-out" "$ROOT/test-out" "$ROOT/test-out21" "$ROOT/sanitized-only-out" \
  "$ROOT/possible-only-out" "$ROOT/safe-only-out" "$ROOT/model-out" "$ROOT/model-scan-out" \
  "$ROOT/dep-out" "$ROOT/app-out" "$ROOT/empty-app-out" "$ROOT/mr-base-out" "$ROOT/mr21-out" \
  "$ROOT/mr-app-out" "$ROOT/dupe-app-out" "$ROOT/dupe-dep-out" "$ROOT/module-out" \
  "$ROOT/async-api-out" "$ROOT/async-out" "$ROOT/async-out21" "$ROOT/diagnostics-out" \
  "$ROOT/exception-out" "$ROOT/.test-tmp"

JAVAC_VERSION="$(javac -version 2>&1 | awk '{print $2}')"
JAVAC_MAJOR="${JAVAC_VERSION%%.*}"
if [[ "$JAVAC_MAJOR" == "1" ]]; then
  JAVAC_MAJOR="$(cut -d. -f2 <<<"$JAVAC_VERSION")"
fi

javac --release 17 -Xlint:all,-serial -Werror \
  -cp "$ROOT/secure-log-scan.jar" -d "$ROOT/demo-out" "$ROOT/demo/demo/Demo.java"

javac --release 17 -Xlint:all,-serial -Werror \
  -cp "$ROOT/secure-log-scan.jar" -d "$ROOT/test-out" \
  $(find "$ROOT/testsrc" -name '*.java' | sort)

javac --release 17 -Xlint:all,-serial -Werror \
  -cp "$ROOT/secure-log-scan.jar:$ROOT/test-out" -d "$ROOT/diagnostics-out" \
  $(find "$ROOT/testsrc-diagnostics" -name '*.java' | sort)

javac --release 17 -Xlint:all,-serial -Werror \
  -cp "$ROOT/secure-log-scan.jar:$ROOT/test-out" -d "$ROOT/sanitized-only-out" \
  $(find "$ROOT/testsrc-sanitized-only" -name '*.java' | sort)

javac --release 17 -Xlint:all,-serial -Werror \
  -cp "$ROOT/secure-log-scan.jar" -d "$ROOT/possible-only-out" \
  $(find "$ROOT/testsrc-possible-only" -name '*.java' | sort)

javac --release 17 -Xlint:all,-serial -Werror \
  -cp "$ROOT/secure-log-scan.jar" -d "$ROOT/safe-only-out" \
  $(find "$ROOT/testsrc-safe-only" -name '*.java' | sort)


javac --release 17 -Xlint:all,-serial -Werror \
  -cp "$ROOT/secure-log-scan.jar" -d "$ROOT/model-out" \
  $(find "$ROOT/testsrc-models" -name '*.java' | sort)
mkdir -p "$ROOT/model-scan-out/models"
cp "$ROOT/model-out"/models/MethodModelCases*.class "$ROOT/model-scan-out/models/"


# Async/callback reachability fixtures. The external Registry API is intentionally omitted from scanner inputs.
javac --release 17 -Xlint:all,-serial -Werror \
  -d "$ROOT/async-api-out" \
  $(find "$ROOT/testsrc-async-api" -name '*.java' | sort)

javac --release 17 -Xlint:all,-serial -Werror \
  -cp "$ROOT/secure-log-scan.jar:$ROOT/async-api-out" -d "$ROOT/async-out" \
  $(find "$ROOT/testsrc-async" -name '*.java' | sort)

javac --release 17 -Xlint:all,-serial -Werror \
  -cp "$ROOT/secure-log-scan.jar" -d "$ROOT/exception-out" \
  $(find "$ROOT/testsrc-exceptions" -name '*.java' | sort)

MODERN_ENABLED=false
if (( JAVAC_MAJOR >= 21 )) && [[ "${SECURE_LOG_SCAN_SKIP_JAVA21:-false}" != "true" ]]; then
  MODERN_ENABLED=true
  javac --release 21 -Xlint:all,-serial -Werror \
    -cp "$ROOT/secure-log-scan.jar:$ROOT/test-out" -d "$ROOT/test-out21" \
    $(find "$ROOT/testsrc21" -name '*.java' | sort)
  cp -R "$ROOT/test-out21"/. "$ROOT/test-out"/
  javac --release 21 -Xlint:all,-serial -Werror \
    -cp "$ROOT/secure-log-scan.jar:$ROOT/async-api-out:$ROOT/async-out" -d "$ROOT/async-out21" \
    $(find "$ROOT/testsrc21-async" -name '*.java' | sort)
  cp -R "$ROOT/async-out21"/. "$ROOT/async-out"/
fi


# Dependency/classpath fixtures.
javac --release 17 -Xlint:all,-serial -Werror \
  -cp "$ROOT/secure-log-scan.jar" -d "$ROOT/dep-out" \
  $(find "$ROOT/testsrc-dependency/dep" -name '*.java' | sort)

mkdir -p "$ROOT/.dependency-jar-root/META-INF/maven/com.acme/customer-model"
cat > "$ROOT/.dependency-jar-root/META-INF/maven/com.acme/customer-model/pom.properties" <<'EOF_DEP_PROPERTIES'
groupId=com.acme
artifactId=customer-model
version=4.2
EOF_DEP_PROPERTIES
jar --create --file "$ROOT/dep-fixtures.jar" \
  --manifest <(printf 'Manifest-Version: 1.0\nAutomatic-Module-Name: com.acme.customer.model\nImplementation-Title: Customer Model\nImplementation-Version: 4.2\n\n') \
  -C "$ROOT/dep-out" . -C "$ROOT/.dependency-jar-root" META-INF

javac --release 17 -Xlint:all,-serial -Werror \
  -cp "$ROOT/secure-log-scan.jar:$ROOT/dep-out" -d "$ROOT/app-out" \
  $(find "$ROOT/testsrc-dependency/app" -name '*.java' | sort)

javac --release 17 -Xlint:all,-serial -Werror \
  -d "$ROOT/empty-app-out" \
  $(find "$ROOT/testsrc-dependency/emptyapp" -name '*.java' | sort)

mkdir -p "$ROOT/.boot-root/BOOT-INF/classes" "$ROOT/.boot-root/BOOT-INF/lib"
cp -R "$ROOT/app-out"/. "$ROOT/.boot-root/BOOT-INF/classes"/
cp "$ROOT/dep-fixtures.jar" "$ROOT/.boot-root/BOOT-INF/lib/customer-model-4.2.jar"
jar --create --file "$ROOT/boot-fixture.jar" -C "$ROOT/.boot-root" .

mkdir -p "$ROOT/.war-root/WEB-INF/classes" "$ROOT/.war-root/WEB-INF/lib"
cp -R "$ROOT/app-out"/. "$ROOT/.war-root/WEB-INF/classes"/
cp "$ROOT/dep-fixtures.jar" "$ROOT/.war-root/WEB-INF/lib/customer-model-4.2.jar"
jar --create --file "$ROOT/war-fixture.war" -C "$ROOT/.war-root" .

javac --release 17 -Xlint:all,-serial -Werror \
  -cp "$ROOT/secure-log-scan.jar" -d "$ROOT/mr-base-out" \
  $(find "$ROOT/testsrc-dependency/mrbase" -name '*.java' | sort)

javac --release 17 -Xlint:all,-serial -Werror \
  -cp "$ROOT/secure-log-scan.jar:$ROOT/mr-base-out" -d "$ROOT/mr-app-out" \
  $(find "$ROOT/testsrc-dependency/mrapp" -name '*.java' | sort)

if (( JAVAC_MAJOR >= 21 )); then
  javac --release 21 -Xlint:all,-serial -Werror \
    -cp "$ROOT/secure-log-scan.jar" -d "$ROOT/mr21-out" \
    $(find "$ROOT/testsrc-dependency/mr21" -name '*.java' | sort)
  mkdir -p "$ROOT/.mr-root/META-INF/versions/21"
  cp -R "$ROOT/mr-base-out"/. "$ROOT/.mr-root"/
  cp -R "$ROOT/mr21-out"/. "$ROOT/.mr-root/META-INF/versions/21"/
  cat > "$ROOT/.test-tmp/mr-manifest.mf" <<'EOF_MR_MANIFEST'
Manifest-Version: 1.0
Multi-Release: true
Automatic-Module-Name: mr.customer
Implementation-Version: 21

EOF_MR_MANIFEST
  jar --create --file "$ROOT/mr-fixture.jar" --manifest "$ROOT/.test-tmp/mr-manifest.mf" -C "$ROOT/.mr-root" .
fi

javac --release 17 -Xlint:all,-serial -Werror -d "$ROOT/dupe-app-out" \
  $(find "$ROOT/testsrc-dependency/dupeapp" -name '*.java' | sort)
javac --release 17 -Xlint:all,-serial -Werror -d "$ROOT/dupe-dep-out" \
  $(find "$ROOT/testsrc-dependency/dupedep" -name '*.java' | sort)
jar --create --file "$ROOT/dupe-dependency.jar" -C "$ROOT/dupe-dep-out" .

javac --release 17 -Xlint:all,-serial -Werror -d "$ROOT/module-out" \
  $(find "$ROOT/testsrc-dependency/module" -name '*.java' | sort)
jar --create --file "$ROOT/test-dependency-module.jar" -C "$ROOT/module-out" .

run_expect_findings() {
  local output="$1"
  shift
  set +e
  "$ROOT/run.sh" --fail "$@" >"$output" 2>&1
  local code=$?
  set -e
  if [[ $code -ne 1 ]]; then
    cat "$output"
    echo "Expected scanner exit 1, got $code: $*" >&2
    exit 2
  fi
}


run_expect_success() {
  local output="$1"
  shift
  set +e
  "$ROOT/run.sh" --fail "$@" >"$output" 2>&1
  local code=$?
  set -e
  if [[ $code -ne 0 ]]; then
    cat "$output"
    echo "Expected scanner exit 0, got $code: $*" >&2
    exit 8
  fi
}

assert_sanitized() {
  local report="$1" method="$2"
  if ! grep -F "SANITIZED $method" "$report" >/dev/null; then
    cat "$report"
    echo "Missing expected sanitized flow: $method" >&2
    exit 9
  fi
}

assert_possible() {
  local report="$1" method="$2"
  if ! grep -F "POSSIBLE $method" "$report" >/dev/null; then
    cat "$report"
    echo "Missing expected possible flow: $method" >&2
    exit 11
  fi
}

assert_no_possible() {
  local report="$1" method="$2"
  if grep -F "POSSIBLE $method" "$report" >/dev/null; then
    cat "$report"
    echo "Unexpected possible flow: $method" >&2
    exit 12
  fi
}

assert_no_sanitized() {
  local report="$1" method="$2"
  if grep -F "SANITIZED $method" "$report" >/dev/null; then
    cat "$report"
    echo "Unexpected sanitized flow: $method" >&2
    exit 10
  fi
}

assert_analysis_complete() {
  local report="$1"
  if grep -q '^INCOMPLETE ' "$report"; then
    cat "$report"
    echo "Unexpected incomplete analysis" >&2
    exit 3
  fi
  grep -F 'analysis: COMPLETE' "$report" >/dev/null || {
    cat "$report"
    echo "Missing COMPLETE analysis status" >&2
    exit 13
  }
}

assert_finding() {
  local report="$1" method="$2"
  if ! grep -F "ERROR $method" "$report" >/dev/null; then
    cat "$report"
    echo "Missing expected finding: $method" >&2
    exit 4
  fi
}

assert_no_finding() {
  local report="$1" method="$2"
  if grep -F "ERROR $method" "$report" >/dev/null; then
    cat "$report"
    echo "Unexpected finding: $method" >&2
    exit 5
  fi
}

# Original v1/v2 regression fixture.
run_expect_findings "$ROOT/.test-tmp/demo.txt" "$ROOT/demo-out"
for needle in \
  'java.io.PrintStream.println' \
  'java.io.PrintStream.printf' \
  'java.util.logging.Logger.warning' \
  'callee logs value' \
  'derived: demo.Demo$Customer.shadow'; do
  grep -F "$needle" "$ROOT/.test-tmp/demo.txt" >/dev/null || {
    cat "$ROOT/.test-tmp/demo.txt"
    echo "Missing original regression output: $needle" >&2
    exit 6
  }
done
assert_analysis_complete "$ROOT/.test-tmp/demo.txt"

# Complete language/call/rendering matrix.
run_expect_findings "$ROOT/.test-tmp/matrix.txt" "$ROOT/test-out"
assert_analysis_complete "$ROOT/.test-tmp/matrix.txt"

grep '^ERROR matrix\.' "$ROOT/.test-tmp/matrix.txt" \
  | sed 's/^ERROR //' | sort -u > "$ROOT/.test-tmp/actual-positive.txt"
if $MODERN_ENABLED; then
  cp "$ROOT/testmatrix/expected-positive.txt" "$ROOT/.test-tmp/expected-positive.txt"
else
  grep -v '^matrix\.modern\.' "$ROOT/testmatrix/expected-positive.txt" \
    > "$ROOT/.test-tmp/expected-positive.txt"
fi
if ! diff -u "$ROOT/.test-tmp/expected-positive.txt" "$ROOT/.test-tmp/actual-positive.txt"; then
  echo "The exact positive-method matrix changed" >&2
  exit 7
fi

grep '^POSSIBLE matrix\.' "$ROOT/.test-tmp/matrix.txt" \
  | sed 's/^POSSIBLE //' | sort -u > "$ROOT/.test-tmp/actual-possible.txt"
if ! diff -u "$ROOT/testmatrix/expected-possible.txt" "$ROOT/.test-tmp/actual-possible.txt"; then
  echo "The exact possible-method matrix changed" >&2
  exit 14
fi

while IFS= read -r method; do
  [[ -z "$method" ]] || assert_no_finding "$ROOT/.test-tmp/matrix.txt" "$method"
done < "$ROOT/testmatrix/expected-safe.txt"

while IFS= read -r method; do
  [[ -z "$method" ]] || assert_finding "$ROOT/.test-tmp/matrix.txt" "$method"
done < "$ROOT/testmatrix/expected-legacy-positive.txt"

# A custom secure annotation is ignored by default and recognized when configured.
assert_no_finding "$ROOT/.test-tmp/matrix.txt" 'custom.CustomAnnotationCases.configuredAnnotation()V'
run_expect_findings "$ROOT/.test-tmp/custom-annotation.txt" \
  --annotation=custom.Confidential "$ROOT/test-out"
assert_finding "$ROOT/.test-tmp/custom-annotation.txt" 'custom.CustomAnnotationCases.configuredAnnotation()V'


# Sanitization state is separate from unsafe taint and survives normal Java flows.
grep '^ERROR sanitize\.' "$ROOT/.test-tmp/matrix.txt" \
  | sed 's/^ERROR //' | sort -u > "$ROOT/.test-tmp/actual-sanitize-unsafe.txt"
grep '^SANITIZED sanitize\.' "$ROOT/.test-tmp/matrix.txt" \
  | sed 's/^SANITIZED //' | sort -u > "$ROOT/.test-tmp/actual-sanitized.txt"
diff -u "$ROOT/testmatrix/expected-sanitize-unsafe.txt" "$ROOT/.test-tmp/actual-sanitize-unsafe.txt"
diff -u "$ROOT/testmatrix/expected-sanitized.txt" "$ROOT/.test-tmp/actual-sanitized.txt"
assert_no_finding "$ROOT/.test-tmp/matrix.txt" 'sanitize.SanitizeCases.untrackedValue()V'
assert_no_sanitized "$ROOT/.test-tmp/matrix.txt" 'sanitize.SanitizeCases.untrackedValue()V'
grep -F 'description: Stable one-way log correlation value' "$ROOT/.test-tmp/matrix.txt" >/dev/null
grep -F 'justification: Approved security utility SEC-1421' "$ROOT/.test-tmp/matrix.txt" >/dev/null

# MDC and thread-context writes are first-class CONTEXT_CAPTURE sinks.
grep '^ERROR context\.' "$ROOT/.test-tmp/matrix.txt" \
  | sed 's/^ERROR //' | sort -u > "$ROOT/.test-tmp/actual-context-unsafe.txt"
grep '^SANITIZED context\.' "$ROOT/.test-tmp/matrix.txt" \
  | sed 's/^SANITIZED //' | sort -u > "$ROOT/.test-tmp/actual-context-sanitized.txt"
diff -u "$ROOT/testmatrix/expected-context-unsafe.txt" "$ROOT/.test-tmp/actual-context-unsafe.txt"
diff -u "$ROOT/testmatrix/expected-context-sanitized.txt" "$ROOT/.test-tmp/actual-context-sanitized.txt"
grep '^POSSIBLE context\.' "$ROOT/.test-tmp/matrix.txt" \
  | sed 's/^POSSIBLE //' | sort -u > "$ROOT/.test-tmp/actual-context-possible.txt"
diff -u "$ROOT/testmatrix/expected-context-possible.txt" "$ROOT/.test-tmp/actual-context-possible.txt"
assert_possible "$ROOT/.test-tmp/matrix.txt" 'context.MdcCases.possibleUnknownContextCapture()V'
grep -A8 -F 'POSSIBLE context.MdcCases.possibleUnknownContextCapture()V' "$ROOT/.test-tmp/matrix.txt" \
  | grep -F 'category: CONTEXT_CAPTURE' >/dev/null
assert_no_finding "$ROOT/.test-tmp/matrix.txt" 'context.MdcCases.clearAndRemoveAreNotCapture()V'
assert_no_sanitized "$ROOT/.test-tmp/matrix.txt" 'context.MdcCases.clearAndRemoveAreNotCapture()V'
assert_no_finding "$ROOT/.test-tmp/matrix.txt" 'context.MdcCases.uninvokedLambdaIsNotCapture()V'
assert_no_sanitized "$ROOT/.test-tmp/matrix.txt" 'context.MdcCases.uninvokedLambdaIsNotCapture()V'
assert_no_finding "$ROOT/.test-tmp/matrix.txt" 'context.MdcCases.untrackedContext()V'
assert_no_sanitized "$ROOT/.test-tmp/matrix.txt" 'context.MdcCases.untrackedContext()V'
assert_no_finding "$ROOT/.test-tmp/matrix.txt" 'context.MdcCases.jbossClearRemoveAreNotCapture(Lorg/jboss/logging/LoggerProvider;Lorg/jboss/logmanager/ExtLogRecord;)V'
assert_no_sanitized "$ROOT/.test-tmp/matrix.txt" 'context.MdcCases.jbossClearRemoveAreNotCapture(Lorg/jboss/logging/LoggerProvider;Lorg/jboss/logmanager/ExtLogRecord;)V'
assert_finding "$ROOT/.test-tmp/matrix.txt" 'context.MdcCases.sameOriginUnsafeDominates()V'
assert_no_sanitized "$ROOT/.test-tmp/matrix.txt" 'context.MdcCases.sameOriginUnsafeDominates()V'
assert_finding "$ROOT/.test-tmp/matrix.txt" 'context.MdcCases.differentOriginsRemainSeparate()V'
assert_sanitized "$ROOT/.test-tmp/matrix.txt" 'context.MdcCases.differentOriginsRemainSeparate()V'
grep -A4 -F 'ERROR context.MdcCases.directMdcPut()V' "$ROOT/.test-tmp/matrix.txt" \
  | grep -F 'category: CONTEXT_CAPTURE' >/dev/null
grep -F 'flow: value captured in diagnostic context' "$ROOT/.test-tmp/matrix.txt" >/dev/null
grep -F 'justification: Approved context sanitizer CTX-1' "$ROOT/.test-tmp/matrix.txt" >/dev/null

# SANITIZED findings are reported but do not fail --fail when no UNSAFE flow exists.
run_expect_success "$ROOT/.test-tmp/sanitized-only.txt" "$ROOT/sanitized-only-out"
assert_sanitized "$ROOT/.test-tmp/sanitized-only.txt" 'sanitizedonly.SanitizedOnly.log()V'
assert_sanitized "$ROOT/.test-tmp/sanitized-only.txt" 'sanitizedonly.ContextSanitizedOnly.capture()V'
grep -A4 -F 'SANITIZED sanitizedonly.ContextSanitizedOnly.capture()V' "$ROOT/.test-tmp/sanitized-only.txt" \
  | grep -F 'category: CONTEXT_CAPTURE' >/dev/null
grep -F 'justification: SEC-ONLY-1' "$ROOT/.test-tmp/sanitized-only.txt" >/dev/null
grep -F 'justification: CTX-ONLY-1' "$ROOT/.test-tmp/sanitized-only.txt" >/dev/null

# A custom sanitizer annotation is ignored by default and honored when configured.
assert_no_finding "$ROOT/.test-tmp/matrix.txt" 'custom.CustomSanitizeCases.configuredSanitizer()V'
assert_possible "$ROOT/.test-tmp/matrix.txt" 'custom.CustomSanitizeCases.configuredSanitizer()V'
run_expect_findings "$ROOT/.test-tmp/custom-sanitize-annotation.txt" \
  --sanitize-annotation=custom.Cleansed "$ROOT/test-out"
assert_no_finding "$ROOT/.test-tmp/custom-sanitize-annotation.txt" 'custom.CustomSanitizeCases.configuredSanitizer()V'
assert_no_possible "$ROOT/.test-tmp/custom-sanitize-annotation.txt" 'custom.CustomSanitizeCases.configuredSanitizer()V'
assert_sanitized "$ROOT/.test-tmp/custom-sanitize-annotation.txt" 'custom.CustomSanitizeCases.configuredSanitizer()V'
grep -F 'justification: CUSTOM-7' "$ROOT/.test-tmp/custom-sanitize-annotation.txt" >/dev/null

# Conservative unknown-call behavior is configurable without breaking direct flow.
run_expect_findings "$ROOT/.test-tmp/non-conservative.txt" \
  --no-conservative-unknown-calls "$ROOT/test-out"
assert_no_finding "$ROOT/.test-tmp/non-conservative.txt" \
  'matrix.expressions.ExpressionCases.unknownTransformationIsConservative()V'
assert_no_possible "$ROOT/.test-tmp/non-conservative.txt" \
  'matrix.expressions.ExpressionCases.unknownTransformationIsConservative()V'
assert_finding "$ROOT/.test-tmp/non-conservative.txt" \
  'matrix.language.ControlFlowCases.straightLine()V'

# Worklist convergence is not bounded by an arbitrary round count.
assert_finding "$ROOT/.test-tmp/matrix.txt" 'analysis.LongChainCases.leakThroughSixtyCalls()V'

# POSSIBLE findings fail closed by default, but can be explicitly allowed.
run_expect_findings "$ROOT/.test-tmp/possible-only.txt" "$ROOT/possible-only-out"
assert_possible "$ROOT/.test-tmp/possible-only.txt" 'possibleonly.PossibleOnly.inlinedConstant()V'
assert_possible "$ROOT/.test-tmp/possible-only.txt" 'possibleonly.PossibleOnly.identicalLiteralWithoutFieldReference()V'
assert_possible "$ROOT/.test-tmp/possible-only.txt" 'possibleonly.PossibleOnly.unknownTransformation()V'
grep -F 'INLINED_SECURE_CONSTANT' "$ROOT/.test-tmp/possible-only.txt" >/dev/null
grep -F 'UNKNOWN_METHOD_RETURN' "$ROOT/.test-tmp/possible-only.txt" >/dev/null
run_expect_success "$ROOT/.test-tmp/possible-allowed.txt" --allow-possible "$ROOT/possible-only-out"

# Incomplete analysis fails closed and requires an explicit opt-out.
run_expect_findings "$ROOT/.test-tmp/work-cap.txt" --max-work-items=1 "$ROOT/safe-only-out"
grep -F 'INCOMPLETE securelogscan.SecureLogScan.analysis()V' "$ROOT/.test-tmp/work-cap.txt" >/dev/null
grep -F 'Worklist safety limit reached' "$ROOT/.test-tmp/work-cap.txt" >/dev/null
run_expect_success "$ROOT/.test-tmp/work-cap-allowed.txt" --allow-incomplete-analysis --max-work-items=1 "$ROOT/safe-only-out"

mkdir -p "$ROOT/.test-tmp/duplicate-a" "$ROOT/.test-tmp/duplicate-b"
cp -R "$ROOT/safe-only-out"/. "$ROOT/.test-tmp/duplicate-a"/
cp -R "$ROOT/safe-only-out"/. "$ROOT/.test-tmp/duplicate-b"/
run_expect_findings "$ROOT/.test-tmp/duplicate.txt" "$ROOT/.test-tmp/duplicate-a" "$ROOT/.test-tmp/duplicate-b"
grep -F 'Duplicate class safeonly.SafeOnly' "$ROOT/.test-tmp/duplicate.txt" >/dev/null

mkdir -p "$ROOT/.test-tmp/broken"
printf '\xCA\xFE\xBA\xBEbroken' > "$ROOT/.test-tmp/broken/Broken.class"
run_expect_findings "$ROOT/.test-tmp/broken.txt" "$ROOT/.test-tmp/broken"
grep -F 'Unable to read' "$ROOT/.test-tmp/broken.txt" >/dev/null

run_expect_findings "$ROOT/.test-tmp/missing-input.txt" "$ROOT/.test-tmp/does-not-exist"
grep -F 'Unable to scan input' "$ROOT/.test-tmp/missing-input.txt" >/dev/null


# Exact external method models: sink, renderer, callback, mutation, and sanitizer.
"$ROOT/run.sh" "$ROOT/model-scan-out" > "$ROOT/.test-tmp/model-unconfigured.txt"
for method in \
  'models.MethodModelCases.configuredSink()V' \
  'models.MethodModelCases.configuredContextSink()V' \
  'models.MethodModelCases.configuredCallbackCaptured()V' \
  'models.MethodModelCases.configuredMutation()V'; do
  assert_no_finding "$ROOT/.test-tmp/model-unconfigured.txt" "$method"
done

run_expect_findings "$ROOT/.test-tmp/model-configured.txt" \
  --model="$ROOT/models/test-methods.models" "$ROOT/model-scan-out"
assert_analysis_complete "$ROOT/.test-tmp/model-configured.txt"
grep '^ERROR models\.MethodModelCases' "$ROOT/.test-tmp/model-configured.txt" \
  | sed 's/^ERROR //' | sort -u > "$ROOT/.test-tmp/actual-model-unsafe.txt"
grep '^SANITIZED models\.MethodModelCases' "$ROOT/.test-tmp/model-configured.txt" \
  | sed 's/^SANITIZED //' | sort -u > "$ROOT/.test-tmp/actual-model-sanitized.txt"
diff -u "$ROOT/testmatrix/expected-model-unsafe.txt" "$ROOT/.test-tmp/actual-model-unsafe.txt"
diff -u "$ROOT/testmatrix/expected-model-sanitized.txt" "$ROOT/.test-tmp/actual-model-sanitized.txt"
assert_no_finding "$ROOT/.test-tmp/model-configured.txt" 'models.MethodModelCases.configuredSanitizer()V'
assert_no_finding "$ROOT/.test-tmp/model-configured.txt" 'models.MethodModelCases.configuredSanitizerMethodReference()V'
assert_no_finding "$ROOT/.test-tmp/model-configured.txt" 'models.MethodModelCases.sanitizedConfiguredContext()V'
assert_no_finding "$ROOT/.test-tmp/model-configured.txt" 'models.MethodModelCases.directModeDoesNotRenderObject()V'
assert_no_sanitized "$ROOT/.test-tmp/model-configured.txt" 'models.MethodModelCases.directModeDoesNotRenderObject()V'
assert_no_finding "$ROOT/.test-tmp/model-configured.txt" 'models.MethodModelCases.untrackedConfiguredSink()V'
grep -F 'configured method models: 10' "$ROOT/.test-tmp/model-configured.txt" >/dev/null
grep -F 'description: External masking boundary' "$ROOT/.test-tmp/model-configured.txt" >/dev/null
grep -F 'justification: MODEL-SEC-7' "$ROOT/.test-tmp/model-configured.txt" >/dev/null
grep -A5 -F 'ERROR models.MethodModelCases.configuredContextSink()V' "$ROOT/.test-tmp/model-configured.txt" \
  | grep -F 'category: CONTEXT_CAPTURE' >/dev/null

"$ROOT/run.sh" --json --model="$ROOT/models/test-methods.models" "$ROOT/model-scan-out" \
  > "$ROOT/.test-tmp/model-report.json"
grep -F '"methodModels": [' "$ROOT/.test-tmp/model-report.json" >/dev/null
grep -F 'renderer models.ExternalApis.serialize' "$ROOT/.test-tmp/model-report.json" >/dev/null
grep -F '"state": "SANITIZED"' "$ROOT/.test-tmp/model-report.json" >/dev/null

cat > "$ROOT/.test-tmp/invalid.models" <<'EOF_MODEL'
sink LOG_OUTPUT models.ExternalApis::audit(Ljava/lang/Object;)V values=arg99 mode=deep
EOF_MODEL
run_expect_findings "$ROOT/.test-tmp/invalid-model.txt" \
  --model="$ROOT/.test-tmp/invalid.models" "$ROOT/safe-only-out"
grep -F 'Invalid method model' "$ROOT/.test-tmp/invalid-model.txt" >/dev/null
grep -F 'outside method argument range' "$ROOT/.test-tmp/invalid-model.txt" >/dev/null
run_expect_findings "$ROOT/.test-tmp/missing-model.txt" \
  --model="$ROOT/.test-tmp/missing.models" "$ROOT/safe-only-out"
grep -F 'Unable to load method model' "$ROOT/.test-tmp/missing-model.txt" >/dev/null


# Built-in asynchronous callbacks, lazy/fluent suppliers, reachability, and callback escape uncertainty.
run_expect_findings "$ROOT/.test-tmp/async.txt" "$ROOT/async-out"
assert_analysis_complete "$ROOT/.test-tmp/async.txt"
grep '^ERROR async\.' "$ROOT/.test-tmp/async.txt" \
  | sed 's/^ERROR //' | sort -u > "$ROOT/.test-tmp/actual-async-unsafe.txt"
if $MODERN_ENABLED; then
  cp "$ROOT/testmatrix/expected-async-unsafe.txt" "$ROOT/.test-tmp/expected-async-unsafe.txt"
else
  grep -v '^async\.ModernAsyncCases\.' "$ROOT/testmatrix/expected-async-unsafe.txt" \
    > "$ROOT/.test-tmp/expected-async-unsafe.txt"
fi
diff -u "$ROOT/.test-tmp/expected-async-unsafe.txt" "$ROOT/.test-tmp/actual-async-unsafe.txt"
grep '^POSSIBLE async\.' "$ROOT/.test-tmp/async.txt" \
  | sed 's/^POSSIBLE //' | sort -u > "$ROOT/.test-tmp/actual-async-possible.txt"
grep '^SANITIZED async\.' "$ROOT/.test-tmp/async.txt" \
  | sed 's/^SANITIZED //' | sort -u > "$ROOT/.test-tmp/actual-async-sanitized.txt"
diff -u "$ROOT/testmatrix/expected-async-possible.txt" "$ROOT/.test-tmp/actual-async-possible.txt"
diff -u "$ROOT/testmatrix/expected-async-sanitized.txt" "$ROOT/.test-tmp/actual-async-sanitized.txt"
while IFS= read -r method; do
  assert_no_finding "$ROOT/.test-tmp/async.txt" "$method"
  assert_no_possible "$ROOT/.test-tmp/async.txt" "$method"
  assert_no_sanitized "$ROOT/.test-tmp/async.txt" "$method"
done < "$ROOT/testmatrix/expected-async-safe.txt"
grep -A40 -F 'POSSIBLE async.AsyncCases.unknownCallbackEscape(Lexternal/Registry;)V' "$ROOT/.test-tmp/async.txt" \
  | grep -F 'CALLBACK_MAY_EXECUTE' >/dev/null
assert_finding "$ROOT/.test-tmp/async.txt" 'async.AsyncCases.executorThroughHelper(Ljava/util/concurrent/Executor;)V'
assert_finding "$ROOT/.test-tmp/async.txt" 'async.AsyncCases.completionStageThroughHelper()V'
assert_finding "$ROOT/.test-tmp/async.txt" 'async.AsyncCases.fluentSupplierThroughHelper()V'
assert_sanitized "$ROOT/.test-tmp/async.txt" 'async.AsyncCases.sanitizedFluentSupplierThroughHelper()V'

"$ROOT/run.sh" --json "$ROOT/async-out" > "$ROOT/.test-tmp/async.json"
grep -F '"CALLBACK_MAY_EXECUTE"' "$ROOT/.test-tmp/async.json" >/dev/null
grep -F '"method": "safeUnusedDirectFieldLambda()V"' "$ROOT/.test-tmp/async.json" >/dev/null && {
  cat "$ROOT/.test-tmp/async.json"
  echo 'Unused lambda unexpectedly appeared in JSON findings' >&2
  exit 32
}

# Exception message/cause/suppressed graphs and asynchronous completion failures.
run_expect_findings "$ROOT/.test-tmp/exceptions.txt" "$ROOT/exception-out"
assert_analysis_complete "$ROOT/.test-tmp/exceptions.txt"
grep '^ERROR exceptions\.' "$ROOT/.test-tmp/exceptions.txt" \
  | sed 's/^ERROR //' | sort -u > "$ROOT/.test-tmp/actual-exception-unsafe.txt"
grep '^SANITIZED exceptions\.' "$ROOT/.test-tmp/exceptions.txt" \
  | sed 's/^SANITIZED //' | sort -u > "$ROOT/.test-tmp/actual-exception-sanitized.txt"
diff -u "$ROOT/testmatrix/expected-exception-unsafe.txt" "$ROOT/.test-tmp/actual-exception-unsafe.txt"
diff -u "$ROOT/testmatrix/expected-exception-sanitized.txt" "$ROOT/.test-tmp/actual-exception-sanitized.txt"
while IFS= read -r method; do
  assert_no_finding "$ROOT/.test-tmp/exceptions.txt" "$method"
  assert_no_possible "$ROOT/.test-tmp/exceptions.txt" "$method"
  assert_no_sanitized "$ROOT/.test-tmp/exceptions.txt" "$method"
done < "$ROOT/testmatrix/expected-exception-safe.txt"
assert_finding "$ROOT/.test-tmp/exceptions.txt" 'exceptions.ExceptionGraphCases.helperSuppressed(Lexceptions/ExceptionGraphCases$Bean;)V'
assert_finding "$ROOT/.test-tmp/exceptions.txt" 'exceptions.ExceptionGraphCases.returnedFailedFuture(Lexceptions/ExceptionGraphCases$Bean;)V'
assert_sanitized "$ROOT/.test-tmp/exceptions.txt" 'exceptions.ExceptionGraphCases.sanitizedFailedFuture(Lexceptions/ExceptionGraphCases$Bean;)V'
grep -F 'justification: EX-11' "$ROOT/.test-tmp/exceptions.txt" >/dev/null

"$ROOT/run.sh" --json "$ROOT/exception-out" > "$ROOT/.test-tmp/exceptions.json"
grep -F '"owner": "exceptions.ExceptionGraphCases"' "$ROOT/.test-tmp/exceptions.json" >/dev/null
grep -F '"method": "failedFutureExceptionally(Lexceptions/ExceptionGraphCases$Bean;)V"' "$ROOT/.test-tmp/exceptions.json" >/dev/null
grep -F '"state": "SANITIZED"' "$ROOT/.test-tmp/exceptions.json" >/dev/null

# Dependency/classpath analysis, provenance, nested archives, and policy.
run_expect_findings "$ROOT/.test-tmp/dependency-classpath.txt" \
  --classpath="$ROOT/dep-fixtures.jar" "$ROOT/app-out"
assert_analysis_complete "$ROOT/.test-tmp/dependency-classpath.txt"
assert_finding "$ROOT/.test-tmp/dependency-classpath.txt" 'app.AppCases.dependencyToString(Ldep/Customer;)V'
assert_finding "$ROOT/.test-tmp/dependency-classpath.txt" 'app.AppCases.dependencyVirtualDispatch(Ldep/Customer;)V'
assert_finding "$ROOT/.test-tmp/dependency-classpath.txt" 'app.AppCases.dependencyOwnedSink(Lapp/AppBean;)V'
assert_sanitized "$ROOT/.test-tmp/dependency-classpath.txt" 'app.AppCases.dependencySanitizer(Ldep/Customer;)V'
grep -F 'scope: CROSS_BOUNDARY' "$ROOT/.test-tmp/dependency-classpath.txt" >/dev/null
grep -A30 -F 'ERROR app.AppCases.dependencyOwnedSink(Lapp/AppBean;)V' "$ROOT/.test-tmp/dependency-classpath.txt" | grep -F 'sink artifact: com.acme:customer-model:4.2 [DEPENDENCY]' >/dev/null
grep -F 'com.acme:customer-model:4.2 [DEPENDENCY]' "$ROOT/.test-tmp/dependency-classpath.txt" >/dev/null
grep -F 'module: com.acme.customer.model' "$ROOT/.test-tmp/dependency-classpath.txt" >/dev/null
grep -F 'justification: DEP-42' "$ROOT/.test-tmp/dependency-classpath.txt" >/dev/null

run_expect_findings "$ROOT/.test-tmp/unresolved-dependency.txt" "$ROOT/app-out"
assert_possible "$ROOT/.test-tmp/unresolved-dependency.txt" 'app.AppCases.unresolvedDependency(Lapp/AppBean;)V'
grep -A40 -F 'POSSIBLE app.AppCases.unresolvedDependency(Lapp/AppBean;)V' "$ROOT/.test-tmp/unresolved-dependency.txt" \
  | grep -F 'UNRESOLVED_DEPENDENCY' >/dev/null

run_expect_success "$ROOT/.test-tmp/dependency-report.txt" \
  --classpath="$ROOT/dep-fixtures.jar" "$ROOT/empty-app-out"
assert_finding "$ROOT/.test-tmp/dependency-report.txt" 'dep.DepLeak.leakInsideDependency()V'
grep -A4 -F 'ERROR dep.DepLeak.leakInsideDependency()V' "$ROOT/.test-tmp/dependency-report.txt" \
  | grep -F 'scope: DEPENDENCY_INTERNAL' >/dev/null

run_expect_findings "$ROOT/.test-tmp/dependency-fail.txt" \
  --dependency-findings=fail --classpath="$ROOT/dep-fixtures.jar" "$ROOT/empty-app-out"
assert_finding "$ROOT/.test-tmp/dependency-fail.txt" 'dep.DepLeak.leakInsideDependency()V'

run_expect_success "$ROOT/.test-tmp/dependency-ignore.txt" \
  --dependency-findings=ignore --classpath="$ROOT/dep-fixtures.jar" "$ROOT/empty-app-out"
if grep -F 'dep.DepLeak.leakInsideDependency()V' "$ROOT/.test-tmp/dependency-ignore.txt" >/dev/null; then
  cat "$ROOT/.test-tmp/dependency-ignore.txt"
  echo 'Dependency-internal finding was not suppressed' >&2
  exit 31
fi

run_expect_findings "$ROOT/.test-tmp/boot-nested.txt" "$ROOT/boot-fixture.jar"
assert_finding "$ROOT/.test-tmp/boot-nested.txt" 'app.AppCases.dependencyToString(Ldep/Customer;)V'
grep -F 'BOOT-INF/lib/customer-model-4.2.jar' "$ROOT/.test-tmp/boot-nested.txt" >/dev/null

run_expect_findings "$ROOT/.test-tmp/war-nested.txt" "$ROOT/war-fixture.war"
assert_finding "$ROOT/.test-tmp/war-nested.txt" 'app.AppCases.dependencyVirtualDispatch(Ldep/Customer;)V'
grep -F 'WEB-INF/lib/customer-model-4.2.jar' "$ROOT/.test-tmp/war-nested.txt" >/dev/null

if (( JAVAC_MAJOR >= 21 )); then
  run_expect_success "$ROOT/.test-tmp/mr17.txt" --release=17 --classpath="$ROOT/mr-fixture.jar" "$ROOT/mr-app-out"
  assert_no_finding "$ROOT/.test-tmp/mr17.txt" 'app.MrCases.logVersionedCustomer(Lmr/VersionedCustomer;)V'
  run_expect_findings "$ROOT/.test-tmp/mr21.txt" --release=21 --classpath="$ROOT/mr-fixture.jar" "$ROOT/mr-app-out"
  assert_finding "$ROOT/.test-tmp/mr21.txt" 'app.MrCases.logVersionedCustomer(Lmr/VersionedCustomer;)V'
fi

run_expect_findings "$ROOT/.test-tmp/dependency-duplicate-fail.txt" \
  --classpath="$ROOT/dupe-dependency.jar" "$ROOT/dupe-app-out"
grep -F 'Duplicate class dupe.Shared' "$ROOT/.test-tmp/dependency-duplicate-fail.txt" >/dev/null
grep -F '(conflicting bytecode)' "$ROOT/.test-tmp/dependency-duplicate-fail.txt" >/dev/null

run_expect_success "$ROOT/.test-tmp/dependency-duplicate-first.txt" \
  --duplicate-classes=first --classpath="$ROOT/dupe-dependency.jar" "$ROOT/dupe-app-out"
grep -F 'duplicate classes: 1 (policy=first)' "$ROOT/.test-tmp/dependency-duplicate-first.txt" >/dev/null
grep -F 'selected:' "$ROOT/.test-tmp/dependency-duplicate-first.txt" >/dev/null

run_expect_success "$ROOT/.test-tmp/module-path.txt" \
  --module-path="$ROOT/test-dependency-module.jar" "$ROOT/empty-app-out"
grep -F 'module: test.dependency.module' "$ROOT/.test-tmp/module-path.txt" >/dev/null
grep -F 'DEPENDENCY: 1' "$ROOT/.test-tmp/module-path.txt" >/dev/null

run_expect_success "$ROOT/.test-tmp/jrt-module.txt" \
  --jdk-module=jdk.unsupported "$ROOT/empty-app-out"
grep -F 'module: jdk.unsupported' "$ROOT/.test-tmp/jrt-module.txt" >/dev/null
grep -E 'JDK_RUNTIME: [1-9][0-9]*' "$ROOT/.test-tmp/jrt-module.txt" >/dev/null

"$ROOT/run.sh" --json --classpath="$ROOT/dep-fixtures.jar" "$ROOT/app-out" \
  > "$ROOT/.test-tmp/dependency-report.json"
grep -F '"classesByRole": {' "$ROOT/.test-tmp/dependency-report.json" >/dev/null
grep -F '"scope": "CROSS_BOUNDARY"' "$ROOT/.test-tmp/dependency-report.json" >/dev/null
grep -F '"coordinate":"com.acme:customer-model:4.2"' "$ROOT/.test-tmp/dependency-report.json" >/dev/null
grep -F '"sinkArtifact": "app-out [APPLICATION]"' "$ROOT/.test-tmp/dependency-report.json" >/dev/null
grep -F '"artifact":"com.acme:customer-model:4.2 [DEPENDENCY]"' "$ROOT/.test-tmp/dependency-report.json" >/dev/null

# Single-class, directory, and JAR inputs.
run_expect_findings "$ROOT/.test-tmp/single-class.txt" \
  "$ROOT/test-out/matrix/language/ControlFlowCases.class"
assert_finding "$ROOT/.test-tmp/single-class.txt" \
  'matrix.language.ControlFlowCases.straightLine()V'

jar --create --file "$ROOT/test-fixtures.jar" -C "$ROOT/test-out" .
run_expect_findings "$ROOT/.test-tmp/jar.txt" "$ROOT/test-fixtures.jar"
assert_finding "$ROOT/.test-tmp/jar.txt" 'matrix.lambda.LambdaCases.constructorReference()V'
assert_possible "$ROOT/.test-tmp/jar.txt" 'matrix.types.ConstantInliningCases.crossClassPrimitiveConstant()V'
assert_analysis_complete "$ROOT/.test-tmp/jar.txt"

# JSON output remains machine-oriented and contains representative findings.
"$ROOT/run.sh" --json "$ROOT/test-out" > "$ROOT/.test-tmp/report.json"
grep -F '"analysisComplete": true' "$ROOT/.test-tmp/report.json" >/dev/null
grep -F '"worklistMethodAnalyses":' "$ROOT/.test-tmp/report.json" >/dev/null
grep -F '"findings": [' "$ROOT/.test-tmp/report.json" >/dev/null
grep -F '"owner": "matrix.lambda.LambdaCases"' "$ROOT/.test-tmp/report.json" >/dev/null
grep -F '"method": "constructorReference()V"' "$ROOT/.test-tmp/report.json" >/dev/null
grep -F '"state": "SANITIZED"' "$ROOT/.test-tmp/report.json" >/dev/null
grep -F '"category": "CONTEXT_CAPTURE"' "$ROOT/.test-tmp/report.json" >/dev/null
grep -F '"state": "POSSIBLE"' "$ROOT/.test-tmp/report.json" >/dev/null
grep -F '"uncertaintyReasons": ["INLINED_SECURE_CONSTANT"]' "$ROOT/.test-tmp/report.json" >/dev/null
grep -F '"justification":"Approved security utility SEC-1421"' "$ROOT/.test-tmp/report.json" >/dev/null
grep -F '"justification":"Approved context sanitizer CTX-1"' "$ROOT/.test-tmp/report.json" >/dev/null

# Actionable diagnostics: source lines, sink arguments, MDC keys, call paths, JSON, and SARIF.
run_expect_findings "$ROOT/.test-tmp/diagnostics.txt" "$ROOT/diagnostics-out"
grep -A30 -F 'ERROR diagnostics.DiagnosticCases.directMdc()V' "$ROOT/.test-tmp/diagnostics.txt" | grep -F 'source location: diagnostics.DiagnosticCases.directMdc()V (DiagnosticCases.java:11)' >/dev/null
grep -A30 -F 'ERROR diagnostics.DiagnosticCases.directMdc()V' "$ROOT/.test-tmp/diagnostics.txt" | grep -F 'sink argument: 1' >/dev/null
grep -A30 -F 'ERROR diagnostics.DiagnosticCases.directMdc()V' "$ROOT/.test-tmp/diagnostics.txt" | grep -F 'context key: customer.ssn' >/dev/null
grep -A40 -F 'ERROR diagnostics.DiagnosticCases.helperPath()V' "$ROOT/.test-tmp/diagnostics.txt" | grep -F 'diagnostics.DiagnosticCases.write(Ljava/lang/String;)V (DiagnosticCases.java:19)' >/dev/null

"$ROOT/run.sh" --json "$ROOT/diagnostics-out" > "$ROOT/.test-tmp/diagnostics.json"
"$ROOT/run.sh" --sarif "$ROOT/diagnostics-out" > "$ROOT/.test-tmp/diagnostics.sarif"
"$ROOT/run.sh" --sarif="$ROOT/.test-tmp/diagnostics-file.sarif" "$ROOT/diagnostics-out" > "$ROOT/.test-tmp/diagnostics-sarif-text.txt"
python - "$ROOT/.test-tmp/diagnostics.json" "$ROOT/.test-tmp/diagnostics.sarif" "$ROOT/.test-tmp/diagnostics-file.sarif" <<'PY_DIAGNOSTICS'
import json, sys
json_report = json.load(open(sys.argv[1], encoding='utf-8'))
direct = next(f for f in json_report['findings'] if f['owner'] == 'diagnostics.DiagnosticCases' and f['method'] == 'directMdc()V')
assert direct['sourceFile'] == 'DiagnosticCases.java'
assert direct['line'] == 11
assert direct['instructionIndex'] >= 0
assert direct['sinkArgument'] == 1
assert direct['contextKey'] == 'customer.ssn'
helper = next(f for f in json_report['findings'] if f['owner'] == 'diagnostics.DiagnosticCases' and f['method'] == 'helperPath()V')
assert len(helper['callPath']) >= 2
assert helper['callPath'][-1]['method'].startswith('diagnostics.DiagnosticCases.write')
for path in sys.argv[2:]:
    sarif = json.load(open(path, encoding='utf-8'))
    assert sarif['version'] == '2.1.0'
    run = sarif['runs'][0]
    assert run['tool']['driver']['name'] == 'SecureLogScan'
    assert any(result['ruleId'] == 'secure-log/unsafe' for result in run['results'])
    result = next(result for result in run['results'] if result['properties'].get('contextKey') == 'customer.ssn')
    assert result['locations'][0]['physicalLocation']['region']['startLine'] == 11
    assert result['properties']['sinkArgument'] == 1
    assert result['codeFlows'][0]['threadFlows'][0]['locations']
PY_DIAGNOSTICS

"$ROOT/test-policy.sh"

BASE_EXPECTED="$(grep -vc '^matrix\.modern\.' "$ROOT/testmatrix/expected-positive.txt")"
if $MODERN_ENABLED; then
  MATRIX_EXPECTED="$(wc -l < "$ROOT/testmatrix/expected-positive.txt" | tr -d ' ')"
  MODERN_TEXT=" + Java 21 pattern/record switch"
else
  MATRIX_EXPECTED="$BASE_EXPECTED"
  MODERN_TEXT="; Java 21 fixtures skipped on javac $JAVAC_VERSION"
fi
SAFE_COUNT="$(wc -l < "$ROOT/testmatrix/expected-safe.txt" | tr -d ' ')"
POSSIBLE_COUNT="$(wc -l < "$ROOT/testmatrix/expected-possible.txt" | tr -d ' ')"
SANITIZED_COUNT="$(wc -l < "$ROOT/testmatrix/expected-sanitized.txt" | tr -d ' ')"
SANITIZE_UNSAFE_COUNT="$(wc -l < "$ROOT/testmatrix/expected-sanitize-unsafe.txt" | tr -d ' ')"
CONTEXT_UNSAFE_COUNT="$(wc -l < "$ROOT/testmatrix/expected-context-unsafe.txt" | tr -d ' ')"
CONTEXT_SANITIZED_COUNT="$(wc -l < "$ROOT/testmatrix/expected-context-sanitized.txt" | tr -d ' ')"
CONTEXT_POSSIBLE_COUNT="$(wc -l < "$ROOT/testmatrix/expected-context-possible.txt" | tr -d ' ')"
MODEL_UNSAFE_COUNT="$(wc -l < "$ROOT/testmatrix/expected-model-unsafe.txt" | tr -d ' ')"
MODEL_SANITIZED_COUNT="$(wc -l < "$ROOT/testmatrix/expected-model-sanitized.txt" | tr -d ' ')"
ASYNC_UNSAFE_COUNT="$(grep -vc '^async\.ModernAsyncCases\.' "$ROOT/testmatrix/expected-async-unsafe.txt" | tr -d ' ')"
if $MODERN_ENABLED; then ASYNC_UNSAFE_COUNT="$(wc -l < "$ROOT/testmatrix/expected-async-unsafe.txt" | tr -d ' ')"; fi
ASYNC_POSSIBLE_COUNT="$(wc -l < "$ROOT/testmatrix/expected-async-possible.txt" | tr -d ' ')"
ASYNC_SANITIZED_COUNT="$(wc -l < "$ROOT/testmatrix/expected-async-sanitized.txt" | tr -d ' ')"
EXCEPTION_UNSAFE_COUNT="$(wc -l < "$ROOT/testmatrix/expected-exception-unsafe.txt" | tr -d ' ')"
EXCEPTION_SANITIZED_COUNT="$(wc -l < "$ROOT/testmatrix/expected-exception-sanitized.txt" | tr -d ' ')"
EXCEPTION_SAFE_COUNT="$(wc -l < "$ROOT/testmatrix/expected-exception-safe.txt" | tr -d ' ')"
echo "PASS: $MATRIX_EXPECTED exact unsafe methods, $POSSIBLE_COUNT exact possible methods, $SAFE_COUNT explicit negatives, $SANITIZED_COUNT sanitized log flows, $SANITIZE_UNSAFE_COUNT sanitizer-related unsafe flows, $CONTEXT_UNSAFE_COUNT unsafe context-capture methods, $CONTEXT_POSSIBLE_COUNT possible context-capture method, $CONTEXT_SANITIZED_COUNT sanitized context-capture methods, $MODEL_UNSAFE_COUNT configured-model unsafe methods, $MODEL_SANITIZED_COUNT configured-model sanitized methods, $ASYNC_UNSAFE_COUNT async/lazy unsafe methods, $ASYNC_POSSIBLE_COUNT callback-escape possible methods, $ASYNC_SANITIZED_COUNT async/lazy sanitized methods, $EXCEPTION_UNSAFE_COUNT exception-graph unsafe methods, $EXCEPTION_SANITIZED_COUNT exception-graph sanitized methods, $EXCEPTION_SAFE_COUNT exception precision negatives, 60-call worklist convergence, fail-closed incomplete analysis, duplicate/broken-class detection, callbacks/lambdas/method references, all JVM invocation opcodes, control flow, expressions, type forms, initializers, logging+MDC APIs, constants, arrays, directory/class/JAR/JSON/custom secure+sanitizer annotation modes, dependency classpaths, artifact provenance, Spring Boot/WAR nested JARs, multi-release selection, duplicate precedence, dependency finding policy, source diagnostics, call paths, sink arguments, MDC keys, JSON, and SARIF$MODERN_TEXT"
