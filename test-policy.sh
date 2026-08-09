#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
TMP="$ROOT/.policy-test-tmp"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
cleanup
mkdir -p "$TMP/base" "$TMP/new" "$TMP/invalid"

[[ -f "$ROOT/secure-log-scan.jar" ]] || "$ROOT/build.sh" >/dev/null

javac --release 17 -Xlint:all,-serial -Werror -cp "$ROOT/secure-log-scan.jar" \
  -d "$TMP/base" $(find "$ROOT/testsrc-policy" -name '*.java' | sort)
javac --release 17 -Xlint:all,-serial -Werror -cp "$ROOT/secure-log-scan.jar" \
  -d "$TMP/new" $(find "$ROOT/testsrc-policy-new" -name '*.java' | sort)
javac --release 17 -Xlint:all,-serial -Werror -cp "$ROOT/secure-log-scan.jar" \
  -d "$TMP/invalid" $(find "$ROOT/testsrc-policy-invalid" -name '*.java' | sort)

"$ROOT/run.sh" "$TMP/base" > "$TMP/report.txt"
for expected in \
  'ERROR policy.PolicyCases.methodReturnSource()V' \
  'ERROR policy.PolicyCases.parameterSource(Ljava/lang/String;)V' \
  'ERROR policy.PolicyCases.metaParameterSource(Ljava/lang/String;)V' \
  'ERROR policy.PolicyCases.recordComponentSource(Lpolicy/PolicyCases$Customer;)V' \
  'ERROR policy.PolicyCases.typeSource(Lpolicy/PolicyCases$SecretEnvelope;)V' \
  'ERROR policy.PolicyCases.inheritedReturnContract(Lpolicy/PolicyCases$ContractImpl;)V' \
  'ERROR policy.PolicyCases$ContractImpl.consume(Ljava/lang/String;)V' \
  'SANITIZED policy.PolicyCases.sanitizedParameter(Ljava/lang/String;)V'; do
  grep -F "$expected" "$TMP/report.txt" >/dev/null || { cat "$TMP/report.txt"; echo "Missing policy finding: $expected" >&2; exit 40; }
done
grep -F 'effective secure annotations: [Lsecure/Secure;, Lpolicy/Pii;]' "$TMP/report.txt" >/dev/null
grep -A20 -F 'ERROR policy.PolicyCases.suppressedMethod' "$TMP/report.txt" | grep -F 'disposition: SUPPRESSED' >/dev/null
grep -A25 -F 'ERROR policy.PolicyCases.callsSuppressedHelper' "$TMP/report.txt" | grep -F 'reason: Central audited helper' >/dev/null
grep -A20 -F 'ERROR policy.PolicyCases$SuppressedType.log()V' "$TMP/report.txt" | grep -F 'disposition: SUPPRESSED' >/dev/null

# A type-suppressed class containing no active findings must pass --fail.
set +e
"$ROOT/run.sh" --fail "$TMP/base/policy/PolicyCases\$SuppressedType.class" > "$TMP/suppressed-only.txt" 2>&1
suppressed_code=$?
set -e
[[ $suppressed_code -eq 0 ]] || { cat "$TMP/suppressed-only.txt"; echo 'Suppressed-only scan did not pass' >&2; exit 41; }

# Baseline generation is valid JSON and turns existing findings into BASELINED without hiding them.
"$ROOT/run.sh" --write-baseline="$TMP/baseline.json" "$TMP/base" > "$TMP/write.txt"
python - "$TMP/baseline.json" <<'PY_BASELINE'
import json, sys
baseline = json.load(open(sys.argv[1], encoding='utf-8'))
assert baseline['version'] == 1
assert len(baseline['fingerprints']) >= 8
assert all(len(value) == 64 for value in baseline['fingerprints'])
PY_BASELINE
set +e
"$ROOT/run.sh" --fail-on-new --baseline="$TMP/baseline.json" "$TMP/base" > "$TMP/baselined.txt" 2>&1
baseline_code=$?
"$ROOT/run.sh" --fail-on-new --baseline="$TMP/baseline.json" "$TMP/base" "$TMP/new" > "$TMP/new.txt" 2>&1
new_code=$?
set -e
[[ $baseline_code -eq 0 ]] || { cat "$TMP/baselined.txt"; echo 'Baselined scan did not pass' >&2; exit 42; }
[[ $new_code -eq 1 ]] || { cat "$TMP/new.txt"; echo 'New finding did not fail' >&2; exit 43; }
grep -F 'disposition: BASELINED' "$TMP/baselined.txt" >/dev/null
grep -A8 -F 'ERROR policy.NewPolicyCase.newlyIntroducedFinding()V' "$TMP/new.txt" | grep -F 'disposition: NEW' >/dev/null

# Baselines are artifact-independent for the same bytecode/source identity.
jar --create --file "$TMP/base.jar" -C "$TMP/base" .
set +e
"$ROOT/run.sh" --fail-on-new --baseline="$TMP/baseline.json" "$TMP/base.jar" > "$TMP/baselined-jar.txt" 2>&1
jar_code=$?
set -e
[[ $jar_code -eq 0 ]] || { cat "$TMP/baselined-jar.txt"; echo 'Baseline did not survive directory-to-JAR packaging' >&2; exit 44; }

# Invalid, expired, and ticketless suppressions fail closed.
set +e
"$ROOT/run.sh" --fail "$TMP/invalid" > "$TMP/invalid.txt" 2>&1
invalid_code=$?
"$ROOT/run.sh" --fail --require-suppression-ticket "$TMP/invalid" > "$TMP/ticket.txt" 2>&1
ticket_code=$?
set -e
[[ $invalid_code -eq 1 && $ticket_code -eq 1 ]] || { cat "$TMP/invalid.txt"; cat "$TMP/ticket.txt"; exit 45; }
grep -F 'reason must not be blank' "$TMP/invalid.txt" >/dev/null
grep -F 'Expired suppression' "$TMP/invalid.txt" >/dev/null
grep -F 'ticket is required' "$TMP/ticket.txt" >/dev/null

# JSON and SARIF retain fingerprints, dispositions, suppressions, and baseline state.
"$ROOT/run.sh" --json --baseline="$TMP/baseline.json" "$TMP/base" > "$TMP/report.json"
"$ROOT/run.sh" --sarif --baseline="$TMP/baseline.json" "$TMP/base" > "$TMP/report.sarif"
python - "$TMP/report.json" "$TMP/report.sarif" <<'PY_REPORTS'
import json, sys
report = json.load(open(sys.argv[1], encoding='utf-8'))
assert report['baselineFingerprintsLoaded'] > 0
assert any(f['disposition'] == 'SUPPRESSED' and f['suppression'] for f in report['findings'])
assert any(f['disposition'] == 'BASELINED' and len(f['fingerprint']) == 64 for f in report['findings'])
sarif = json.load(open(sys.argv[2], encoding='utf-8'))
results = sarif['runs'][0]['results']
assert any(r.get('suppressions') for r in results)
assert any(r.get('baselineState') == 'unchanged' for r in results)
assert all(len(r['properties']['fingerprint']) == 64 for r in results)
PY_REPORTS

echo 'PASS: secure sources on fields/method returns/parameters/records/types/meta-annotations, inherited contracts, auditable suppressions, expiration/ticket validation, stable baselines, JSON, and SARIF'
