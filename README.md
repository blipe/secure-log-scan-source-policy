# Secure Log Scan Source Policy

JDK-only bytecode analysis that tracks values marked with `@secure.Secure` and reports flows into logging, diagnostic context, exception output, and asynchronous output.

The scanner uses the JDK's internal ASM implementation and has no runtime dependencies.

## Build

Requires JDK 21 and Maven 3.9 or newer.

```bash
mvn --batch-mode --no-transfer-progress clean package
```

Or use the dependency-free build script:

```bash
./build.sh
```

## Run

```bash
./run.sh --fail path/to/application.jar
```

The scanner supports application and dependency inputs, nested JARs, multi-release JARs, secure fields/parameters/returns/types/meta-annotations, sanitizer boundaries, MDC and ThreadContext capture, asynchronous callbacks, exception graphs, source diagnostics, SARIF, suppressions, and baselines.

Useful options include:

```text
--fail
--fail-on-new
--baseline=<file>
--write-baseline=<file>
--json
--sarif[=<file>]
--classpath=<paths>
--module-path=<paths>
--model=<file>
--dependency-findings=report|fail|ignore
--duplicate-classes=fail|first
```

## Example

```java
final class Customer {
    @secure.Secure("PII")
    String ssn;
}

@secure.Sanitize(
    description = "Stable one-way correlation value",
    justification = "Approved security utility SEC-1421"
)
static String hash(String value) {
    return approvedHash(value);
}
```

Raw secure values reaching recognized output are `UNSAFE`; uncertain flows are `POSSIBLE`; approved sanitizer returns are tracked separately as `SANITIZED`.
