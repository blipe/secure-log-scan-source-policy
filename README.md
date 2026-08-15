# secure-log-scan-source-policy

A dependency-free, JDK-only bytecode analyzer that tracks data sources marked `@secure.Secure` and reports when their values reach logs, diagnostic context, exception output, or asynchronous output.

## Build with Maven

Requires JDK 21 and Maven 3.9 or newer. Maven resolves only build plugins; the produced scanner has no runtime dependencies.

```bash
mvn --batch-mode --no-transfer-progress clean verify
```

The executable artifact is:

```text
target/secure-log-scan-source-policy-12.0.0-SNAPSHOT.jar
```

Run it with the JDK internal-ASM exports:

```bash
java \
  --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED \
  --add-exports java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED \
  --add-exports java.base/jdk.internal.org.objectweb.asm.tree.analysis=ALL-UNNAMED \
  -jar target/secure-log-scan-source-policy-12.0.0-SNAPSHOT.jar \
  --fail path/to/application.jar
```

The original dependency-free `build.sh`, `run.sh`, `test.sh`, and `test-policy.sh` workflows remain available.

## Annotations

### Secure sources

`@Secure` has `RetentionPolicy.CLASS` and can mark fields, method returns, parameters, record components, or an entire type:

```java
import secure.Secure;

final class Customer {
    @Secure("PII")
    String ssn;

    @Secure
    String governmentId() {
        return ssn;
    }

    void accept(@Secure String externalId) {
        // externalId begins this method as an UNSAFE source.
    }
}

record Payment(@Secure String accountNumber) {}

@Secure
record SecretEnvelope(String value) {}
```

Method and parameter contracts are propagated across interface implementations and superclass overrides. A secure type marks values of that type, including values seen through a secure supertype or interface, as unsafe to render.

Corporate meta-annotations are discovered transitively from scanned bytecode:

```java
@Secure("corporate PII")
@Retention(RetentionPolicy.CLASS)
@Target({FIELD, METHOD, PARAMETER, RECORD_COMPONENT, TYPE})
@interface Pii {}

final class Customer {
    @Pii String ssn;
}
```

An additional non-meta-annotated corporate source annotation can still be configured explicitly:

```bash
./run.sh --annotation=com.acme.security.Secret path/to/classes
```

### Sanitizer method

```java
import secure.Sanitize;

final class LogValues {
    @Sanitize(
        description = "Stable one-way correlation value",
        justification = "Approved security utility SEC-1421"
    )
    static String hash(String value) {
        return approvedHash(value);
    }
}
```

Both attributes are optional. `@Sanitize` is an explicit trust boundary: the analyzer reports its metadata but does not claim to prove the implementation.

A corporate sanitizer annotation can be added with:

```bash
./run.sh --sanitize-annotation=com.acme.security.LogSafe path/to/classes
```

## Auditable suppressions and baselines

A suppression never erases a finding. It changes the finding disposition to `SUPPRESSED` and is retained in text, JSON, and SARIF:

```java
@SuppressSecureLog(
    reason = "Required regulated audit output",
    ticket = "SEC-1842",
    expires = "2026-12-31"
)
void writeRegulatedAudit(Customer customer) {
    LOG.info("ssn={}", customer.ssn);
}
```

Rules:

- `reason` is required and must be non-blank;
- `ticket` is optional, or mandatory with `--require-suppression-ticket`;
- `expires` is optional ISO `yyyy-MM-dd`;
- invalid and expired suppressions produce fail-closed `INCOMPLETE` findings;
- method suppressions follow summarized flows through helpers and callbacks;
- type suppressions apply to methods declared in that type.

Existing findings can be baselined without hiding them:

```bash
./run.sh --write-baseline=secure-log-baseline.json application.jar
./run.sh --fail-on-new --baseline=secure-log-baseline.json application.jar
```

Each unsafe or possible finding receives a stable SHA-256 fingerprint. Its disposition is one of:

```text
NEW
BASELINED
SUPPRESSED
SANITIZED
```

`--fail-on-new` fails only unsuppressed findings absent from the supplied baseline. Plain `--fail` remains strict and does not exempt baselined findings. Baselines are valid JSON and remain stable when the same classes move between a directory and a JAR.


## Actionable diagnostics and SARIF

Every data-flow finding now includes:

- source file and source line when debug line tables are present;
- JVM instruction index within the containing method;
- zero-based sink argument position, or `-1` for a receiver/implicit sink;
- constant MDC/ThreadContext key when recoverable;
- interprocedural call path from the reporting method to the actual sink;
- application, dependency, sink, and secure-source artifact provenance.

Example:

```text
ERROR diagnostics.DiagnosticCases.directMdc()V
  category: CONTEXT_CAPTURE
  sink: org.slf4j.MDC.put(Ljava/lang/String;Ljava/lang/String;)V
  source location: diagnostics.DiagnosticCases.directMdc()V (DiagnosticCases.java:11) [instruction 3]
  sink argument: 1
  context key: customer.ssn
  call path:
    - diagnostics.DiagnosticCases.directMdc()V (DiagnosticCases.java:11) [instruction 3]
```

SARIF 2.1.0 can be emitted to stdout or written alongside the normal report:

```bash
./run.sh --sarif path/to/classes > secure-log.sarif
./run.sh --sarif=build/reports/secure-log.sarif path/to/classes
./run.sh --json --sarif=build/reports/secure-log.sarif path/to/classes
```

SARIF results include rule IDs, physical and logical locations, secure sources as related locations, code-flow steps, sink argument, context key, uncertainty reasons, sanitizer metadata, and artifact provenance. Exact class-file byte offsets are not claimed because ASM tree normalization does not preserve every original encoding width; the report uses a stable JVM instruction index plus the source line.

## Async callbacks and lazy logging

Common JDK asynchronous boundaries are built in; they do not require a method-model file:

- `Executor` and `ExecutorService`, including `execute`, `submit`, `invokeAll`, and `invokeAny`;
- `ScheduledExecutorService`;
- `Thread`, `Thread.Builder`, `ThreadFactory`, and virtual-thread startup where present;
- `CompletableFuture` and `CompletionStage` composition;
- `ForkJoinPool` and `ForkJoinTask`;
- callbacks carried through helper methods, fields, arrays, collections, returned values, nested lambdas, and method references.

A lambda body is analyzed as deferred code. Creating it does not by itself produce a finding:

```java
Runnable unused = () -> LOG.info(customer.ssn); // no finding
executor.execute(() -> LOG.info(customer.ssn)); // UNSAFE
```

When a callback containing a sink escapes into an unavailable or unmodeled API, the scanner cannot prove whether it executes. It emits `POSSIBLE` with `CALLBACK_MAY_EXECUTE`:

```java
externalRegistry.register(() -> LOG.info(customer.ssn));
// POSSIBLE: CALLBACK_MAY_EXECUTE
```

A configured `callback` model replaces that uncertainty with exact invocation semantics for proprietary frameworks.

Lazy fluent logging arguments are evaluated when the eventual log operation is analyzed, including suppliers passed directly or through helper methods:

```java
LOG.atInfo().addArgument(() -> customer.ssn).log("ssn={}"); // UNSAFE
LOG.atInfo().addKeyValue("ssn", () -> LogValues.hash(customer.ssn)).log(); // SANITIZED
```

Async boundaries preserve the normal state rules: definite unsafe values remain `UNSAFE`, approved sanitizer results remain `SANITIZED`, and unresolved callback execution remains `POSSIBLE`.

## Exception graphs and asynchronous failures

Exception output is analyzed as a graph rather than as only the top-level message. The scanner follows:

- standard exception message constructors;
- cause constructors and `initCause`;
- suppressed exceptions added through `addSuppressed`;
- nested cause/suppressed combinations with cycle protection;
- `getMessage`, `getLocalizedMessage`, `getCause`, and `getSuppressed`;
- custom exception overrides of `getMessage`, `getLocalizedMessage`, and `toString`;
- `printStackTrace()` plus its `PrintStream` and `PrintWriter` overloads;
- throwable arguments supplied to logging APIs;
- exception values carried through helpers, fields, returns, and arrays.

Example:

```java
RuntimeException failure = new RuntimeException("request failed");
failure.addSuppressed(new RuntimeException(customer.ssn));
failure.printStackTrace(); // UNSAFE
```

Sanitized exception text remains separately reported:

```java
new RuntimeException(LogValues.hash(customer.ssn)).printStackTrace(); // SANITIZED
```

`CompletableFuture` and `CompletionStage` keep successful values and exceptional completions in separate analysis channels. Failure data is propagated through `thenApply`, `thenAccept`, `thenRun`, `whenComplete`, `handle`, `exceptionally`, combination stages, fields, and helper returns:

```java
CompletableFuture.failedFuture(new RuntimeException(customer.ssn))
    .exceptionally(error -> {
        error.printStackTrace(); // UNSAFE
        return null;
    });
```

A secure successful value is not treated as a failure merely because a `whenComplete` callback has a throwable parameter.

## Dependency and classpath analysis

Application inputs are positional arguments. Dependency bytecode is supplied separately so the analyzer can preserve precedence, provenance, and finding policy:

```bash
./run.sh --fail \
  --classpath=lib/customer-model.jar:lib/security-utils.jar \
  --module-path=modules \
  --release=21 \
  application.jar
```

On Windows, classpath and module-path lists use `;`, following `File.pathSeparator`. The options are repeatable through `--dependency=<path>` or multiple scanner invocations.

The analyzer assigns every class to one of three roles:

- `APPLICATION`: positional scan inputs;
- `DEPENDENCY`: explicit classpath/module-path entries and nested application libraries;
- `JDK_RUNTIME`: explicitly selected `jrt:/` modules.

Dependency classes participate fully in secure-field discovery, sanitizer discovery, method summaries, rendering, mutation, virtual/interface dispatch, callbacks, and sink propagation. They are not merely indexed by name.

### Supported dependency layouts

- ordinary class directories and JARs;
- directories containing Maven-style dependency JAR collections;
- modular and automatic-module JARs;
- Spring Boot `BOOT-INF/classes` and recursively discovered `BOOT-INF/lib/*.jar`;
- WAR `WEB-INF/classes` and recursively discovered `WEB-INF/lib/*.jar`;
- shaded/uber JARs;
- multi-release JARs, selecting the highest version not greater than `--release`;
- selected JDK modules through `--jdk-module=<name>` or `--module-path=jrt:/<name>`.

Examples:

```bash
./run.sh --classpath=target/dependency application-classes
./run.sh --jdk-module=jdk.unsupported application-classes
./run.sh --module-path=mods --release=17 application.jar
```

### Artifact identity and provenance

Reports retain the source artifact for:

- every loaded class;
- each `@Secure` source;
- the application/dependency location where a finding is reported;
- the artifact containing the actual sink when the sink is reached through a dependency helper.

Artifact identity is read from, in order:

- `META-INF/maven/**/pom.properties` coordinates;
- `Automatic-Module-Name` or `module-info.class`;
- implementation title/version manifest attributes;
- archive or directory name.

A call from application code into a dependency method that performs logging is therefore reported as `CROSS_BOUNDARY`, with distinct location and sink artifacts.

### Dependency finding policy

Dependency bytecode is always analyzed. Output/failure policy for findings entirely inside dependencies is configurable:

```bash
--dependency-findings=report   # default: report, but do not fail --fail
--dependency-findings=fail     # report and fail
--dependency-findings=ignore   # suppress dependency-internal output only
```

Flows crossing between application and dependency code are never treated as dependency-internal and remain subject to normal failure policy.

### Duplicate classes and precedence

Precedence is deterministic:

```text
application inputs
> explicit classpath order
> explicit module-path order
> nested dependencies
> selected JDK runtime modules
```

The default is fail closed on any duplicate class:

```bash
--duplicate-classes=fail
```

Use `--duplicate-classes=first` only when the above precedence is intentional. Reports still list the selected and shadowed definitions and whether their bytecode was identical or conflicting.

### Missing dependencies

If tracked data enters an unavailable external method and its return later reaches a sink, the result is `POSSIBLE` with `UNRESOLVED_DEPENDENCY`. If a loaded hierarchy references a missing non-JDK type needed for dispatch, the result uses `UNRESOLVED_DISPATCH_TARGET`.

Malformed archives/classes, unsupported class versions, duplicate definitions under fail policy, and dependency-loading failures produce fail-closed `INCOMPLETE` findings.

## External method models

When a library method has no bytecode in the scan, an exact model can describe the behavior that matters to secure-data flow. Load one or more model files with:

```bash
./run.sh --model=security.models path/to/classes
```

The model format is line-oriented, dependency-free, and fail-closed. Blank lines and `#` comments are ignored. Methods use an exact owner, name, and JVM descriptor:

```text
owner::name(JVM-descriptor)
```

Owners may use Java dots or JVM slashes. Value selectors are `receiver`, `arg0`, `arg1`, or `allArgs`. Modes are:

- `direct`: only the selected value itself;
- `render`: textual rendering such as `toString()` and known container contents;
- `deep`: rendering plus fields recursively inspected by serializers or structured sinks.

Supported rules:

```text
sink LOG_OUTPUT com.acme.Audit::write(Ljava/lang/Object;)V values=arg0 mode=deep
sink CONTEXT_CAPTURE com.acme.Context::put(Ljava/lang/String;Ljava/lang/Object;)V values=arg1 mode=deep

renderer com.acme.Json::serialize(Ljava/lang/Object;)Ljava/lang/String; values=arg0 mode=deep

callback com.acme.Dispatcher::submit(Ljava/lang/Object;Ljava/util/function/Consumer;)V target=arg1 invoke=accept(Ljava/lang/Object;)V values=arg0

mutation com.acme.ExternalBag::add(Ljava/lang/Object;)V target=receiver values=arg0 mode=deep

sanitizer com.acme.Redaction::mask(Ljava/lang/String;)Ljava/lang/String; description="Log-safe mask" justification="SEC-1421"
```

Rule meanings:

- `sink`: selected values are emitted or captured immediately;
- `renderer`: the return value is derived from selected inputs, including reflective/serializer-style deep field inspection;
- `callback`: the selected functional object is invoked with the selected values; non-void callback results propagate to the modeled call result;
- `mutation`: selected values become contents of the selected receiver or argument;
- `sanitizer`: the exact external method is an approved sanitization boundary.

Configured behavior participates in interprocedural summaries, lambdas, method references, helper methods, sanitized state, and the normal `UNSAFE > POSSIBLE > SANITIZED` precedence. Invalid rules, missing model files, impossible selectors, duplicate renderer rules, and conflicting sanitizer metadata produce `INCOMPLETE` analysis.

A documented starter file is included at `models/example.models`.

## Outcome model

The scanner exposes four outcomes:

- **UNTRACKED**: no relationship to an `@Secure` field was detected; no finding is emitted.
- **UNSAFE**: the bytecode proves a secure-derived value reaches a sink; emitted as `ERROR`.
- **POSSIBLE**: a secure-derived flow may reach a sink, but bytecode alone cannot prove the link; emitted separately with an uncertainty reason.
- **SANITIZED**: the value passed through an approved `@Sanitize` method; allowed but reported separately.

```java
System.out.println(customer.ssn);                 // UNSAFE / LOG_OUTPUT
System.out.println(LogValues.hash(customer.ssn)); // SANITIZED / LOG_OUTPUT

MDC.put("ssn", customer.ssn);                     // UNSAFE / CONTEXT_CAPTURE
MDC.put("ssnToken", LogValues.hash(customer.ssn)); // SANITIZED / CONTEXT_CAPTURE
```

### Why `POSSIBLE` exists

Two cases cannot always be decided from compiled bytecode:

1. **Compiler-inlined secure constants**

```java
@Secure static final String SECRET = "same";
System.out.println("same");
```

`javac` removes the field read. The class file contains only the literal, so the scanner cannot prove whether that literal came from `SECRET` or was written independently. It reports `POSSIBLE` with reason `INLINED_SECURE_CONSTANT` instead of a false definite error.

2. **Unavailable method implementations**

```java
System.out.println(externalTransform(customer.ssn));
```

When `externalTransform` bytecode is not supplied, the scanner conservatively propagates a possible result and reports `UNKNOWN_METHOD_RETURN` if that result reaches a known sink.

Current uncertainty reasons are:

- `INLINED_SECURE_CONSTANT`
- `UNKNOWN_METHOD_RETURN`
- `UNKNOWN_INVOKEDYNAMIC`
- `UNRESOLVED_DEPENDENCY`
- `UNRESOLVED_DISPATCH_TARGET`
- `CALLBACK_MAY_EXECUTE`

At the same sink and for the same secure origin, precedence is:

```text
UNSAFE > POSSIBLE > SANITIZED
```

Different secure origins remain separate.

## Worklist convergence and fail-closed analysis

Interprocedural analysis now uses a monotonic worklist and continues until no method, field, callback, rendering, or sink summary changes. It no longer relies on an arbitrary fixed number of rounds.

Analysis integrity failures are emitted as `INCOMPLETE`, including:

- malformed or unreadable class files;
- duplicate class definitions across scan roots;
- ASM method-analysis failures;
- an explicitly configured worklist safety limit being reached;
- input roots that cannot be read.

With `--fail`, the default policy is fail closed:

- `ERROR` fails;
- `POSSIBLE` fails;
- `INCOMPLETE` fails;
- `SANITIZED` does not fail.

The two uncertainty opt-outs are explicit:

```bash
./run.sh --fail --allow-possible path/to/classes
./run.sh --fail --allow-incomplete-analysis path/to/classes
```

Use `--allow-incomplete-analysis` only when another control guarantees the omitted bytecode is acceptable.

## Diagnostic-context handling

Diagnostic-context writes are first-class sinks with category `CONTEXT_CAPTURE`. The analyzer reports at the write itself because a later logging pattern may emit the value without an explicit read in application bytecode.

```java
MDC.put("ssn", customer.ssn); // finding now
MDC.clear();                   // does not erase the earlier finding
```

Built-in context models include:

- SLF4J `MDC`: `put`, `putCloseable`, `setContextMap`, and `pushByKey`;
- SLF4J `MDCAdapter`: `put`, `setContextMap`, and `pushByKey`;
- Log4j 2 `ThreadContext`: `put`, `putIfNull`, `putAll`, `push`, `pushAll`, and `setStack`;
- Log4j 2 `CloseableThreadContext` and its `Instance`: `put`, `putAll`, `push`, and `pushAll`;
- Log4j 1 `MDC.put` and `NDC.push`;
- JBoss Logging and JBoss Log Manager MDC/NDC entry points.

Removal and clearing APIs are intentionally not sinks. Bulk maps, collections, arrays, formatted stack entries, object values, helper methods, lambdas, and method references are analyzed through the same interprocedural and rendering engine.

## Build and test

JDK 17 or newer is required. Java 21 enables the record-pattern and pattern-switch fixture set.

```bash
./build.sh
./test.sh
```

The JDK 21 harness validates all prior matrices plus:

- secure sources on fields, method returns, parameters, record components, types, and transitive meta-annotations;
- inherited secure return and parameter contracts;
- method-, helper-, and type-level auditable suppressions;
- blank, expired, and ticket-required suppression validation;
- stable baseline generation, `NEW`/`BASELINED`/`SUPPRESSED` dispositions, JSON, and SARIF;
- 136 exact definite-unsafe language/call/rendering methods;
- 5 exact possible language/call/rendering methods;
- 22 explicit precision negatives;
- 15 sanitized log-output flows;
- 6 sanitizer-related unsafe flows;
- 34 unsafe diagnostic-context methods;
- 1 possible diagnostic-context method;
- 6 sanitized diagnostic-context methods;
- 13 exact configured-model unsafe methods;
- 4 exact configured-model sanitized methods;
- 25 exact async/lazy unsafe methods on JDK 21, or 22 on the Java 17-only branch;
- 2 exact callback-escape possible methods;
- 5 exact async/lazy sanitized methods;
- explicit negatives for unused lambdas, never-started threads, ignored callbacks, and safe suppliers;
- explicit dependency classpaths and module paths;
- application-to-dependency and dependency-to-application cross-boundary flows;
- dependency-owned sinks reached from application secure sources;
- dependency-internal `report`, `fail`, and `ignore` policy;
- Spring Boot and WAR nested dependency discovery;
- Java 17 versus Java 21 multi-release JAR selection;
- Maven coordinates, manifest metadata, modular-JAR names, and `jrt:/` module provenance;
- duplicate-class fail/first precedence behavior;
- a reverse-ordered 60-call chain that exceeded the old 20-round design;
- fail-closed worklist-cap, duplicate-class, malformed-class, and unreadable-input behavior.

The tests compile with warnings treated as errors and exercise directory, individual class, JAR, WAR, nested JAR, module path, selected `jrt:/` module, JSON, SARIF, source-line diagnostics, sink arguments, MDC keys, call paths, custom annotation, conservative-analysis, Java 17, and Java 21 modes. Set `SECURE_LOG_SCAN_SKIP_JAVA21=true` to force the Java 17-compatible branch on a newer JDK.

## Run

```bash
./run.sh path/to/classes-or-jar
./run.sh --fail path/to/classes-or-jar
./run.sh --json path/to/classes-or-jar
./run.sh --sarif path/to/classes-or-jar > secure-log.sarif
./run.sh --sarif=build/secure-log.sarif path/to/classes-or-jar
```

Options:

- `--fail`: exit `1` on `UNSAFE`, `POSSIBLE`, or `INCOMPLETE` findings;
- `--allow-possible`: with `--fail`, do not fail on `POSSIBLE` findings;
- `--allow-incomplete-analysis`: with `--fail`, do not fail on `INCOMPLETE` analysis;
- `--baseline=<path>`: load stable finding fingerprints;
- `--write-baseline=<path>`: write current unsafe/possible fingerprints as JSON;
- `--fail-on-new`: fail only unsuppressed findings not present in the baseline;
- `--require-suppression-ticket`: reject suppressions with a blank ticket;
- `--suppression-annotation=<fqcn|descriptor>`: configure an alternative suppression annotation;
- `--json`: emit machine-readable JSON output;
- `--sarif`: emit SARIF 2.1.0 to stdout;
- `--sarif=<path>`: write SARIF 2.1.0 while retaining normal text or JSON stdout output;
- `--annotation=<fqcn|descriptor>`: add a secure-source annotation;
- `--sanitize-annotation=<fqcn|descriptor>`: add a sanitizer-method annotation;
- `--classpath=<paths>` / `--class-path=<paths>` / `--dependency=<paths>`: dependency classes and JARs in precedence order;
- `--module-path=<paths>`: dependency module directories/JARs; accepts `jrt:/<module>`;
- `--jdk-module=<name[,name...]>`: load selected runtime modules through `jrt:/`;
- `--release=N`: target release used for multi-release JAR selection;
- `--duplicate-classes=fail|first`: duplicate-definition policy;
- `--dependency-findings=report|fail|ignore`: dependency-internal output/failure policy;
- `--model=<path>`: load an exact external method-model file; repeatable (`--models` is an alias);
- `--no-conservative-unknown-calls`: stop propagating unavailable method returns;
- `--max-work-items=N`: worklist safety cap, default `10000000`; use `0` for no cap.

## Finding categories

Each data-flow finding has a sink category:

- `LOG_OUTPUT`: textual output through logging, printing, formatting, or stack traces;
- `CONTEXT_CAPTURE`: data stored in MDC, NDC, ThreadContext, or equivalent modeled context;
- `ANALYSIS`: analysis-integrity finding rather than a data-flow sink.

Example definite finding:

```text
ERROR com.acme.CustomerHandler.handle()V
  category: CONTEXT_CAPTURE
  sink: org.slf4j.MDC.put(Ljava/lang/String;Ljava/lang/String;)V
  state: UNSAFE
  flow: value captured in diagnostic context
  secure fields:
    - com.acme.Customer.ssn:Ljava/lang/String;
```

Example uncertain finding:

```text
POSSIBLE com.acme.CustomerHandler.handle()V
  category: LOG_OUTPUT
  sink: java.io.PrintStream.println(Ljava/lang/String;)V
  state: POSSIBLE
  flow: possibly secure value rendered by log/print sink
  secure fields:
    - com.acme.Customer.ssn:Ljava/lang/String;
  uncertainty reasons:
    - UNKNOWN_METHOD_RETURN
```

JSON output includes `analysisComplete`, `worklistMethodAnalyses`, `state`, `category`, `uncertaintyReasons`, source fields, and sanitizer metadata.

## Analysis coverage

### Dependency-aware resolution

- Closed-world dispatch across all supplied application and dependency implementations.
- Secure fields, sanitizers, renderers, callbacks, field mutations, and sink summaries defined in dependencies.
- Cross-artifact propagation with separate application location, actual sink artifact, and source-field artifacts.
- Conservative `POSSIBLE` outcomes when required external bytecode or hierarchy members are unavailable.

### Java data flow

- Operand stack, locals, branches, merges, loops, casts, arithmetic, boxing, and unboxing.
- Direct and derived field stores.
- Static, virtual, interface, special, bridge, overloaded, generic, recursive, and constructor calls.
- Arguments, varargs, returns, factories, getters, setters, fluent chains, and unavailable-call propagation.
- String concatenation, builders, formatters, joiners, arrays, and compiler-inlined secure constants.

### Object rendering

- Explicit and implicit `toString()`.
- Generated and record `toString()` bytecode.
- Nested objects behind `Object`, interfaces, superclasses, generics, records, containers, maps, optionals, and arrays.
- Logger placeholders, varargs, suppliers, exception messages, and `printStackTrace`.
- Separate shallow-array and deep-array behavior to avoid treating `println(Object[])` as element rendering.

### Lambdas and method references

- Captured locals and `this`, block and nested lambdas, serializable lambdas, returned and field-stored lambdas.
- Static, bound, unbound, getter, returning, and constructor references.
- Custom functional interfaces and common JDK callback types.
- Direct invocation, helper-mediated callbacks, collections, maps, optionals, and streams.

Creating a lambda is not itself a leak. Its body is applied when the functional object is invoked or passed through a modeled callback path.

## Log-output sinks

Built-in `LOG_OUTPUT` recognition includes:

- `PrintStream`, `PrintWriter`, and `Console` printing and formatting;
- `java.util.logging.Logger`;
- `System.Logger`;
- logger-shaped SLF4J, Log4j, and application APIs, including fluent event builders;
- `Throwable.printStackTrace` and subclass calls.

## Sanitizer semantics

`@Sanitize` applies only to the return value. It does not make its input safe inside the sanitizer:

```java
@Sanitize
static String bad(String value) {
    System.out.println(value); // still UNSAFE
    return value;              // caller receives SANITIZED because annotation is trusted
}
```

This exposes annotation misuse without requiring a complex approval framework.

## Interpretation and remaining boundaries

This is static **may-reach** analysis. A definite finding means supplied bytecode proves a path by which secure data can reach a recognized output or diagnostic-context sink. A possible finding means the path depends on provenance or code not recoverable from the supplied bytecode.

Additional models or runtime instrumentation are still needed for:

- APIs that are neither supplied through application/dependency/JDK inputs nor declared in a method-model file;
- reflection or method handles whose target cannot be resolved;
- native code;
- runtime-generated classes and dynamic proxies;
- serializers or structured sinks not represented by supplied bytecode or a `renderer`/`sink` model;
- proprietary or framework callback semantics not represented by supplied bytecode, a built-in JDK model, or a configured `callback` model;
- security properties of a sanitizer that depend on organizational review.
