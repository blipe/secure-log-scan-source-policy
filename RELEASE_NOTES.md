# 12.0.0

- Expanded `@Secure` from fields to method returns, parameters, record components, and types.
- Added transitive secure meta-annotation discovery for corporate annotations such as `@Pii`.
- Added secure method/parameter contract propagation across interfaces and superclass overrides.
- Added `@secure.SuppressSecureLog` with required reason, optional ticket, and optional ISO expiration.
- Preserved suppressed findings in text, JSON, and SARIF with `SUPPRESSED` disposition and audit metadata.
- Added fail-closed validation for blank reasons, invalid/expired dates, and optional required tickets.
- Added helper/callback suppression propagation and type-level suppressions.
- Added stable SHA-256 finding fingerprints and JSON baseline generation/loading.
- Added `NEW`, `BASELINED`, `SUPPRESSED`, and `SANITIZED` dispositions.
- Added `--baseline`, `--write-baseline`, `--fail-on-new`, `--require-suppression-ticket`, and `--suppression-annotation`.
- Added SARIF accepted suppressions and `baselineState=unchanged` for baselined findings.
- Added exact policy regression coverage for all new source targets, meta-annotations, inherited contracts, suppressions, baseline stability, JSON, and SARIF.
- Preserved all v11 exception, diagnostics, dependency, callback, method-model, MDC, sanitizer, worklist, Java 17, and Java 21 behavior.

# 11.0.0

- Added first-class exception-graph analysis for messages, causes, suppressed exceptions, and nested combinations.
- Added exact handling for `initCause`, `addSuppressed`, `getCause`, `getSuppressed`, `getMessage`, and `getLocalizedMessage`.
- Added custom exception rendering through overridden `getMessage`, `getLocalizedMessage`, and `toString` methods.
- Added graph-aware `printStackTrace()` handling for no-argument, `PrintStream`, and `PrintWriter` overloads.
- Added throwable graph propagation through helpers, fields, method returns, arrays, and logging throwable arguments.
- Added a separate exceptional-completion channel for `CompletableFuture` and `CompletionStage`.
- Propagated exceptional completion state through composition, observation, recovery, combination, fields, and helper returns without confusing successful values with failures.
- Preserved `UNSAFE`, `POSSIBLE`, and `SANITIZED` states throughout exception and completion-failure graphs.
- Added 27 exact exception-graph unsafe methods, 3 sanitized exception methods, and 5 precision negatives.
- Preserved all v10 diagnostics, SARIF, dependency, callback, method-model, MDC, sanitizer, worklist, Java 17, and Java 21 regressions.

# 10.0.0

- Added source-file and source-line diagnostics by retaining class debug metadata.
- Added stable JVM instruction indices for sink call sites.
- Added zero-based sink argument positions, including configured sinks and diagnostic-context captures.
- Added constant MDC/ThreadContext key recovery through locals and normal stack flow.
- Added bounded, cycle-safe interprocedural call paths carried through method summaries, lambdas, callbacks, and dependency boundaries.
- Added diagnostic metadata to text and JSON output.
- Added SARIF 2.1.0 output through `--sarif` and `--sarif=<path>`.
- Added SARIF rules for unsafe, possible, sanitized, and incomplete outcomes.
- Added SARIF physical/logical locations, related secure-source locations, code flows, uncertainty reasons, sanitizer metadata, sink metadata, and artifact provenance.
- Added exact regression fixtures for source lines, instruction indices, sink arguments, MDC keys, helper call paths, JSON diagnostics, stdout SARIF, and file SARIF.
- Preserved all v9 callback, dependency, method-model, MDC, sanitizer, worklist, Java 17, and Java 21 regressions.

# 9.0.0

- Added reachability-aware lambda analysis: creating an unused lambda no longer reports its deferred sink body.
- Added built-in callback execution models for `Executor`, `ExecutorService`, `ScheduledExecutorService`, `Thread`, `Thread.Builder`, `ThreadFactory`, `CompletableFuture`, `CompletionStage`, `ForkJoinPool`, and `ForkJoinTask`.
- Added callback propagation through helpers, fields, arrays, collections, returned values, nested callbacks, and method references.
- Added exact propagation of callback return values through `CompletableFuture`/`CompletionStage` chains.
- Added lazy SLF4J-style fluent supplier evaluation for `addArgument`, `addKeyValue`, and eventual `log` calls, including suppliers passed through helper methods.
- Added `CALLBACK_MAY_EXECUTE` possible-flow reporting when a sink-bearing callback escapes to unavailable or unmodeled code.
- Preserved sanitized state through asynchronous and lazy execution paths.
- Added precision negatives for unused lambdas, callbacks that ignore secure inputs, never-started threads, sink-free escaped callbacks, and safe suppliers.
- Added 25 JDK 21 async/lazy unsafe methods (22 on the Java 17-only branch), 2 callback-escape possible methods, and 5 async/lazy sanitized methods to the exact regression matrix.
- Retained all v8 dependency, nested archive, multi-release, artifact provenance, duplicate policy, method model, MDC, sanitizer, worklist, Java 17, and Java 21 regressions.

# 8.0.0

- Added first-class application, dependency, and selected JDK-runtime class roles.
- Added `--classpath`, `--class-path`, `--dependency`, and `--module-path` dependency inputs.
- Added selected `jrt:/` runtime-module loading through `--jdk-module` and `--module-path=jrt:/<module>`.
- Added Spring Boot `BOOT-INF/classes` plus recursive `BOOT-INF/lib` discovery.
- Added WAR `WEB-INF/classes` plus recursive `WEB-INF/lib` discovery.
- Added multi-release JAR selection controlled by `--release`, loading exactly one applicable class version.
- Added modular-JAR metadata from `module-info.class` and automatic-module manifest metadata.
- Added Maven `pom.properties`, implementation title/version, module, archive, and directory artifact identity.
- Added artifact inventory and per-class role counts to text and JSON reports.
- Added source-field, finding-location, and actual-sink artifact provenance.
- Added `APPLICATION`, `CROSS_BOUNDARY`, `DEPENDENCY_INTERNAL`, and `ANALYSIS` finding scopes.
- Added dependency-internal `report`, `fail`, and `ignore` policies without disabling dependency analysis.
- Added deterministic precedence: application, explicit classpath, explicit module path, nested dependencies, JDK runtime.
- Added fail-closed duplicate detection and opt-in `--duplicate-classes=first` shadowing with bytecode identity reporting.
- Added `UNRESOLVED_DEPENDENCY` and `UNRESOLVED_DISPATCH_TARGET` possible-flow reasons.
- Added tests for dependency `toString`, virtual dispatch, dependency sanitizers, dependency-owned sinks, missing dependencies, internal dependency findings, nested Boot/WAR layouts, multi-release JARs, modular JARs, selected JDK modules, duplicate precedence, and JSON provenance.
- Retained all v7 language, rendering, callback, logging, MDC, sanitizer, method-model, possible-flow, worklist, Java 17, and Java 21 regressions.
