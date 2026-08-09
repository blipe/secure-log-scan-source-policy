# Regression matrix

The harness uses exact method manifests so missed findings, unexpected findings, and severity drift fail the build.

- `expected-positive.txt`: Java language/call/rendering methods that must produce definite `ERROR` findings.
- `expected-possible.txt`: Java language/call/rendering methods that must produce `POSSIBLE` findings.
- `expected-safe.txt`: precision-sensitive methods that must remain finding-free.
- `expected-sanitized.txt`: log-output methods that must produce `SANITIZED`.
- `expected-sanitize-unsafe.txt`: sanitizer cases that must still produce `ERROR`.
- `expected-context-unsafe.txt`: methods that must produce unsafe `CONTEXT_CAPTURE` findings.
- `expected-context-possible.txt`: methods that must produce possible `CONTEXT_CAPTURE` findings.
- `expected-context-sanitized.txt`: methods that must produce sanitized `CONTEXT_CAPTURE` findings.
- `expected-model-unsafe.txt`: configured external-method cases that must produce definite `ERROR` findings.
- `expected-model-sanitized.txt`: configured external-method cases that must produce `SANITIZED` findings.
- `expected-async-unsafe.txt`: reachable asynchronous callbacks and lazy suppliers that must produce `ERROR`.
- `expected-async-possible.txt`: sink-bearing callbacks escaping to unknown code that must produce `POSSIBLE`.
- `expected-async-sanitized.txt`: asynchronous and lazy flows that must remain `SANITIZED`.
- `expected-async-safe.txt`: deferred callback and supplier precision negatives that must remain finding-free.
- `expected-exception-unsafe.txt`: exception message/cause/suppressed and failed-stage flows that must produce `ERROR`.
- `expected-exception-sanitized.txt`: exception and failed-stage flows that must remain `SANITIZED`.
- `expected-exception-safe.txt`: exception precision negatives that must remain finding-free.
- `test-policy.sh`: exact secure-source, suppression, baseline, JSON, and SARIF policy assertions.

The fixtures cover:

- Java control flow, initializers, exceptions, synchronization, records, enums, sealed types, nested/local/anonymous classes, generics, bridges, arrays, and Java 21 patterns;
- every JVM invocation form and `invokedynamic` use for concatenation, records, lambdas, and method references;
- callbacks through custom/JDK functional interfaces, helpers, collections, maps, optionals, streams, executors, threads, completion stages, schedules, and fork/join APIs;
- deferred callback reachability, unknown callback escape uncertainty, and fluent lazy logging suppliers;
- exception messages, causes, suppressed graphs, custom exception rendering, stack-trace overloads, and throwable logger arguments;
- successful versus exceptional `CompletableFuture`/`CompletionStage` channels through composition, observation, recovery, fields, and returns;
- console, writer, JUL, `System.Logger`, logger-shaped and fluent logging APIs;
- SLF4J MDC/MDCAdapter, Log4j 2 ThreadContext/CloseableThreadContext, Log4j 1 MDC/NDC, and JBoss MDC/NDC;
- context maps, stacks, formatted varargs, objects rendered through `toString()`, helpers, lambdas, and method references;
- sanitized context, unsafe-dominates behavior, different-origin separation, capture-then-clear behavior, and removal/clear negatives;
- possible propagation through unavailable calls and compiler-inlined secure constants;
- exact external sink, renderer, callback, mutation, and sanitizer models with modeled API bytecode omitted;
- 60-call worklist convergence, worklist-cap failure, duplicate-class detection, and malformed-class detection;
- directory, class, JAR, WAR, nested dependency, module-path, selected `jrt:/` module, JSON, custom annotation, conservative, Java 17, and Java 21 operation;
- dependency secure fields, sanitizers, rendering, virtual dispatch, dependency-owned sinks, cross-boundary scope, and internal dependency policy;
- Spring Boot/WAR layouts, Maven and module provenance, multi-release JAR selection, and duplicate precedence;
- secure fields, method returns, parameters, record components, entire types, transitive meta-annotations, and inherited method contracts;
- auditable method/type suppressions, required reasons, optional ticket enforcement, expiry validation, helper propagation, stable baselines, dispositions, JSON, and SARIF.

Java 21 fixtures run when `javac` 21 or newer is available. Set `SECURE_LOG_SCAN_SKIP_JAVA21=true` to exercise the Java 17-only branch.
