package securelogscan;

import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.Handle;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.Type;
import jdk.internal.org.objectweb.asm.tree.*;
import jdk.internal.org.objectweb.asm.tree.analysis.*;

import java.io.*;
import java.net.URI;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.jar.*;

/**
 * JDK-only bytecode scanner for @secure.Secure sources reaching log/print or diagnostic-context sinks.
 *
 * Values have four user-facing outcomes: UNTRACKED, UNSAFE, POSSIBLE, and SANITIZED.
 * Tracked state is propagated through direct, render, and deep-render channels.
 * @secure.Sanitize is an explicit trust boundary for a method return value.
 *
 * Compile/run with the --add-exports flags shown in README or use build.sh/run.sh.
 */
public final class SecureLogScan {
    private SecureLogScan() {}

    static final int ASM = Opcodes.ASM9;
    static final String DEFAULT_SECURE_ANNOTATION_DESC = "Lsecure/Secure;";
    static final String DEFAULT_SANITIZE_ANNOTATION_DESC = "Lsecure/Sanitize;";
    static final String DEFAULT_SUPPRESSION_ANNOTATION_DESC = "Lsecure/SuppressSecureLog;";

    public static void main(String[] args) throws Exception {
        Config cfg = Config.parse(args);
        if (cfg.help || cfg.roots.isEmpty()) {
            Config.printHelp();
            System.exit(cfg.roots.isEmpty() && !cfg.help ? 2 : 0);
        }

        ScanModel model = new ScanModel(cfg);
        model.loadConfiguredInputs();
        model.collectSecureFields();
        model.loadMethodModels();
        model.loadBaseline();
        model.analyzeToFixpoint();
        model.writeBaselineIfRequested();
        model.printReport();
        if ((cfg.failOnFinding || cfg.failOnNew) && model.hasFailingFinding()) System.exit(1);
    }

    enum ArtifactRole { APPLICATION, DEPENDENCY, JDK_RUNTIME }
    enum DuplicateClassPolicy { FAIL, FIRST }
    enum DependencyFindingsPolicy { REPORT, FAIL, IGNORE }
    enum FindingScope { APPLICATION, CROSS_BOUNDARY, DEPENDENCY_INTERNAL, ANALYSIS }

    static final class Config {
        final List<Path> roots = new ArrayList<>();
        final List<Path> classpathRoots = new ArrayList<>();
        final List<Path> modulePathRoots = new ArrayList<>();
        final List<String> jdkModules = new ArrayList<>();
        final Set<String> annotationDescs = new LinkedHashSet<>();
        final Set<String> sanitizeAnnotationDescs = new LinkedHashSet<>();
        final Set<String> suppressionAnnotationDescs = new LinkedHashSet<>();
        final List<Path> modelFiles = new ArrayList<>();
        Path baselineFile;
        Path writeBaselineFile;
        boolean json;
        boolean sarif;
        Path sarifOutput;
        boolean failOnFinding;
        boolean failOnNew;
        boolean requireSuppressionTicket;
        boolean conservativeUnknownCalls = true;
        boolean allowPossible;
        boolean allowIncompleteAnalysis;
        boolean help;
        long maxWorkItems = 10_000_000L;
        int release = Runtime.version().feature();
        DuplicateClassPolicy duplicateClassPolicy = DuplicateClassPolicy.FAIL;
        DependencyFindingsPolicy dependencyFindingsPolicy = DependencyFindingsPolicy.REPORT;

        Config() {
            annotationDescs.add(DEFAULT_SECURE_ANNOTATION_DESC);
            sanitizeAnnotationDescs.add(DEFAULT_SANITIZE_ANNOTATION_DESC);
            suppressionAnnotationDescs.add(DEFAULT_SUPPRESSION_ANNOTATION_DESC);
        }

        static Config parse(String[] args) {
            Config c = new Config();
            for (String a : args) {
                if (a.equals("--help") || a.equals("-h")) c.help = true;
                else if (a.equals("--json")) c.json = true;
                else if (a.equals("--sarif")) c.sarif = true;
                else if (a.startsWith("--sarif=")) c.sarifOutput = Paths.get(a.substring("--sarif=".length()).trim());
                else if (a.equals("--fail")) c.failOnFinding = true;
                else if (a.equals("--fail-on-new")) c.failOnNew = true;
                else if (a.equals("--require-suppression-ticket")) c.requireSuppressionTicket = true;
                else if (a.equals("--no-conservative-unknown-calls")) c.conservativeUnknownCalls = false;
                else if (a.equals("--allow-possible")) c.allowPossible = true;
                else if (a.equals("--allow-incomplete-analysis")) c.allowIncompleteAnalysis = true;
                else if (a.startsWith("--annotation=")) c.annotationDescs.add(toAnnotationDesc(a.substring("--annotation=".length()).trim()));
                else if (a.startsWith("--sanitize-annotation=")) c.sanitizeAnnotationDescs.add(toAnnotationDesc(a.substring("--sanitize-annotation=".length()).trim()));
                else if (a.startsWith("--suppression-annotation=")) c.suppressionAnnotationDescs.add(toAnnotationDesc(a.substring("--suppression-annotation=".length()).trim()));
                else if (a.startsWith("--baseline=")) c.baselineFile = Paths.get(a.substring("--baseline=".length()).trim());
                else if (a.startsWith("--write-baseline=")) c.writeBaselineFile = Paths.get(a.substring("--write-baseline=".length()).trim());
                else if (a.startsWith("--model=")) c.modelFiles.add(Paths.get(a.substring("--model=".length()).trim()));
                else if (a.startsWith("--models=")) c.modelFiles.add(Paths.get(a.substring("--models=".length()).trim()));
                else if (a.startsWith("--max-work-items=")) c.maxWorkItems = Long.parseLong(a.substring("--max-work-items=".length()));
                else if (a.startsWith("--release=")) c.release = Integer.parseInt(a.substring("--release=".length()));
                else if (a.startsWith("--classpath=")) addPathList(c.classpathRoots, c.jdkModules, a.substring("--classpath=".length()), false);
                else if (a.startsWith("--class-path=")) addPathList(c.classpathRoots, c.jdkModules, a.substring("--class-path=".length()), false);
                else if (a.startsWith("--dependency=")) addPathList(c.classpathRoots, c.jdkModules, a.substring("--dependency=".length()), false);
                else if (a.startsWith("--module-path=")) addPathList(c.modulePathRoots, c.jdkModules, a.substring("--module-path=".length()), true);
                else if (a.startsWith("--jdk-module=")) addCommaList(c.jdkModules, a.substring("--jdk-module=".length()));
                else if (a.startsWith("--jdk-modules=")) addCommaList(c.jdkModules, a.substring("--jdk-modules=".length()));
                else if (a.startsWith("--duplicate-classes=")) c.duplicateClassPolicy = parseEnum(DuplicateClassPolicy.class, a.substring("--duplicate-classes=".length()));
                else if (a.startsWith("--dependency-findings=")) c.dependencyFindingsPolicy = parseEnum(DependencyFindingsPolicy.class, a.substring("--dependency-findings=".length()));
                else c.roots.add(Paths.get(a));
            }
            if (c.release < 8) throw new IllegalArgumentException("--release must be at least 8");
            if (c.json && c.sarif) throw new IllegalArgumentException("--json and --sarif are mutually exclusive");
            return c;
        }

        static <E extends Enum<E>> E parseEnum(Class<E> type, String value) {
            try { return Enum.valueOf(type, value.trim().toUpperCase(Locale.ROOT)); }
            catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("Invalid " + type.getSimpleName() + " value: " + value, ex);
            }
        }

        static void addCommaList(List<String> target, String value) {
            for (String item : value.split(",")) if (!item.isBlank()) target.add(item.trim());
        }

        static void addPathList(List<Path> target, List<String> jdkModules, String value, boolean modulePath) {
            if (value == null || value.isBlank()) return;
            String separator = File.pathSeparator;
            String[] parts;
            if (value.startsWith("jrt:/")) parts = new String[]{value};
            else parts = value.split(java.util.regex.Pattern.quote(separator));
            for (String part : parts) {
                if (part.isBlank()) continue;
                String trimmed = part.trim();
                if (trimmed.startsWith("jrt:/")) {
                    String module = trimmed.substring("jrt:/".length());
                    if (module.startsWith("modules/")) module = module.substring("modules/".length());
                    if (module.endsWith("/")) module = module.substring(0, module.length() - 1);
                    if (!module.isBlank()) jdkModules.add(module);
                } else target.add(Paths.get(trimmed));
            }
        }

        static String toAnnotationDesc(String v) {
            if (v.startsWith("L") && v.endsWith(";")) return v;
            return "L" + v.replace('.', '/') + ";";
        }

        static void printHelp() {
            System.out.println("Usage: java <exports> securelogscan.SecureLogScan [options] <application-class-dir|class|jar>...");
            System.out.println("Options:");
            System.out.println("  --classpath=<paths>                 Dependency class directories/JARs in precedence order");
            System.out.println("  --module-path=<paths>               Dependency module directories/JARs; jrt:/<module> is accepted");
            System.out.println("  --jdk-module=<name[,name...]>       Analyze selected runtime modules through jrt:/");
            System.out.println("  --release=<N>                       Multi-release JAR target, default current runtime feature");
            System.out.println("  --duplicate-classes=fail|first      Conflicting duplicate policy, default fail");
            System.out.println("  --dependency-findings=report|fail|ignore  Dependency-internal finding policy, default report");
            System.out.println("  --annotation=<fqcn|Linternal/Desc;> Secure annotation, default secure.Secure");
            System.out.println("  --sanitize-annotation=<fqcn|desc>   Sanitizer annotation, default secure.Sanitize");
            System.out.println("  --suppression-annotation=<fqcn|desc> Suppression annotation, default secure.SuppressSecureLog");
            System.out.println("  --baseline=<path>                   Mark matching stable fingerprints as BASELINED");
            System.out.println("  --write-baseline=<path>             Write current unsafe/possible fingerprints as JSON");
            System.out.println("  --fail-on-new                       Fail only on unsuppressed findings absent from the baseline");
            System.out.println("  --require-suppression-ticket        Reject suppressions without a ticket");
            System.out.println("  --model=<path>                      Load exact external method models; repeatable");
            System.out.println("  --json                              Emit JSON report");
            System.out.println("  --sarif                             Emit SARIF 2.1.0 to stdout");
            System.out.println("  --sarif=<path>                      Also write SARIF 2.1.0 to a file");
            System.out.println("  --fail                              Exit 1 on applicable UNSAFE, POSSIBLE, or incomplete analysis");
            System.out.println("  --allow-possible                    With --fail, do not fail on POSSIBLE findings");
            System.out.println("  --allow-incomplete-analysis         With --fail, do not fail when analysis is incomplete");
            System.out.println("  --no-conservative-unknown-calls     Do not track unknown method returns from tracked args");
            System.out.println("  --max-work-items=N                  Safety cap for worklist processing, default 10000000");
        }
    }

    static final class ArtifactInfo implements Comparable<ArtifactInfo> {
        final String id;
        final String path;
        final ArtifactRole role;
        final String coordinate;
        final String moduleName;
        final String version;

        ArtifactInfo(String id, String path, ArtifactRole role, String coordinate, String moduleName, String version) {
            this.id = id == null || id.isBlank() ? path : id;
            this.path = path;
            this.role = role;
            this.coordinate = coordinate == null ? "" : coordinate;
            this.moduleName = moduleName == null ? "" : moduleName;
            this.version = version == null ? "" : version;
        }

        String displayName() {
            if (!coordinate.isBlank()) return coordinate;
            if (!moduleName.isBlank() && !version.isBlank()) return moduleName + ":" + version;
            if (!moduleName.isBlank()) return moduleName;
            return id;
        }

        @Override public int compareTo(ArtifactInfo other) {
            int c = role.compareTo(other.role); if (c != 0) return c;
            c = displayName().compareTo(other.displayName()); if (c != 0) return c;
            return path.compareTo(other.path);
        }
    }

    static final class ClassOrigin {
        final String source;
        final ArtifactInfo artifact;
        final int priority;
        final String sha256;

        ClassOrigin(String source, ArtifactInfo artifact, int priority, String sha256) {
            this.source = source;
            this.artifact = artifact;
            this.priority = priority;
            this.sha256 = sha256;
        }
    }

    static final class NestedArchive {
        final byte[] bytes;
        final String source;
        final ArtifactInfo parent;
        NestedArchive(byte[] bytes, String source, ArtifactInfo parent) {
            this.bytes = bytes;
            this.source = source;
            this.parent = parent;
        }
    }

    static final class DuplicateClass implements Comparable<DuplicateClass> {
        final String className;
        final ClassOrigin selected;
        final ClassOrigin duplicate;
        final boolean identical;

        DuplicateClass(String className, ClassOrigin selected, ClassOrigin duplicate, boolean identical) {
            this.className = className;
            this.selected = selected;
            this.duplicate = duplicate;
            this.identical = identical;
        }

        @Override public int compareTo(DuplicateClass other) {
            int c = className.compareTo(other.className); if (c != 0) return c;
            c = selected.source.compareTo(other.selected.source); if (c != 0) return c;
            return duplicate.source.compareTo(other.duplicate.source);
        }
    }

    static final class ScanModel {
        static final int PRIORITY_APPLICATION = 300;
        static final int PRIORITY_EXPLICIT_DEPENDENCY = 200;
        static final int PRIORITY_MODULE_PATH = 180;
        static final int PRIORITY_NESTED_DEPENDENCY = 100;
        static final int PRIORITY_JDK_RUNTIME = 10;

        final Config cfg;
        final Map<String, ClassNode> classes = new LinkedHashMap<>();
        final Map<String, ClassOrigin> classOrigins = new LinkedHashMap<>();
        final Map<String, ArtifactInfo> artifacts = new LinkedHashMap<>();
        final List<NestedArchive> nestedArchives = new ArrayList<>();
        final Set<DuplicateClass> duplicateClasses = new TreeSet<>();
        final Map<MethodKey, MethodNode> methods = new LinkedHashMap<>();
        final Set<MethodKey> deferredLambdaBodies = new LinkedHashSet<>();
        final Set<FieldKey> annotatedSecureFields = new LinkedHashSet<>();
        final Set<String> effectiveSecureAnnotationDescs = new LinkedHashSet<>();
        final Map<MethodKey, FieldKey> secureMethodReturns = new LinkedHashMap<>();
        final Map<MethodKey, Map<Integer, FieldKey>> secureParameters = new LinkedHashMap<>();
        final Map<String, FieldKey> secureTypes = new LinkedHashMap<>();
        final Set<FieldKey> taintedFields = new LinkedHashSet<>();
        final Map<FieldKey, Set<Source>> fieldDirectSources = new LinkedHashMap<>();
        final Map<FieldKey, Set<Source>> fieldRenderSources = new LinkedHashMap<>();
        final Map<FieldKey, Set<Source>> fieldDeepRenderSources = new LinkedHashMap<>();
        final Map<FieldKey, Set<Source>> fieldCompletionFailureSources = new LinkedHashMap<>();
        final Map<FieldKey, Set<TypeRef>> fieldTypes = new LinkedHashMap<>();
        final Map<FieldKey, Set<LambdaTemplate>> fieldLambdas = new LinkedHashMap<>();
        final Map<Object, Set<FieldKey>> secureConstantFields = new LinkedHashMap<>();
        final Map<MethodKey, MethodSummary> summaries = new LinkedHashMap<>();
        final Map<MethodKey, SanitizerInfo> sanitizers = new LinkedHashMap<>();
        final Map<MethodKey, SuppressionInfo> methodSuppressions = new LinkedHashMap<>();
        final Map<String, SuppressionInfo> typeSuppressions = new LinkedHashMap<>();
        final Set<String> baselineFingerprints = new LinkedHashSet<>();
        final MethodModelRegistry methodModels = new MethodModelRegistry();
        final Set<Finding> findings = new TreeSet<>();
        boolean changed;
        long analyzedWorkItems;

        ScanModel(Config cfg) { this.cfg = cfg; }

        void loadConfiguredInputs() {
            int index = 0;
            for (Path root : cfg.roots) loadSafely(root, ArtifactRole.APPLICATION, PRIORITY_APPLICATION - index++, true);
            index = 0;
            for (Path root : cfg.classpathRoots) loadSafely(root, ArtifactRole.DEPENDENCY, PRIORITY_EXPLICIT_DEPENDENCY - index++, false);
            index = 0;
            for (Path root : cfg.modulePathRoots) loadSafely(root, ArtifactRole.DEPENDENCY, PRIORITY_MODULE_PATH - index++, false);

            int nestedIndex = 0;
            while (nestedIndex < nestedArchives.size()) {
                NestedArchive nested = nestedArchives.get(nestedIndex++);
                try {
                    loadJarBytes(nested.bytes, nested.source, ArtifactRole.DEPENDENCY,
                            PRIORITY_NESTED_DEPENDENCY, false);
                } catch (IOException | RuntimeException ex) {
                    addFinding(Finding.incomplete("Unable to scan nested dependency " + nested.source + ": " + ex));
                }
            }

            for (String module : new LinkedHashSet<>(cfg.jdkModules)) {
                try { loadJdkModule(module); }
                catch (IOException | RuntimeException ex) {
                    addFinding(Finding.incomplete("Unable to scan JDK module " + module + " through jrt:/: " + ex));
                }
            }
        }

        void loadSafely(Path root, ArtifactRole role, int priority, boolean applicationRoot) {
            try { load(root, role, priority, applicationRoot); }
            catch (IOException | RuntimeException ex) {
                addFinding(Finding.incomplete("Unable to scan input " + root + ": " + ex));
            }
        }

        void load(Path root, ArtifactRole role, int priority, boolean applicationRoot) throws IOException {
            if (!Files.exists(root)) throw new IOException("Missing path: " + root);
            if (Files.isDirectory(root)) {
                ArtifactInfo directoryArtifact = registerArtifact(new ArtifactInfo(
                        root.getFileName() == null ? root.toString() : root.getFileName().toString(),
                        root.toAbsolutePath().normalize().toString(), role, "", "", ""));
                List<Path> files;
                try (var stream = Files.walk(root)) {
                    files = stream.filter(Files::isRegularFile).sorted().toList();
                }
                for (Path file : files) {
                    String name = file.getFileName().toString();
                    if (name.endsWith(".class")) {
                        loadClassBytes(Files.readAllBytes(file), file.toString(), directoryArtifact, priority);
                    } else if (name.endsWith(".jar")) {
                        byte[] bytes = Files.readAllBytes(file);
                        if (applicationRoot) {
                            nestedArchives.add(new NestedArchive(bytes, file.toString(), directoryArtifact));
                        } else {
                            loadJarBytes(bytes, file.toString(), role, priority, false);
                        }
                    }
                }
            } else if (root.toString().endsWith(".jar") || root.toString().endsWith(".war")) {
                loadJarBytes(Files.readAllBytes(root), root.toAbsolutePath().normalize().toString(), role, priority, applicationRoot);
            } else if (root.toString().endsWith(".class")) {
                ArtifactInfo artifact = registerArtifact(new ArtifactInfo(root.getFileName().toString(),
                        root.toAbsolutePath().normalize().toString(), role, "", "", ""));
                loadClassBytes(Files.readAllBytes(root), root.toString(), artifact, priority);
            } else throw new IOException("Unsupported input path: " + root + " (expected class dir, .class, .jar, or .war)");
        }

        void loadJarBytes(byte[] jarBytes, String source, ArtifactRole role, int priority, boolean applicationRoot) throws IOException {
            Map<String, byte[]> entries = new LinkedHashMap<>();
            Manifest manifest;
            try (JarInputStream in = new JarInputStream(new ByteArrayInputStream(jarBytes))) {
                manifest = in.getManifest();
                JarEntry entry;
                while ((entry = in.getNextJarEntry()) != null) {
                    if (entry.isDirectory()) continue;
                    entries.put(entry.getName(), in.readAllBytes());
                }
            }
            if (manifest == null && entries.containsKey(JarFile.MANIFEST_NAME)) {
                manifest = new Manifest(new ByteArrayInputStream(entries.get(JarFile.MANIFEST_NAME)));
            }
            ArtifactInfo artifact = registerArtifact(artifactFromArchive(source, role, manifest, entries));

            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                String name = entry.getKey();
                if (isNestedDependencyEntry(name)) {
                    nestedArchives.add(new NestedArchive(entry.getValue(), source + "!/" + name, artifact));
                }
            }

            boolean multiRelease = manifest != null && "true".equalsIgnoreCase(
                    manifest.getMainAttributes().getValue(Attributes.Name.MULTI_RELEASE));
            boolean containerArchive = applicationRoot && isContainerArchive(entries);
            Map<String, VersionedClassEntry> selected = new TreeMap<>();
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                String name = entry.getKey();
                if (!name.endsWith(".class")) continue;
                if (name.endsWith("module-info.class")) continue;
                VersionedClassEntry candidate = versionedClassEntry(name, entry.getValue(), multiRelease);
                if (candidate == null || candidate.version > cfg.release) continue;
                if (containerArchive && !isApplicationClassEntry(name)
                        && !name.startsWith("META-INF/versions/")) continue;
                VersionedClassEntry prior = selected.get(candidate.logicalName);
                if (prior == null || candidate.version > prior.version) selected.put(candidate.logicalName, candidate);
            }
            for (VersionedClassEntry entry : selected.values()) {
                loadClassBytes(entry.bytes, source + "!/" + entry.originalName, artifact, priority);
            }
        }

        boolean isContainerArchive(Map<String, byte[]> entries) {
            return entries.keySet().stream().anyMatch(name -> name.startsWith("BOOT-INF/classes/") || name.startsWith("WEB-INF/classes/"));
        }

        boolean isApplicationClassEntry(String name) {
            return name.startsWith("BOOT-INF/classes/") || name.startsWith("WEB-INF/classes/");
        }

        boolean isNestedDependencyEntry(String name) {
            return name.endsWith(".jar") && (name.startsWith("BOOT-INF/lib/") || name.startsWith("WEB-INF/lib/"));
        }

        VersionedClassEntry versionedClassEntry(String name, byte[] bytes, boolean multiRelease) {
            if (!name.startsWith("META-INF/versions/")) return new VersionedClassEntry(name, name, 0, bytes);
            if (!multiRelease) return null;
            String remainder = name.substring("META-INF/versions/".length());
            int slash = remainder.indexOf('/');
            if (slash <= 0) return null;
            try {
                int version = Integer.parseInt(remainder.substring(0, slash));
                String logical = remainder.substring(slash + 1);
                return new VersionedClassEntry(logical, name, version, bytes);
            } catch (NumberFormatException ex) {
                return null;
            }
        }

        ArtifactInfo artifactFromArchive(String source, ArtifactRole role, Manifest manifest, Map<String, byte[]> entries) {
            String fileName = source;
            int bang = fileName.lastIndexOf("!/");
            if (bang >= 0) fileName = fileName.substring(bang + 2);
            int slash = Math.max(fileName.lastIndexOf('/'), fileName.lastIndexOf(File.separatorChar));
            if (slash >= 0) fileName = fileName.substring(slash + 1);

            String coordinate = "";
            String version = "";
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                String name = entry.getKey();
                if (!name.startsWith("META-INF/maven/") || !name.endsWith("/pom.properties")) continue;
                Properties properties = new Properties();
                try { properties.load(new ByteArrayInputStream(entry.getValue())); }
                catch (IOException ignored) { continue; }
                String group = properties.getProperty("groupId", "").trim();
                String artifact = properties.getProperty("artifactId", "").trim();
                version = properties.getProperty("version", "").trim();
                if (!artifact.isBlank()) coordinate = (group.isBlank() ? artifact : group + ":" + artifact)
                        + (version.isBlank() ? "" : ":" + version);
                break;
            }

            String module = "";
            String title = "";
            if (manifest != null) {
                Attributes attrs = manifest.getMainAttributes();
                module = value(attrs, "Automatic-Module-Name");
                title = value(attrs, "Implementation-Title");
                if (version.isBlank()) version = value(attrs, "Implementation-Version");
            }
            if (module.isBlank()) module = moduleNameFromEntries(entries, manifest);
            String id = !coordinate.isBlank() ? coordinate : (!title.isBlank() ? title + (version.isBlank() ? "" : ":" + version) : fileName);
            return new ArtifactInfo(id, source, role, coordinate, module, version);
        }

        String moduleNameFromEntries(Map<String, byte[]> entries, Manifest manifest) {
            boolean multiRelease = manifest != null && "true".equalsIgnoreCase(
                    manifest.getMainAttributes().getValue(Attributes.Name.MULTI_RELEASE));
            byte[] selected = entries.get("module-info.class");
            int selectedVersion = 0;
            if (multiRelease) {
                for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                    String name = entry.getKey();
                    if (!name.startsWith("META-INF/versions/") || !name.endsWith("/module-info.class")) continue;
                    String remainder = name.substring("META-INF/versions/".length());
                    int slash = remainder.indexOf('/');
                    if (slash <= 0) continue;
                    try {
                        int version = Integer.parseInt(remainder.substring(0, slash));
                        if (version <= cfg.release && version > selectedVersion) {
                            selectedVersion = version;
                            selected = entry.getValue();
                        }
                    } catch (NumberFormatException ignored) {
                        // Ignore malformed versioned metadata; class loading will still handle valid entries.
                    }
                }
            }
            if (selected == null) return "";
            try {
                ClassNode node = new ClassNode(ASM);
                new ClassReader(selected).accept(node, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
                return node.module == null || node.module.name == null ? "" : node.module.name;
            } catch (RuntimeException ex) {
                return "";
            }
        }

        String value(Attributes attrs, String name) {
            String value = attrs.getValue(name);
            return value == null ? "" : value.trim();
        }

        ArtifactInfo registerArtifact(ArtifactInfo artifact) {
            ArtifactInfo prior = artifacts.putIfAbsent(artifact.path, artifact);
            return prior == null ? artifact : prior;
        }

        void loadJdkModule(String module) throws IOException {
            FileSystem fs;
            try { fs = FileSystems.getFileSystem(URI.create("jrt:/")); }
            catch (FileSystemNotFoundException ex) { fs = FileSystems.newFileSystem(URI.create("jrt:/"), Map.of()); }
            Path root = fs.getPath("/modules", module);
            if (!Files.exists(root)) throw new IOException("Unknown runtime module: " + module);
            ArtifactInfo artifact = registerArtifact(new ArtifactInfo("jrt:" + module, "jrt:/" + module,
                    ArtifactRole.JDK_RUNTIME, "", module, Runtime.version().toString()));
            try (var stream = Files.walk(root)) {
                for (Path file : stream.filter(Files::isRegularFile).filter(p -> p.toString().endsWith(".class")).sorted().toList()) {
                    if (file.getFileName().toString().equals("module-info.class")) continue;
                    loadClassBytes(Files.readAllBytes(file), "jrt:/" + module + "/" + root.relativize(file), artifact, PRIORITY_JDK_RUNTIME);
                }
            }
        }

        void loadClassBytes(byte[] bytes, String source, ArtifactInfo artifact, int priority) {
            try {
                ClassReader reader = new ClassReader(bytes);
                ClassNode node = new ClassNode(ASM);
                reader.accept(node, 0);
                ClassOrigin incoming = new ClassOrigin(source, artifact, priority, sha256(bytes));
                ClassOrigin prior = classOrigins.get(node.name);
                if (prior != null) {
                    boolean identical = prior.sha256.equals(incoming.sha256);
                    duplicateClasses.add(new DuplicateClass(node.name, prior, incoming, identical));
                    if (cfg.duplicateClassPolicy == DuplicateClassPolicy.FAIL) {
                        addFinding(Finding.incomplete("Duplicate class " + node.name.replace('/', '.')
                                + " selected from " + prior.source + " and also found in " + source
                                + (identical ? " (identical bytecode)" : " (conflicting bytecode)")));
                    }
                    return;
                }
                classOrigins.put(node.name, incoming);
                classes.put(node.name, node);
            } catch (RuntimeException ex) {
                addFinding(Finding.incomplete("Unable to read " + source + ": " + ex));
            }
        }

        String sha256(byte[] bytes) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
                StringBuilder out = new StringBuilder(digest.length * 2);
                for (byte b : digest) out.append(String.format(Locale.ROOT, "%02x", b & 0xff));
                return out.toString();
            } catch (NoSuchAlgorithmException ex) {
                throw new IllegalStateException(ex);
            }
        }

        ClassOrigin origin(String owner) { return classOrigins.get(owner); }
        ArtifactInfo artifact(String owner) {
            ClassOrigin origin = origin(owner);
            return origin == null ? null : origin.artifact;
        }

        UncertaintyReason unknownCallReason(MethodInsnNode call, TaintValue receiver) {
            if (!classes.containsKey(call.owner) && !isJdkOwner(call.owner)) return UncertaintyReason.UNRESOLVED_DEPENDENCY;
            if ((call.getOpcode() == Opcodes.INVOKEVIRTUAL || call.getOpcode() == Opcodes.INVOKEINTERFACE)
                    && hierarchyReferencesMissing(call.owner, new HashSet<>())) {
                return UncertaintyReason.UNRESOLVED_DISPATCH_TARGET;
            }
            if (receiver != null) {
                for (TypeRef type : receiver.types) {
                    if (!type.array && hierarchyReferencesMissing(type.name, new HashSet<>())) {
                        return UncertaintyReason.UNRESOLVED_DISPATCH_TARGET;
                    }
                }
            }
            return UncertaintyReason.UNKNOWN_METHOD_RETURN;
        }

        boolean hierarchyReferencesMissing(String type, Set<String> seen) {
            if (type == null || !seen.add(type) || isJdkOwner(type)) return false;
            ClassNode node = classes.get(type);
            if (node == null) return true;
            if (node.superName != null && !node.superName.equals("java/lang/Object")
                    && hierarchyReferencesMissing(node.superName, seen)) return true;
            if (node.interfaces != null) {
                for (String iface : node.interfaces) if (hierarchyReferencesMissing(iface, seen)) return true;
            }
            return false;
        }

        boolean isJdkOwner(String owner) {
            return owner.startsWith("java/") || owner.startsWith("javax/") || owner.startsWith("jdk/")
                    || owner.startsWith("sun/") || owner.startsWith("com/sun/");
        }

        static final class VersionedClassEntry {
            final String logicalName;
            final String originalName;
            final int version;
            final byte[] bytes;
            VersionedClassEntry(String logicalName, String originalName, int version, byte[] bytes) {
                this.logicalName = logicalName;
                this.originalName = originalName;
                this.version = version;
                this.bytes = bytes;
            }
        }

        void collectSecureFields() {
            effectiveSecureAnnotationDescs.clear();
            effectiveSecureAnnotationDescs.addAll(cfg.annotationDescs);
            expandSecureMetaAnnotations();

            for (ClassNode cn : classes.values()) {
                boolean annotationType = (cn.access & Opcodes.ACC_ANNOTATION) != 0;
                if (!annotationType && hasSecureAnnotation(cn.visibleAnnotations, cn.invisibleAnnotations)) {
                    FieldKey typeSource = new FieldKey(cn.name, "<type>", "L" + cn.name + ";");
                    secureTypes.put(cn.name, typeSource);
                    registerSecureSource(typeSource, null);
                }

                SuppressionInfo typeSuppression = suppressionFrom(cn.visibleAnnotations, cn.invisibleAnnotations,
                        cn.name.replace('/', '.'));
                if (typeSuppression != null) typeSuppressions.put(cn.name, typeSuppression);

                Map<String, RecordComponentNode> recordComponents = new LinkedHashMap<>();
                if (cn.recordComponents != null) {
                    for (RecordComponentNode component : cn.recordComponents) {
                        recordComponents.put(component.name + component.descriptor, component);
                        if (hasSecureAnnotation(component.visibleAnnotations, component.invisibleAnnotations)) {
                            FieldKey fieldSource = new FieldKey(cn.name, component.name, component.descriptor);
                            registerSecureSource(fieldSource, null);
                            MethodKey accessor = new MethodKey(cn.name, component.name, "()" + component.descriptor);
                            secureMethodReturns.put(accessor, fieldSource);
                        }
                    }
                }

                for (FieldNode fn : cn.fields) {
                    FieldKey fk = new FieldKey(cn.name, fn.name, fn.desc);
                    boolean recordSecure = recordComponents.containsKey(fn.name + fn.desc)
                            && hasSecureAnnotation(recordComponents.get(fn.name + fn.desc).visibleAnnotations,
                            recordComponents.get(fn.name + fn.desc).invisibleAnnotations);
                    if (hasSecureAnnotation(fn.visibleAnnotations, fn.invisibleAnnotations) || recordSecure) {
                        registerSecureSource(fk, fn.value);
                    }
                    TypeRef declared = TypeRef.declared(Type.getType(fn.desc));
                    if (declared != null) fieldTypes.computeIfAbsent(fk, k -> new TreeSet<>()).add(declared);
                }

                String canonicalRecordConstructor = canonicalRecordConstructor(cn);
                for (MethodNode mn : cn.methods) {
                    MethodKey mk = MethodKey.of(cn, mn);
                    if (!mn.name.equals("<init>") && Type.getReturnType(mn.desc) != Type.VOID_TYPE
                            && hasSecureAnnotation(mn.visibleAnnotations, mn.invisibleAnnotations)) {
                        FieldKey source = secureMethodReturns.computeIfAbsent(mk, ignored ->
                                new FieldKey(cn.name, mn.name + "@return", Type.getReturnType(mn.desc).getDescriptor()));
                        registerSecureSource(source, null);
                    }

                    int receiverOffset = (mn.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
                    Type[] argumentTypes = Type.getArgumentTypes(mn.desc);
                    for (int parameterIndex = 0; parameterIndex < argumentTypes.length; parameterIndex++) {
                        if (hasSecureParameterAnnotation(mn, parameterIndex)) {
                            int ordinal = parameterIndex + receiverOffset;
                            FieldKey source;
                            if (canonicalRecordConstructor != null && mn.name.equals("<init>")
                                    && mn.desc.equals(canonicalRecordConstructor) && cn.recordComponents != null
                                    && parameterIndex < cn.recordComponents.size()
                                    && hasSecureAnnotation(cn.recordComponents.get(parameterIndex).visibleAnnotations,
                                    cn.recordComponents.get(parameterIndex).invisibleAnnotations)) {
                                RecordComponentNode component = cn.recordComponents.get(parameterIndex);
                                source = new FieldKey(cn.name, component.name, component.descriptor);
                            } else {
                                source = new FieldKey(cn.name,
                                        mn.name + "@param" + parameterIndex, argumentTypes[parameterIndex].getDescriptor());
                                registerSecureSource(source, null);
                            }
                            secureParameters.computeIfAbsent(mk, ignored -> new LinkedHashMap<>()).put(ordinal, source);
                        }
                    }

                    AnnotationNode annotation = findAnnotation(mn.visibleAnnotations, cfg.sanitizeAnnotationDescs);
                    if (annotation == null) annotation = findAnnotation(mn.invisibleAnnotations, cfg.sanitizeAnnotationDescs);
                    if (annotation != null) {
                        sanitizers.put(mk, new SanitizerInfo(mk,
                                annotationString(annotation, "description"),
                                annotationString(annotation, "justification")));
                    }

                    SuppressionInfo methodSuppression = suppressionFrom(mn.visibleAnnotations, mn.invisibleAnnotations,
                            mk.toString());
                    if (methodSuppression != null) methodSuppressions.put(mk, methodSuppression);
                }
            }
            propagateInheritedSecureContracts();
        }

        void propagateInheritedSecureContracts() {
            for (MethodKey method : new ArrayList<>(methodsDeclaredInClasses())) {
                for (String ancestor : ancestorTypes(method.owner)) {
                    MethodKey declaration = new MethodKey(ancestor, method.name, method.desc);
                    FieldKey returnSource = secureMethodReturns.get(declaration);
                    if (returnSource != null) secureMethodReturns.putIfAbsent(method, returnSource);
                    Map<Integer, FieldKey> inheritedParameters = secureParameters.get(declaration);
                    if (inheritedParameters != null && !inheritedParameters.isEmpty()) {
                        Map<Integer, FieldKey> target = secureParameters.computeIfAbsent(method, ignored -> new LinkedHashMap<>());
                        for (Map.Entry<Integer, FieldKey> entry : inheritedParameters.entrySet()) {
                            target.putIfAbsent(entry.getKey(), entry.getValue());
                        }
                    }
                }
            }
        }

        Set<MethodKey> methodsDeclaredInClasses() {
            Set<MethodKey> out = new LinkedHashSet<>();
            for (ClassNode owner : classes.values()) {
                for (MethodNode method : owner.methods) out.add(MethodKey.of(owner, method));
            }
            return out;
        }

        Set<String> ancestorTypes(String owner) {
            Set<String> out = new LinkedHashSet<>();
            Deque<String> queue = new ArrayDeque<>();
            ClassNode start = classes.get(owner);
            if (start != null) {
                if (start.superName != null) queue.add(start.superName);
                if (start.interfaces != null) queue.addAll(start.interfaces);
            }
            while (!queue.isEmpty()) {
                String current = queue.removeFirst();
                if (!out.add(current)) continue;
                ClassNode node = classes.get(current);
                if (node == null) continue;
                if (node.superName != null) queue.addLast(node.superName);
                if (node.interfaces != null) queue.addAll(node.interfaces);
            }
            return out;
        }

        void registerSecureSource(FieldKey source, Object constantValue) {
            annotatedSecureFields.add(source);
            taintedFields.add(source);
            fieldDirectSources.computeIfAbsent(source, ignored -> new TreeSet<>()).add(Source.field(source));
            if (constantValue != null) secureConstantFields.computeIfAbsent(constantValue, ignored -> new TreeSet<>()).add(source);
        }

        void expandSecureMetaAnnotations() {
            boolean expanded;
            do {
                expanded = false;
                for (ClassNode annotationClass : classes.values()) {
                    if ((annotationClass.access & Opcodes.ACC_ANNOTATION) == 0) continue;
                    String descriptor = "L" + annotationClass.name + ";";
                    if (effectiveSecureAnnotationDescs.contains(descriptor)) continue;
                    if (containsDescriptor(annotationClass.visibleAnnotations, effectiveSecureAnnotationDescs)
                            || containsDescriptor(annotationClass.invisibleAnnotations, effectiveSecureAnnotationDescs)) {
                        effectiveSecureAnnotationDescs.add(descriptor);
                        expanded = true;
                    }
                }
            } while (expanded);
        }

        boolean containsDescriptor(List<AnnotationNode> annotations, Set<String> descriptors) {
            if (annotations == null) return false;
            for (AnnotationNode annotation : annotations) if (descriptors.contains(annotation.desc)) return true;
            return false;
        }

        boolean hasSecureAnnotation(List<AnnotationNode> visible, List<AnnotationNode> invisible) {
            return containsDescriptor(visible, effectiveSecureAnnotationDescs)
                    || containsDescriptor(invisible, effectiveSecureAnnotationDescs);
        }

        boolean hasSecureParameterAnnotation(MethodNode method, int parameterIndex) {
            return hasParameterAnnotation(method.visibleParameterAnnotations, parameterIndex)
                    || hasParameterAnnotation(method.invisibleParameterAnnotations, parameterIndex);
        }

        boolean hasParameterAnnotation(List<AnnotationNode>[] annotations, int parameterIndex) {
            return annotations != null && parameterIndex >= 0 && parameterIndex < annotations.length
                    && containsDescriptor(annotations[parameterIndex], effectiveSecureAnnotationDescs);
        }

        String canonicalRecordConstructor(ClassNode cn) {
            if (cn.recordComponents == null || cn.recordComponents.isEmpty()) return null;
            StringBuilder descriptor = new StringBuilder("(");
            for (RecordComponentNode component : cn.recordComponents) descriptor.append(component.descriptor);
            return descriptor.append(")V").toString();
        }

        FieldKey secureParameterSource(MethodKey method, int ordinal) {
            return secureParameters.getOrDefault(method, Map.of()).get(ordinal);
        }

        Set<Source> secureTypeSources(Type type) {
            if (type == null || type.getSort() != Type.OBJECT) return Set.of();
            FieldKey source = secureTypeSource(type.getInternalName(), new HashSet<>());
            return source == null ? Set.of() : Set.of(Source.field(source));
        }

        FieldKey secureTypeSource(String type, Set<String> visited) {
            if (type == null || !visited.add(type)) return null;
            FieldKey direct = secureTypes.get(type);
            if (direct != null) return direct;
            ClassNode node = classes.get(type);
            if (node == null) return null;
            FieldKey fromSuper = secureTypeSource(node.superName, visited);
            if (fromSuper != null) return fromSuper;
            if (node.interfaces != null) {
                for (String iface : node.interfaces) {
                    FieldKey fromInterface = secureTypeSource(iface, visited);
                    if (fromInterface != null) return fromInterface;
                }
            }
            return null;
        }

        SuppressionInfo suppressionFrom(List<AnnotationNode> visible, List<AnnotationNode> invisible, String location) {
            AnnotationNode annotation = findAnnotation(visible, cfg.suppressionAnnotationDescs);
            if (annotation == null) annotation = findAnnotation(invisible, cfg.suppressionAnnotationDescs);
            if (annotation == null) return null;
            String reason = annotationString(annotation, "reason").trim();
            String ticket = annotationString(annotation, "ticket").trim();
            String expires = annotationString(annotation, "expires").trim();
            if (reason.isBlank()) {
                addFinding(Finding.incomplete("Invalid suppression at " + location + ": reason must not be blank"));
                return null;
            }
            if (cfg.requireSuppressionTicket && ticket.isBlank()) {
                addFinding(Finding.incomplete("Invalid suppression at " + location + ": ticket is required"));
                return null;
            }
            if (!expires.isBlank()) {
                try {
                    LocalDate expiration = LocalDate.parse(expires);
                    if (expiration.isBefore(LocalDate.now())) {
                        addFinding(Finding.incomplete("Expired suppression at " + location + ": " + expires));
                        return null;
                    }
                } catch (DateTimeParseException ex) {
                    addFinding(Finding.incomplete("Invalid suppression expiration at " + location
                            + ": expected yyyy-MM-dd but got " + expires));
                    return null;
                }
            }
            return new SuppressionInfo(reason, ticket, expires, location);
        }

        SuppressionInfo suppression(MethodKey method) {
            SuppressionInfo direct = methodSuppressions.get(method);
            return direct != null ? direct : typeSuppressions.get(method.owner);
        }


        void loadMethodModels() {
            for (Path modelFile : cfg.modelFiles) {
                try {
                    methodModels.load(modelFile, this);
                } catch (IOException | RuntimeException ex) {
                    addFinding(Finding.incomplete("Unable to load method model " + modelFile + ": " + ex.getMessage()));
                }
            }
        }

        AnnotationNode findAnnotation(List<AnnotationNode> annotations, Set<String> descriptors) {
            if (annotations == null) return null;
            for (AnnotationNode annotation : annotations) if (descriptors.contains(annotation.desc)) return annotation;
            return null;
        }

        String annotationString(AnnotationNode annotation, String key) {
            if (annotation == null || annotation.values == null) return "";
            for (int i = 0; i + 1 < annotation.values.size(); i += 2) {
                if (key.equals(annotation.values.get(i))) return String.valueOf(annotation.values.get(i + 1));
            }
            return "";
        }

        SanitizerInfo sanitizer(MethodKey method) { return sanitizers.get(method); }

        void analyzeToFixpoint() {
            for (ClassNode cn : classes.values()) {
                for (MethodNode mn : cn.methods) {
                    MethodKey key = MethodKey.of(cn, mn);
                    MethodSummary initial = new MethodSummary();
                    FieldKey secureReturn = secureMethodReturns.get(key);
                    if (secureReturn != null) initial.returnSources.add(Source.field(secureReturn));
                    summaries.put(key, initial);
                    methods.put(key, mn);
                }
            }
            discoverDeferredLambdaBodies();

            ArrayDeque<MethodKey> worklist = new ArrayDeque<>();
            Set<MethodKey> queued = new LinkedHashSet<>();
            enqueueAll(worklist, queued);

            while (!worklist.isEmpty()) {
                if (cfg.maxWorkItems > 0 && analyzedWorkItems >= cfg.maxWorkItems) {
                    addFinding(Finding.incomplete("Worklist safety limit reached after " + analyzedWorkItems
                            + " method analyses; results may be incomplete"));
                    return;
                }
                MethodKey key = worklist.removeFirst();
                queued.remove(key);
                MethodNode method = methods.get(key);
                ClassNode owner = classes.get(key.owner);
                if (method == null || owner == null) {
                    addFinding(Finding.incomplete("Internal worklist entry could not be resolved: " + key));
                    continue;
                }
                analyzedWorkItems++;
                changed = false;
                analyzeMethod(owner, method);
                if (changed) enqueueAll(worklist, queued);
            }
        }


        void discoverDeferredLambdaBodies() {
            deferredLambdaBodies.clear();
            for (ClassNode owner : classes.values()) {
                for (MethodNode method : owner.methods) {
                    for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                        if (!(insn instanceof InvokeDynamicInsnNode indy)) continue;
                        String bootstrapOwner = indy.bsm == null ? "" : indy.bsm.getOwner();
                        if (!bootstrapOwner.equals("java/lang/invoke/LambdaMetafactory")
                                && !bootstrapOwner.equals("java/lang/invoke/InnerClassLambdaMetafactory")) continue;
                        Handle implementation = null;
                        for (Object argument : indy.bsmArgs) {
                            if (argument instanceof Handle handle) {
                                implementation = handle;
                                break;
                            }
                        }
                        if (implementation == null) continue;
                        MethodKey key = new MethodKey(implementation.getOwner(), implementation.getName(), implementation.getDesc());
                        MethodNode implementationMethod = methods.get(key);
                        if (implementationMethod == null) continue;
                        // Only synthetic lambda bodies are deferred. Normal methods used by a method reference remain
                        // ordinary independently reachable methods and are analyzed/reported normally.
                        if ((implementationMethod.access & Opcodes.ACC_SYNTHETIC) != 0
                                && implementationMethod.name.startsWith("lambda$")) {
                            deferredLambdaBodies.add(key);
                        }
                    }
                }
            }
        }

        boolean isDeferredLambdaBody(MethodKey method) {
            return deferredLambdaBodies.contains(method);
        }

        void enqueueAll(ArrayDeque<MethodKey> worklist, Set<MethodKey> queued) {
            for (MethodKey key : methods.keySet()) {
                if (queued.add(key)) worklist.addLast(key);
            }
        }

        void analyzeMethod(ClassNode cn, MethodNode mn) {
            MethodKey mk = MethodKey.of(cn, mn);
            TaintInterpreter interp = new TaintInterpreter(this, cn, mn, mk);
            Analyzer<TaintValue> analyzer = new Analyzer<>(interp);
            try {
                analyzer.analyze(cn.name, mn);
            } catch (AnalyzerException | RuntimeException ex) {
                addFinding(Finding.incomplete("Analyzer skipped " + mk + ": " + ex.getMessage()));
            }
        }

        boolean hasFailingFinding() {
            for (Finding finding : findings) {
                if (finding.severity.equals("INCOMPLETE") && !cfg.allowIncompleteAnalysis) return true;
                if (isSuppressed(finding)) continue;
                if (cfg.failOnNew && isBaselined(finding)) continue;
                FindingScope scope = findingScope(finding);
                boolean dependencyInternal = scope == FindingScope.DEPENDENCY_INTERNAL;
                if (dependencyInternal && cfg.dependencyFindingsPolicy != DependencyFindingsPolicy.FAIL) continue;
                if (finding.severity.equals("ERROR")) return true;
                if (finding.severity.equals("POSSIBLE") && !cfg.allowPossible) return true;
            }
            return false;
        }

        FindingScope findingScope(Finding finding) {
            if (finding.category == SinkCategory.ANALYSIS) return FindingScope.ANALYSIS;
            ArtifactInfo sinkArtifact = artifact(finding.sinkArtifactOwner);
            boolean sinkApplication = sinkArtifact == null || sinkArtifact.role == ArtifactRole.APPLICATION;
            boolean hasApplicationSource = false;
            boolean hasDependencySource = false;
            for (FieldKey field : finding.fields) {
                ArtifactInfo sourceArtifact = artifact(field.owner);
                if (sourceArtifact == null || sourceArtifact.role == ArtifactRole.APPLICATION) hasApplicationSource = true;
                else hasDependencySource = true;
            }
            if (sinkApplication) return hasDependencySource ? FindingScope.CROSS_BOUNDARY : FindingScope.APPLICATION;
            return hasApplicationSource ? FindingScope.CROSS_BOUNDARY : FindingScope.DEPENDENCY_INTERNAL;
        }

        List<Finding> visibleFindings() {
            List<Finding> out = new ArrayList<>();
            for (Finding finding : findings) {
                if (cfg.dependencyFindingsPolicy == DependencyFindingsPolicy.IGNORE
                        && findingScope(finding) == FindingScope.DEPENDENCY_INTERNAL) continue;
                out.add(finding);
            }
            return out;
        }

        String artifactDisplay(String owner) {
            ArtifactInfo artifact = artifact(owner);
            return artifact == null ? "unresolved" : artifact.displayName() + " [" + artifact.role + "]";
        }

        void addFinding(Finding finding) {
            if (finding.severity.equals("ERROR")) {
                findings.removeIf(existing -> (existing.severity.equals("POSSIBLE") || existing.severity.equals("SANITIZED"))
                        && existing.sameSinkLocation(finding)
                        && !Collections.disjoint(existing.fields, finding.fields));
                findings.add(finding);
                return;
            }
            if (finding.severity.equals("POSSIBLE")) {
                boolean unsafeAlreadyReported = findings.stream().anyMatch(existing -> existing.severity.equals("ERROR")
                        && existing.sameSinkLocation(finding)
                        && !Collections.disjoint(existing.fields, finding.fields));
                if (unsafeAlreadyReported) return;
                findings.removeIf(existing -> existing.severity.equals("SANITIZED")
                        && existing.sameSinkLocation(finding)
                        && !Collections.disjoint(existing.fields, finding.fields));
                findings.add(finding);
                return;
            }
            if (finding.severity.equals("SANITIZED")) {
                boolean strongerAlreadyReported = findings.stream().anyMatch(existing ->
                        (existing.severity.equals("ERROR") || existing.severity.equals("POSSIBLE"))
                                && existing.sameSinkLocation(finding)
                                && !Collections.disjoint(existing.fields, finding.fields));
                if (strongerAlreadyReported) return;
            }
            findings.add(finding);
        }
        void addTaintedField(FieldKey fk) { if (taintedFields.add(fk)) changed = true; }

        void addFieldDirectSources(FieldKey fk, Set<Source> sources) {
            if (sources.isEmpty()) return;
            if (fieldDirectSources.computeIfAbsent(fk, k -> new TreeSet<>()).addAll(sources)) changed = true;
        }

        Set<Source> fieldDirectSources(FieldKey fk) { return fieldDirectSources.getOrDefault(fk, Set.of()); }

        void addFieldRenderSources(FieldKey fk, Set<Source> sources) {
            if (sources.isEmpty()) return;
            if (fieldRenderSources.computeIfAbsent(fk, k -> new TreeSet<>()).addAll(sources)) changed = true;
        }

        void addFieldDeepRenderSources(FieldKey fk, Set<Source> sources) {
            if (sources.isEmpty()) return;
            if (fieldDeepRenderSources.computeIfAbsent(fk, k -> new TreeSet<>()).addAll(sources)) changed = true;
        }

        void addFieldTypes(FieldKey fk, Set<TypeRef> types) {
            if (types.isEmpty()) return;
            if (fieldTypes.computeIfAbsent(fk, k -> new TreeSet<>()).addAll(types)) changed = true;
        }

        Set<Source> fieldRenderSources(FieldKey fk) { return fieldRenderSources.getOrDefault(fk, Set.of()); }
        Set<Source> fieldDeepRenderSources(FieldKey fk) { return fieldDeepRenderSources.getOrDefault(fk, Set.of()); }
        Set<Source> fieldCompletionFailureSources(FieldKey fk) { return fieldCompletionFailureSources.getOrDefault(fk, Set.of()); }
        void addFieldCompletionFailureSources(FieldKey fk, Set<Source> sources) {
            if (sources.isEmpty()) return;
            if (fieldCompletionFailureSources.computeIfAbsent(fk, k -> new TreeSet<>()).addAll(sources)) changed = true;
        }
        Set<TypeRef> fieldTypes(FieldKey fk) { return fieldTypes.getOrDefault(fk, Set.of()); }
        Set<LambdaTemplate> fieldLambdas(FieldKey fk) { return fieldLambdas.getOrDefault(fk, Set.of()); }

        void addFieldLambdas(FieldKey fk, Set<LambdaTemplate> lambdas) {
            if (lambdas.isEmpty()) return;
            if (fieldLambdas.computeIfAbsent(fk, k -> new TreeSet<>()).addAll(lambdas)) changed = true;
        }

        Set<Source> constantSources(Object value) {
            Set<Source> out = new TreeSet<>();
            for (FieldKey field : secureConstantFields.getOrDefault(value, Set.of())) out.add(Source.possibleField(field));
            return out;
        }

        void addReturnSources(MethodKey mk, Set<Source> direct, Set<Source> render, Set<Source> deepRender,
                              Set<Source> completionFailures, Set<TypeRef> types, Set<LambdaTemplate> lambdas) {
            MethodSummary s = summaries.computeIfAbsent(mk, k -> new MethodSummary());
            if (s.returnSources.addAll(direct)) changed = true;
            if (s.returnRenderSources.addAll(render)) changed = true;
            if (s.returnDeepRenderSources.addAll(deepRender)) changed = true;
            if (s.returnCompletionFailureSources.addAll(completionFailures)) changed = true;
            if (s.returnTypes.addAll(types)) changed = true;
            if (s.returnLambdas.addAll(lambdas)) changed = true;
        }

        void addSinkSources(MethodKey mk, SinkSummary sink) {
            if (summaries.computeIfAbsent(mk, k -> new MethodSummary()).sinks.add(sink)) changed = true;
        }

        void addStoreSources(MethodKey mk, StoreSummary store) {
            if (summaries.computeIfAbsent(mk, k -> new MethodSummary()).stores.add(store)) changed = true;
        }

        void addMutation(MethodKey mk, MutationSummary mutation) {
            if (summaries.computeIfAbsent(mk, k -> new MethodSummary()).mutations.add(mutation)) changed = true;
        }

        void addCallback(MethodKey mk, CallbackSummary callback) {
            if (summaries.computeIfAbsent(mk, k -> new MethodSummary()).callbacks.add(callback)) changed = true;
        }

        MethodSummary summary(MethodKey mk) { return summaries.getOrDefault(mk, MethodSummary.EMPTY); }

        Set<Source> renderingSources(Set<TypeRef> refs) {
            Set<Source> out = new TreeSet<>();
            for (TypeRef ref : refs) {
                if (ref.array) continue; // Object.toString on an array does not render elements.
                for (String runtimeType : dispatchTypes(ref)) {
                    MethodKey toString = resolveVirtual(runtimeType, "toString", "()Ljava/lang/String;");
                    if (toString == null) continue;
                    MethodSummary s = summary(toString);
                    for (Source source : s.returnSources) if (!isReceiverPlaceholder(source)) out.add(source);
                    for (Source source : s.returnRenderSources) if (!isReceiverPlaceholder(source)) out.add(source);
                }
            }
            return out;
        }

        Set<Source> exceptionTextSources(Set<TypeRef> refs) {
            Set<Source> out = new TreeSet<>();
            for (TypeRef ref : refs) {
                if (ref.array) continue;
                for (String runtimeType : dispatchTypes(ref)) {
                    for (String methodName : List.of("getLocalizedMessage", "getMessage", "toString")) {
                        MethodKey method = resolveVirtual(runtimeType, methodName, "()Ljava/lang/String;");
                        if (method == null) continue;
                        MethodSummary summary = summary(method);
                        for (Source source : summary.returnSources) if (!isReceiverPlaceholder(source)) out.add(source);
                        for (Source source : summary.returnRenderSources) if (!isReceiverPlaceholder(source)) out.add(source);
                    }
                }
            }
            return out;
        }

        Set<Source> serializedSources(Set<TypeRef> refs) {
            Set<Source> out = new TreeSet<>();
            Set<String> visited = new HashSet<>();
            for (TypeRef ref : refs) {
                if (ref.array) continue;
                for (String runtimeType : dispatchTypes(ref)) collectSerializedClassSources(runtimeType, visited, out);
            }
            return out;
        }

        void collectSerializedClassSources(String type, Set<String> visited, Set<Source> out) {
            if (type == null || !visited.add(type)) return;
            ClassNode classNode = classes.get(type);
            if (classNode == null) return;
            for (FieldNode field : classNode.fields) {
                if ((field.access & Opcodes.ACC_STATIC) != 0) continue;
                FieldKey key = new FieldKey(classNode.name, field.name, field.desc);
                out.addAll(fieldDirectSources(key));
                out.addAll(fieldRenderSources(key));
                out.addAll(fieldDeepRenderSources(key));
                for (TypeRef fieldType : fieldTypes(key)) {
                    if (fieldType.array) continue;
                    for (String runtimeType : dispatchTypes(fieldType)) collectSerializedClassSources(runtimeType, visited, out);
                }
            }
            collectSerializedClassSources(classNode.superName, visited, out);
        }

        boolean isReceiverPlaceholder(Source s) {
            return s.kind != SourceKind.FIELD && s.paramOrdinal == 0;
        }

        List<String> dispatchTypes(TypeRef ref) {
            if (ref.array) return List.of();
            if (ref.exact) return classes.containsKey(ref.name) ? List.of(ref.name) : List.of();
            ClassNode declared = classes.get(ref.name);
            if (declared == null) return List.of();
            List<String> out = new ArrayList<>();
            for (String candidate : classes.keySet()) if (isAssignableFrom(ref.name, candidate)) out.add(candidate);
            if (out.isEmpty()) out.add(ref.name);
            return out;
        }

        boolean shouldResolveParameterType(TypeRef ref) {
            if (ref == null || ref.array || ref.exact) return ref != null && ref.exact;
            ClassNode cn = classes.get(ref.name);
            if (cn == null || ref.name.equals("java/lang/Object")) return false;
            return (cn.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT)) == 0;
        }

        boolean isAssignableFrom(String parent, String child) {
            if (parent.equals(child) || parent.equals("java/lang/Object")) return true;
            Set<String> seen = new HashSet<>();
            Deque<String> q = new ArrayDeque<>();
            q.add(child);
            while (!q.isEmpty()) {
                String cur = q.removeFirst();
                if (!seen.add(cur)) continue;
                ClassNode cn = classes.get(cur);
                if (cn == null) continue;
                if (parent.equals(cn.superName)) return true;
                if (cn.superName != null) q.addLast(cn.superName);
                if (cn.interfaces != null) {
                    for (String i : cn.interfaces) {
                        if (parent.equals(i)) return true;
                        q.addLast(i);
                    }
                }
            }
            return false;
        }

        MethodKey resolveVirtual(String runtimeType, String name, String desc) {
            String cur = runtimeType;
            Set<String> seen = new HashSet<>();
            while (cur != null && seen.add(cur)) {
                ClassNode cn = classes.get(cur);
                if (cn == null) return null;
                for (MethodNode mn : cn.methods) if (mn.name.equals(name) && mn.desc.equals(desc)) return new MethodKey(cn.name, name, desc);
                MethodKey viaInterface = resolveInterfaceMethod(cn.interfaces, name, desc, new HashSet<>());
                if (viaInterface != null) return viaInterface;
                cur = cn.superName;
            }
            return null;
        }

        MethodKey resolveInterfaceMethod(List<String> interfaces, String name, String desc, Set<String> seen) {
            if (interfaces == null) return null;
            for (String i : interfaces) {
                if (!seen.add(i)) continue;
                ClassNode cn = classes.get(i);
                if (cn == null) continue;
                for (MethodNode mn : cn.methods) if (mn.name.equals(name) && mn.desc.equals(desc)) return new MethodKey(cn.name, name, desc);
                MethodKey nested = resolveInterfaceMethod(cn.interfaces, name, desc, seen);
                if (nested != null) return nested;
            }
            return null;
        }

        void loadBaseline() {
            if (cfg.baselineFile == null) return;
            try {
                String text = Files.readString(cfg.baselineFile, StandardCharsets.UTF_8);
                java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("\\\"([0-9a-fA-F]{64})\\\"").matcher(text);
                while (matcher.find()) baselineFingerprints.add(matcher.group(1).toLowerCase(Locale.ROOT));
            } catch (IOException | RuntimeException ex) {
                addFinding(Finding.incomplete("Unable to read baseline " + cfg.baselineFile + ": " + ex.getMessage()));
            }
        }

        void writeBaselineIfRequested() {
            if (cfg.writeBaselineFile == null) return;
            try {
                Path absolute = cfg.writeBaselineFile.toAbsolutePath().normalize();
                Path parent = absolute.getParent();
                if (parent != null) Files.createDirectories(parent);
                Set<String> fingerprints = new TreeSet<>();
                for (Finding finding : findings) {
                    if (finding.severity.equals("ERROR") || finding.severity.equals("POSSIBLE")) {
                        if (finding.suppression == null) fingerprints.add(finding.fingerprint());
                    }
                }
                StringBuilder json = new StringBuilder();
                json.append("{\n  \"version\": 1,\n  \"fingerprints\": [\n");
                int index = 0;
                for (String fingerprint : fingerprints) {
                    if (index++ > 0) json.append(",\n");
                    json.append("    \"").append(fingerprint).append("\"");
                }
                json.append("\n  ]\n}\n");
                Files.writeString(absolute, json.toString(), StandardCharsets.UTF_8);
            } catch (IOException | RuntimeException ex) {
                addFinding(Finding.incomplete("Unable to write baseline " + cfg.writeBaselineFile + ": " + ex.getMessage()));
            }
        }

        boolean isBaselined(Finding finding) { return baselineFingerprints.contains(finding.fingerprint()); }
        boolean isSuppressed(Finding finding) { return finding.suppression != null; }
        String disposition(Finding finding) {
            if (finding.severity.equals("SANITIZED")) return "SANITIZED";
            if (finding.severity.equals("INCOMPLETE")) return "ACTIVE";
            if (isSuppressed(finding)) return "SUPPRESSED";
            if (isBaselined(finding)) return "BASELINED";
            return "NEW";
        }

        void printReport() throws IOException {
            if (cfg.sarifOutput != null) {
                Path parent = cfg.sarifOutput.toAbsolutePath().normalize().getParent();
                if (parent != null) Files.createDirectories(parent);
                Files.writeString(cfg.sarifOutput, buildSarif(), StandardCharsets.UTF_8);
            }
            if (cfg.sarif) printSarif();
            else if (cfg.json) printJson();
            else printText();
        }

        void printText() {
            List<Finding> reported = visibleFindings();
            System.out.println("SecureLogScan report");
            System.out.println("  release: " + cfg.release);
            System.out.println("  classes: " + classes.size());
            for (ArtifactRole role : ArtifactRole.values()) {
                long count = classOrigins.values().stream().filter(origin -> origin.artifact.role == role).count();
                System.out.println("    " + role + ": " + count);
            }
            System.out.println("  artifacts: " + artifacts.size());
            for (ArtifactInfo artifact : new TreeSet<>(artifacts.values())) {
                System.out.println("    artifact: " + artifact.displayName());
                System.out.println("      role: " + artifact.role);
                System.out.println("      path: " + artifact.path);
                if (!artifact.moduleName.isBlank()) System.out.println("      module: " + artifact.moduleName);
                if (!artifact.version.isBlank()) System.out.println("      version: " + artifact.version);
            }
            System.out.println("  duplicate classes: " + duplicateClasses.size() + " (policy="
                    + cfg.duplicateClassPolicy.name().toLowerCase(Locale.ROOT) + ")");
            for (DuplicateClass duplicate : duplicateClasses) {
                System.out.println("    duplicate: " + duplicate.className.replace('/', '.'));
                System.out.println("      selected: " + duplicate.selected.source);
                System.out.println("      also present: " + duplicate.duplicate.source);
                System.out.println("      bytecode: " + (duplicate.identical ? "identical" : "conflicting"));
            }
            System.out.println("  dependency findings: " + cfg.dependencyFindingsPolicy.name().toLowerCase(Locale.ROOT));
            System.out.println("  worklist method analyses: " + analyzedWorkItems);
            System.out.println("  @Secure sources: " + annotatedSecureFields.size());
            System.out.println("    effective secure annotations: " + effectiveSecureAnnotationDescs);
            for (FieldKey field : annotatedSecureFields) {
                System.out.println("    source: " + field.javaName());
                System.out.println("      artifact: " + artifactDisplay(field.owner));
            }
            System.out.println("  @Sanitize/configured sanitizer methods: " + sanitizers.size());
            for (SanitizerInfo sanitizer : new TreeSet<>(sanitizers.values())) {
                System.out.println("    sanitizer: " + sanitizer.method);
                if (!sanitizer.description.isBlank()) System.out.println("      description: " + sanitizer.description);
                if (!sanitizer.justification.isBlank()) System.out.println("      justification: " + sanitizer.justification);
            }
            System.out.println("  configured method models: " + methodModels.size());
            for (String description : methodModels.descriptions) System.out.println("    model: " + description);
            Set<FieldKey> derived = new TreeSet<>(taintedFields);
            derived.removeAll(annotatedSecureFields);
            System.out.println("  derived tracked fields: " + derived.size());
            for (FieldKey field : derived) System.out.println("    derived: " + field.javaName());
            long violations = reported.stream().filter(f -> f.severity.equals("ERROR")).count();
            long possible = reported.stream().filter(f -> f.severity.equals("POSSIBLE")).count();
            long sanitized = reported.stream().filter(f -> f.severity.equals("SANITIZED")).count();
            long incomplete = reported.stream().filter(f -> f.severity.equals("INCOMPLETE")).count();
            long suppressed = reported.stream().filter(this::isSuppressed).count();
            long baselined = reported.stream().filter(f -> !isSuppressed(f) && isBaselined(f)).count();
            long fresh = reported.stream().filter(f -> disposition(f).equals("NEW")).count();
            System.out.println("  baseline fingerprints loaded: " + baselineFingerprints.size());
            System.out.println("  suppressions: " + (methodSuppressions.size() + typeSuppressions.size()));
            System.out.println("  analysis: " + (findings.stream().noneMatch(f -> f.severity.equals("INCOMPLETE")) ? "COMPLETE" : "INCOMPLETE"));
            System.out.println("  findings: " + reported.size() + " (unsafe=" + violations
                    + ", possible=" + possible + ", sanitized=" + sanitized + ", incomplete=" + incomplete
                    + ", new=" + fresh + ", baselined=" + baselined + ", suppressed=" + suppressed + ")");
            for (Finding finding : reported) {
                System.out.println();
                System.out.println(finding.severity + " " + finding.location());
                System.out.println("  disposition: " + disposition(finding));
                System.out.println("  fingerprint: " + finding.fingerprint());
                System.out.println("  scope: " + findingScope(finding));
                System.out.println("  category: " + finding.category);
                System.out.println("  sink: " + finding.sink);
                if (finding.category != SinkCategory.ANALYSIS) {
                    System.out.println("  source location: " + finding.location.display());
                    if (finding.sinkArgument >= 0) System.out.println("  sink argument: " + finding.sinkArgument);
                    if (!finding.contextKey.isBlank()) System.out.println("  context key: " + finding.contextKey);
                    System.out.println("  location artifact: " + artifactDisplay(finding.owner));
                    System.out.println("  sink artifact: " + artifactDisplay(finding.sinkArtifactOwner));
                    if (!finding.path.isEmpty()) {
                        System.out.println("  call path:");
                        for (DiagnosticLocation step : finding.path) System.out.println("    - " + step.display());
                    }
                }
                if (finding.severity.equals("ERROR")) System.out.println("  state: UNSAFE");
                else if (finding.severity.equals("POSSIBLE")) System.out.println("  state: POSSIBLE");
                else if (finding.severity.equals("SANITIZED")) System.out.println("  state: SANITIZED");
                System.out.println("  flow: " + finding.flow);
                if (finding.suppression != null) {
                    System.out.println("  suppression:");
                    System.out.println("    reason: " + finding.suppression.reason);
                    if (!finding.suppression.ticket.isBlank()) System.out.println("    ticket: " + finding.suppression.ticket);
                    if (!finding.suppression.expires.isBlank()) System.out.println("    expires: " + finding.suppression.expires);
                    System.out.println("    declared at: " + finding.suppression.declaredAt);
                }
                if (!finding.fields.isEmpty()) {
                    System.out.println("  secure fields:");
                    for (FieldKey field : finding.fields) {
                        System.out.println("    - " + field.javaName());
                        System.out.println("      artifact: " + artifactDisplay(field.owner));
                    }
                }
                if (!finding.uncertainties.isEmpty()) {
                    System.out.println("  uncertainty reasons:");
                    for (UncertaintyReason reason : finding.uncertainties) System.out.println("    - " + reason);
                }
                for (SanitizerInfo sanitizer : finding.sanitizers) {
                    System.out.println("  sanitizer: " + sanitizer.method);
                    if (!sanitizer.description.isBlank()) System.out.println("    description: " + sanitizer.description);
                    if (!sanitizer.justification.isBlank()) System.out.println("    justification: " + sanitizer.justification);
                }
            }
        }

        void printJson() {
            List<Finding> reported = visibleFindings();
            StringBuilder sb = new StringBuilder(8192);
            sb.append("{\n");
            sb.append("  \"release\": ").append(cfg.release).append(",\n");
            sb.append("  \"classes\": ").append(classes.size()).append(",\n");
            sb.append("  \"classesByRole\": {");
            int roleIndex = 0;
            for (ArtifactRole role : ArtifactRole.values()) {
                if (roleIndex++ > 0) sb.append(", ");
                long count = classOrigins.values().stream().filter(origin -> origin.artifact.role == role).count();
                sb.append('"').append(role.name()).append("\": ").append(count);
            }
            sb.append("},\n");
            sb.append("  \"worklistMethodAnalyses\": ").append(analyzedWorkItems).append(",\n");
            sb.append("  \"analysisComplete\": ").append(findings.stream().noneMatch(f -> f.severity.equals("INCOMPLETE"))).append(",\n");
            prop(sb, "duplicateClassPolicy", cfg.duplicateClassPolicy.name(), 2, true);
            prop(sb, "dependencyFindingsPolicy", cfg.dependencyFindingsPolicy.name(), 2, true);
            sb.append("  \"baselineFingerprintsLoaded\": ").append(baselineFingerprints.size()).append(",\n");
            sb.append("  \"artifacts\": [");
            int artifactIndex = 0;
            for (ArtifactInfo artifact : new TreeSet<>(artifacts.values())) {
                if (artifactIndex++ > 0) sb.append(", ");
                sb.append("{\"name\":\"").append(json(artifact.displayName())).append("\",")
                        .append("\"path\":\"").append(json(artifact.path)).append("\",")
                        .append("\"role\":\"").append(artifact.role).append("\",")
                        .append("\"coordinate\":\"").append(json(artifact.coordinate)).append("\",")
                        .append("\"module\":\"").append(json(artifact.moduleName)).append("\",")
                        .append("\"version\":\"").append(json(artifact.version)).append("\"}");
            }
            sb.append("],\n");
            sb.append("  \"duplicateClasses\": [");
            int duplicateIndex = 0;
            for (DuplicateClass duplicate : duplicateClasses) {
                if (duplicateIndex++ > 0) sb.append(", ");
                sb.append("{\"class\":\"").append(json(duplicate.className.replace('/', '.'))).append("\",")
                        .append("\"selected\":\"").append(json(duplicate.selected.source)).append("\",")
                        .append("\"duplicate\":\"").append(json(duplicate.duplicate.source)).append("\",")
                        .append("\"identical\":").append(duplicate.identical).append('}');
            }
            sb.append("],\n");
            appendFieldArray(sb, "secureFields", annotatedSecureFields, 2).append(",\n");
            Set<FieldKey> derived = new TreeSet<>(taintedFields); derived.removeAll(annotatedSecureFields);
            appendFieldArray(sb, "derivedTrackedFields", derived, 2).append(",\n");
            sb.append("  \"sanitizers\": [");
            int sanitizerIndex = 0;
            for (SanitizerInfo sanitizer : new TreeSet<>(sanitizers.values())) {
                if (sanitizerIndex++ > 0) sb.append(", ");
                sb.append("{\"method\":\"").append(json(sanitizer.method.toString())).append("\",")
                        .append("\"description\":\"").append(json(sanitizer.description)).append("\",")
                        .append("\"justification\":\"").append(json(sanitizer.justification)).append("\"}");
            }
            sb.append("],\n");
            sb.append("  \"methodModels\": [");
            for (int modelIndex = 0; modelIndex < methodModels.descriptions.size(); modelIndex++) {
                if (modelIndex > 0) sb.append(", ");
                sb.append('"').append(json(methodModels.descriptions.get(modelIndex))).append('"');
            }
            sb.append("],\n");
            sb.append("  \"findings\": [\n");
            int i = 0;
            for (Finding finding : reported) {
                if (i++ > 0) sb.append(",\n");
                sb.append("    {\n");
                prop(sb, "severity", finding.severity, 6, true);
                prop(sb, "disposition", disposition(finding), 6, true);
                prop(sb, "fingerprint", finding.fingerprint(), 6, true);
                if (finding.severity.equals("ERROR")) prop(sb, "state", "UNSAFE", 6, true);
                else if (finding.severity.equals("POSSIBLE")) prop(sb, "state", "POSSIBLE", 6, true);
                else if (finding.severity.equals("SANITIZED")) prop(sb, "state", "SANITIZED", 6, true);
                prop(sb, "scope", findingScope(finding).name(), 6, true);
                prop(sb, "owner", finding.owner.replace('/', '.'), 6, true);
                prop(sb, "method", finding.method + finding.desc, 6, true);
                prop(sb, "category", finding.category.name(), 6, true);
                prop(sb, "sink", finding.sink, 6, true);
                prop(sb, "locationArtifact", artifactDisplay(finding.owner), 6, true);
                prop(sb, "sinkArtifact", artifactDisplay(finding.sinkArtifactOwner), 6, true);
                prop(sb, "flow", finding.flow, 6, true);
                prop(sb, "sourceFile", finding.location.sourceFile, 6, true);
                sb.append("      \"line\": ").append(finding.location.line).append(",\n");
                sb.append("      \"instructionIndex\": ").append(finding.location.instructionIndex).append(",\n");
                sb.append("      \"sinkArgument\": ").append(finding.sinkArgument).append(",\n");
                prop(sb, "contextKey", finding.contextKey, 6, true);
                sb.append("      \"suppression\": ");
                if (finding.suppression == null) sb.append("null,\n");
                else sb.append("{\"reason\":\"").append(json(finding.suppression.reason)).append("\",")
                        .append("\"ticket\":\"").append(json(finding.suppression.ticket)).append("\",")
                        .append("\"expires\":\"").append(json(finding.suppression.expires)).append("\",")
                        .append("\"declaredAt\":\"").append(json(finding.suppression.declaredAt)).append("\"},\n");
                sb.append("      \"callPath\": [");
                int pathIndex = 0;
                for (DiagnosticLocation step : finding.path) {
                    if (pathIndex++ > 0) sb.append(", ");
                    sb.append("{\"method\":\"").append(json(step.methodDisplay())).append("\",")
                            .append("\"sourceFile\":\"").append(json(step.sourceFile)).append("\",")
                            .append("\"line\":").append(step.line).append(',')
                            .append("\"instructionIndex\":").append(step.instructionIndex).append(',')
                            .append("\"artifact\":\"").append(json(step.artifact)).append("\"}");
                }
                sb.append("],\n");
                sb.append("      \"fields\": [");
                int j = 0;
                for (FieldKey field : finding.fields) {
                    if (j++ > 0) sb.append(", ");
                    sb.append("{\"field\":\"").append(json(field.javaName())).append("\",")
                            .append("\"artifact\":\"").append(json(artifactDisplay(field.owner))).append("\"}");
                }
                sb.append("],\n      \"uncertaintyReasons\": [");
                int uncertaintyIndex = 0;
                for (UncertaintyReason reason : finding.uncertainties) {
                    if (uncertaintyIndex++ > 0) sb.append(", ");
                    sb.append('"').append(reason.name()).append('"');
                }
                sb.append("],\n      \"sanitizers\": [");
                int sanitizerFindingIndex = 0;
                for (SanitizerInfo sanitizer : finding.sanitizers) {
                    if (sanitizerFindingIndex++ > 0) sb.append(", ");
                    sb.append("{\"method\":\"").append(json(sanitizer.method.toString())).append("\",")
                            .append("\"description\":\"").append(json(sanitizer.description)).append("\",")
                            .append("\"justification\":\"").append(json(sanitizer.justification)).append("\"}");
                }
                sb.append("]\n    }");
            }
            sb.append("\n  ]\n}\n");
            System.out.print(sb);
        }

        void printSarif() { System.out.print(buildSarif()); }

        String buildSarif() {
            List<Finding> reported = visibleFindings();
            StringBuilder sb = new StringBuilder(16384);
            sb.append("{\n");
            sb.append("  \"version\": \"2.1.0\",\n");
            sb.append("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
            sb.append("  \"runs\": [{\n");
            sb.append("    \"tool\": {\"driver\": {\"name\": \"SecureLogScan\", \"version\": \"12.0.0\", \"rules\": [\n");
            appendSarifRule(sb, "secure-log/unsafe", "Secure data reaches a log or diagnostic-context sink", "error", true);
            appendSarifRule(sb, "secure-log/possible", "Secure data may reach a log or diagnostic-context sink", "warning", true);
            appendSarifRule(sb, "secure-log/sanitized", "Sanitized secure data reaches an approved sink", "note", true);
            appendSarifRule(sb, "secure-log/incomplete", "Security analysis was incomplete", "error", false);
            sb.append("    ]}},\n");
            sb.append("    \"results\": [\n");
            int resultIndex = 0;
            for (Finding finding : reported) {
                if (resultIndex++ > 0) sb.append(",\n");
                String ruleId = sarifRuleId(finding);
                String level = finding.severity.equals("ERROR") || finding.severity.equals("INCOMPLETE") ? "error"
                        : finding.severity.equals("POSSIBLE") ? "warning" : "note";
                sb.append("      {\n");
                sb.append("        \"ruleId\": \"").append(ruleId).append("\",\n");
                sb.append("        \"level\": \"").append(level).append("\",\n");
                sb.append("        \"message\": {\"text\": \"").append(json(sarifMessage(finding))).append("\"},\n");
                sb.append("        \"locations\": [");
                appendSarifLocation(sb, finding.location, finding.location.methodDisplay());
                sb.append("],\n");
                sb.append("        \"relatedLocations\": [");
                int related = 0;
                for (FieldKey field : finding.fields) {
                    if (related++ > 0) sb.append(',');
                    ClassNode sourceClass = classes.get(field.owner);
                    DiagnosticLocation sourceLocation = new DiagnosticLocation(field.owner, "<field>", field.desc,
                            sourceClass == null ? "" : sourceClass.sourceFile, -1, -1, artifactDisplay(field.owner));
                    sb.append("{\"id\":").append(related).append(',');
                    sb.append("\"message\":{\"text\":\"Secure source ").append(json(field.javaName())).append("\"},");
                    sb.append("\"physicalLocation\":");
                    appendSarifPhysicalLocation(sb, sourceLocation);
                    sb.append('}');
                }
                sb.append("],\n");
                if (!finding.path.isEmpty()) {
                    sb.append("        \"codeFlows\": [{\"threadFlows\": [{\"locations\": [");
                    int pathIndex = 0;
                    for (DiagnosticLocation step : finding.path) {
                        if (pathIndex++ > 0) sb.append(',');
                        sb.append("{\"location\":");
                        appendSarifLocationObject(sb, step, step.methodDisplay());
                        sb.append('}');
                    }
                    sb.append("]}]}],\n");
                }
                if (finding.suppression != null) {
                    sb.append("        \"suppressions\": [{\"kind\":\"inSource\",\"status\":\"accepted\",")
                            .append("\"justification\":\"").append(json(finding.suppression.reason)).append("\"}],\n");
                }
                if (!isSuppressed(finding) && isBaselined(finding)) {
                    sb.append("        \"baselineState\": \"unchanged\",\n");
                }
                sb.append("        \"properties\": {");
                sb.append("\"state\":\"").append(json(sarifState(finding))).append("\",");
                sb.append("\"disposition\":\"").append(disposition(finding)).append("\",");
                sb.append("\"fingerprint\":\"").append(finding.fingerprint()).append("\",");
                sb.append("\"scope\":\"").append(findingScope(finding).name()).append("\",");
                sb.append("\"category\":\"").append(finding.category.name()).append("\",");
                sb.append("\"sink\":\"").append(json(finding.sink)).append("\",");
                sb.append("\"sinkArgument\":").append(finding.sinkArgument).append(',');
                sb.append("\"contextKey\":\"").append(json(finding.contextKey)).append("\",");
                sb.append("\"instructionIndex\":").append(finding.location.instructionIndex).append(',');
                sb.append("\"locationArtifact\":\"").append(json(artifactDisplay(finding.owner))).append("\",");
                sb.append("\"sinkArtifact\":\"").append(json(artifactDisplay(finding.sinkArtifactOwner))).append("\",");
                sb.append("\"uncertaintyReasons\":[");
                int uncertaintyIndex = 0;
                for (UncertaintyReason reason : finding.uncertainties) {
                    if (uncertaintyIndex++ > 0) sb.append(',');
                    sb.append('"').append(reason.name()).append('"');
                }
                sb.append("],\"sanitizers\":[");
                int sanitizerIndex = 0;
                for (SanitizerInfo sanitizer : finding.sanitizers) {
                    if (sanitizerIndex++ > 0) sb.append(',');
                    sb.append("{\"method\":\"").append(json(sanitizer.method.toString())).append("\",")
                            .append("\"description\":\"").append(json(sanitizer.description)).append("\",")
                            .append("\"justification\":\"").append(json(sanitizer.justification)).append("\"}");
                }
                sb.append("]}\n");
                sb.append("      }");
            }
            sb.append("\n    ]\n");
            sb.append("  }]\n");
            sb.append("}\n");
            return sb.toString();
        }

        void appendSarifRule(StringBuilder sb, String id, String description, String level, boolean comma) {
            sb.append("      {\"id\":\"").append(id).append("\",\"shortDescription\":{\"text\":\"")
                    .append(json(description)).append("\"},\"defaultConfiguration\":{\"level\":\"")
                    .append(level).append("\"}}");
            if (comma) sb.append(',');
            sb.append('\n');
        }

        String sarifRuleId(Finding finding) {
            if (finding.severity.equals("ERROR")) return "secure-log/unsafe";
            if (finding.severity.equals("POSSIBLE")) return "secure-log/possible";
            if (finding.severity.equals("SANITIZED")) return "secure-log/sanitized";
            return "secure-log/incomplete";
        }

        String sarifState(Finding finding) {
            if (finding.severity.equals("ERROR")) return "UNSAFE";
            if (finding.severity.equals("POSSIBLE")) return "POSSIBLE";
            if (finding.severity.equals("SANITIZED")) return "SANITIZED";
            return "INCOMPLETE";
        }

        String sarifMessage(Finding finding) {
            StringBuilder message = new StringBuilder();
            message.append(sarifState(finding)).append(' ').append(finding.category).append(": ").append(finding.flow);
            if (!finding.fields.isEmpty()) message.append("; source=").append(finding.fields);
            if (finding.sinkArgument >= 0) message.append("; argument=").append(finding.sinkArgument);
            if (!finding.contextKey.isBlank()) message.append("; contextKey=").append(finding.contextKey);
            return message.toString();
        }

        void appendSarifLocation(StringBuilder sb, DiagnosticLocation location, String message) {
            appendSarifLocationObject(sb, location, message);
        }

        void appendSarifLocationObject(StringBuilder sb, DiagnosticLocation location, String message) {
            sb.append('{');
            sb.append("\"physicalLocation\":");
            appendSarifPhysicalLocation(sb, location);
            sb.append(",\"logicalLocations\":[{\"fullyQualifiedName\":\"")
                    .append(json(location.methodDisplay())).append("\"}]");
            if (message != null && !message.isBlank()) {
                sb.append(",\"message\":{\"text\":\"").append(json(message)).append("\"}");
            }
            sb.append('}');
        }

        void appendSarifPhysicalLocation(StringBuilder sb, DiagnosticLocation location) {
            String uri = !location.sourceFile.isBlank() ? location.sourceFile : location.owner.replace('/', '.') + ".class";
            sb.append("{\"artifactLocation\":{\"uri\":\"").append(json(uri)).append("\"}");
            if (location.line > 0) sb.append(",\"region\":{\"startLine\":").append(location.line).append('}');
            sb.append('}');
        }

        StringBuilder appendFieldArray(StringBuilder sb, String name, Set<FieldKey> fields, int indent) {
            String sp = " ".repeat(indent);
            sb.append(sp).append('"').append(name).append("\": [");
            int i = 0;
            for (FieldKey f : fields) {
                if (i++ > 0) sb.append(", ");
                sb.append('"').append(json(f.javaName())).append('"');
            }
            sb.append(']');
            return sb;
        }

        void prop(StringBuilder sb, String key, String val, int indent, boolean comma) {
            sb.append(" ".repeat(indent)).append('"').append(key).append("\": \"").append(json(val)).append('"');
            if (comma) sb.append(',');
            sb.append('\n');
        }

        String json(String s) { return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r"); }
    }

    static final class TaintInterpreter extends Interpreter<TaintValue> implements Opcodes {
        final ScanModel model;
        final ClassNode cn;
        final MethodNode mn;
        final MethodKey method;
        final Map<Integer, Integer> localToParamOrdinal;
        final Map<Integer, Set<Source>> arrayDirect = new HashMap<>();
        final Map<Integer, Set<Source>> arrayRender = new HashMap<>();
        final Map<Integer, Set<TypeRef>> arrayTypes = new HashMap<>();
        final Map<Integer, Set<Integer>> arrayNestedIds = new HashMap<>();
        final Map<Integer, Set<LambdaTemplate>> arrayLambdas = new HashMap<>();
        final Map<Integer, Set<Source>> objectContents = new HashMap<>();
        final Map<Integer, Set<LambdaTemplate>> objectLambdas = new HashMap<>();
        final Map<Integer, TaintValue> exceptionMessages = new HashMap<>();
        final Map<Integer, TaintValue> exceptionCauses = new HashMap<>();
        final Map<Integer, List<TaintValue>> exceptionSuppressed = new HashMap<>();
        final IdentityHashMap<AbstractInsnNode, Integer> allocationIds = new IdentityHashMap<>();
        int nextAllocationId = 1;

        TaintInterpreter(ScanModel model, ClassNode cn, MethodNode mn, MethodKey method) {
            super(ASM);
            this.model = model;
            this.cn = cn;
            this.mn = mn;
            this.method = method;
            this.localToParamOrdinal = localToParamOrdinal((mn.access & ACC_STATIC) == 0, mn.desc);
        }

        DiagnosticLocation diagnosticLocation(AbstractInsnNode target) {
            int line = -1;
            int instructionIndex = -1;
            int currentIndex = 0;
            if (target != null) {
                for (AbstractInsnNode node = mn.instructions.getFirst(); node != null; node = node.getNext()) {
                    if (node instanceof LineNumberNode lineNode) line = lineNode.line;
                    if (node.getOpcode() >= 0) {
                        if (node == target) { instructionIndex = currentIndex; break; }
                        currentIndex++;
                    } else if (node == target) break;
                }
            }
            return new DiagnosticLocation(cn.name, mn.name, mn.desc, cn.sourceFile, line,
                    instructionIndex, model.artifactDisplay(cn.name));
        }

        List<DiagnosticLocation> prependPath(DiagnosticLocation location, List<DiagnosticLocation> path) {
            List<DiagnosticLocation> out = new ArrayList<>();
            boolean alreadyPresent = false;
            if (location != null) {
                for (DiagnosticLocation step : path) {
                    if (step.owner.equals(location.owner) && step.method.equals(location.method) && step.desc.equals(location.desc)) {
                        alreadyPresent = true;
                        break;
                    }
                }
                if (!alreadyPresent) out.add(location);
            }
            for (DiagnosticLocation step : path) {
                if (out.size() >= 64) break;
                if (out.isEmpty() || !out.get(out.size() - 1).equals(step)) out.add(step);
            }
            return List.copyOf(out);
        }

        String diagnosticContextKey(MethodInsnNode call, List<? extends TaintValue> args) {
            if (sinkCategory(call) != SinkCategory.CONTEXT_CAPTURE) return "";
            if (!args.isEmpty() && args.get(0).stringConstants.size() == 1) return args.get(0).stringConstants.iterator().next();
            if (call.name.equals("setContextMap") || call.name.equals("putAll") || call.name.equals("putAllValues")) return "<map>";
            if (call.name.toLowerCase(Locale.ROOT).contains("push") || call.owner.endsWith("/NDC")) return "<stack>";
            return "";
        }

        int selectorArgument(ModelValueSelector selector) {
            return selector.kind == ModelSelectorKind.ARG ? selector.argumentIndex : -1;
        }

        @Override public TaintValue newValue(Type type) {
            if (type == null) return TaintValue.oneSlot();
            if (type == Type.VOID_TYPE) return null;
            TypeRef tr = TypeRef.declared(type);
            TaintValue value = tr == null ? TaintValue.empty(type.getSize()) : TaintValue.empty(type.getSize()).withType(tr);
            for (Source source : model.secureTypeSources(type)) value = value.withDirect(source);
            return value;
        }

        @Override public TaintValue newParameterValue(boolean isInstanceMethod, int local, Type type) {
            TaintValue base = newValue(type);
            Integer ord = localToParamOrdinal.get(local);
            if (base == null || ord == null) return base;
            base = base.withDirect(Source.param(ord));
            FieldKey policySource = model.secureParameterSource(method, ord);
            return policySource == null ? base : base.withDirect(Source.field(policySource));
        }

        @Override public TaintValue newOperation(AbstractInsnNode insn) {
            int op = insn.getOpcode();
            switch (op) {
                case ACONST_NULL: return TaintValue.oneSlot();
                case ICONST_M1: case ICONST_0: case ICONST_1: case ICONST_2: case ICONST_3:
                case ICONST_4: case ICONST_5: case LCONST_0: case LCONST_1: case FCONST_0: case FCONST_1:
                case FCONST_2: case DCONST_0: case DCONST_1: case BIPUSH: case SIPUSH: {
                    TaintValue value = TaintValue.empty(sizeOfConstant(insn));
                    Object constant = opcodeConstant(insn);
                    for (Source source : model.constantSources(constant)) value = value.withDirect(source);
                    return value;
                }
                case LDC: {
                    Object c = ((LdcInsnNode) insn).cst;
                    TaintValue v = TaintValue.empty(sizeOfConstant(insn));
                    for (Source source : model.constantSources(c)) v = v.withDirect(source);
                    if (c instanceof String text) v = v.withType(TypeRef.exact("java/lang/String")).withStringConstant(text);
                    else if (c instanceof Type) v = v.withType(TypeRef.exact("java/lang/Class"));
                    return v;
                }
                case GETSTATIC: return fieldValue((FieldInsnNode) insn);
                case NEW: {
                    String type = ((TypeInsnNode) insn).desc;
                    TaintValue value = TaintValue.empty(1).withType(TypeRef.exact(type)).withObjectId(idFor(insn));
                    for (Source source : model.secureTypeSources(Type.getObjectType(type))) value = value.withDirect(source);
                    return value;
                }
                default: return TaintValue.oneSlot();
            }
        }

        @Override public TaintValue copyOperation(AbstractInsnNode insn, TaintValue value) { return value; }

        @Override public TaintValue unaryOperation(AbstractInsnNode insn, TaintValue value) {
            int op = insn.getOpcode();
            switch (op) {
                case INEG: case IINC: case L2I: case F2I: case D2I: case I2B: case I2C: case I2S:
                case LNEG: case I2L: case F2L: case D2L: case FNEG: case I2F: case L2F: case D2F:
                case DNEG: case I2D: case L2D: case F2D: case INSTANCEOF:
                    return value;
                case CHECKCAST: {
                    String type = ((TypeInsnNode) insn).desc;
                    TaintValue cast = value.withType(TypeRef.declaredObject(type));
                    for (Source source : model.secureTypeSources(Type.getObjectType(type))) cast = cast.withDirect(source);
                    return cast;
                }
                case GETFIELD: return fieldValue((FieldInsnNode) insn);
                case PUTSTATIC: {
                    FieldInsnNode f = (FieldInsnNode) insn;
                    noteFieldStore(new FieldKey(f.owner, f.name, f.desc), value);
                    return null;
                }
                case NEWARRAY: {
                    TypeRef tr = TypeRef.exactArray(primitiveArrayDescriptor(((IntInsnNode) insn).operand));
                    int id = idFor(insn);
                    return TaintValue.empty(1).withType(tr).withArrayId(id).withObjectId(id);
                }
                case ANEWARRAY: {
                    TypeInsnNode t = (TypeInsnNode) insn;
                    String desc = t.desc.startsWith("[") ? "[" + t.desc : "[L" + t.desc + ";";
                    int id = idFor(insn);
                    return TaintValue.empty(1).withType(TypeRef.exactArray(desc)).withArrayId(id).withObjectId(id);
                }
                case ARRAYLENGTH: return TaintValue.empty(1);
                case ATHROW: case MONITORENTER: case MONITOREXIT: case IFEQ: case IFNE: case IFLT:
                case IFGE: case IFGT: case IFLE: case TABLESWITCH: case LOOKUPSWITCH: case IRETURN:
                case LRETURN: case FRETURN: case DRETURN: case ARETURN: case RETURN:
                    return null;
                default: return value;
            }
        }

        @Override public TaintValue binaryOperation(AbstractInsnNode insn, TaintValue v1, TaintValue v2) {
            int op = insn.getOpcode();
            switch (op) {
                case IALOAD: case LALOAD: case FALOAD: case DALOAD: case BALOAD: case CALOAD: case SALOAD:
                    return arrayElement(v1, primitiveLoadSize(op));
                case AALOAD: return arrayElement(v1, 1);
                case IADD: case LADD: case FADD: case DADD: case ISUB: case LSUB: case FSUB: case DSUB:
                case IMUL: case LMUL: case FMUL: case DMUL: case IDIV: case LDIV: case FDIV: case DDIV:
                case IREM: case LREM: case FREM: case DREM: case ISHL: case LSHL: case ISHR: case LSHR:
                case IUSHR: case LUSHR: case IAND: case LAND: case IOR: case LOR: case IXOR: case LXOR:
                case LCMP: case FCMPL: case FCMPG: case DCMPL: case DCMPG:
                    return v1.merge(v2);
                case PUTFIELD: {
                    FieldInsnNode f = (FieldInsnNode) insn;
                    noteFieldStore(new FieldKey(f.owner, f.name, f.desc), v2);
                    return null;
                }
                case IF_ICMPEQ: case IF_ICMPNE: case IF_ICMPLT: case IF_ICMPGE: case IF_ICMPGT: case IF_ICMPLE:
                case IF_ACMPEQ: case IF_ACMPNE:
                    return null;
                default: return v1.merge(v2);
            }
        }

        @Override public TaintValue ternaryOperation(AbstractInsnNode insn, TaintValue array, TaintValue index, TaintValue value) {
            int op = insn.getOpcode();
            if (op == IASTORE || op == LASTORE || op == FASTORE || op == DASTORE || op == AASTORE
                    || op == BASTORE || op == CASTORE || op == SASTORE) {
                for (Integer id : array.arrayIds) {
                    arrayDirect.computeIfAbsent(id, k -> new TreeSet<>()).addAll(directSources(value));
                    arrayRender.computeIfAbsent(id, k -> new TreeSet<>()).addAll(renderSources(value));
                    arrayTypes.computeIfAbsent(id, k -> new TreeSet<>()).addAll(value.types);
                    arrayNestedIds.computeIfAbsent(id, k -> new TreeSet<>()).addAll(value.arrayIds);
                    arrayLambdas.computeIfAbsent(id, k -> new TreeSet<>()).addAll(lambdaTemplates(value));
                }
                Set<Source> rendered = renderSources(value);
                for (FieldKey origin : array.origins) model.addFieldRenderSources(origin, rendered);
            }
            return null;
        }

        @Override public TaintValue naryOperation(AbstractInsnNode insn, List<? extends TaintValue> values) {
            if (insn.getOpcode() == MULTIANEWARRAY) {
                MultiANewArrayInsnNode a = (MultiANewArrayInsnNode) insn;
                int id = idFor(insn);
                return TaintValue.empty(1).withType(TypeRef.exactArray(a.desc)).withArrayId(id).withObjectId(id);
            }
            if (insn.getOpcode() == INVOKEDYNAMIC) return invokedynamic((InvokeDynamicInsnNode) insn, values);
            if (!(insn instanceof MethodInsnNode m)) return TaintValue.oneSlot();

            MethodKey called = new MethodKey(m.owner, m.name, m.desc);
            List<? extends TaintValue> args = methodArguments(m, values);
            TaintValue receiver = m.getOpcode() == INVOKESTATIC ? null : values.get(0);
            TaintValue callbackResult = null;
            if (receiver != null && isFunctionalInvocation(m)) {
                callbackResult = applyLambdaTemplates(receiver, m.name, m.desc, args);
                recordFunctionalCallback(receiver, m, args);
            }
            TaintValue higherOrderResult = applyKnownHigherOrderCallback(m, receiver, args);
            if (higherOrderResult != null) callbackResult = mergeCallbackResult(callbackResult, higherOrderResult);
            TaintValue asyncResult = applyKnownAsyncCallback(m, receiver, args);
            if (asyncResult != null) callbackResult = mergeCallbackResult(callbackResult, asyncResult);
            for (CallbackMethodModel callbackModel : model.methodModels.callbacks(called)) {
                TaintValue modeledResult = applyConfiguredCallback(callbackModel, m, receiver, args);
                if (modeledResult != null) callbackResult = mergeCallbackResult(callbackResult, modeledResult);
            }

            DiagnosticLocation callLocation = diagnosticLocation(m);
            String contextKey = diagnosticContextKey(m, args);
            List<SinkMethodModel> configuredSinks = model.methodModels.sinks(called);
            if (!configuredSinks.isEmpty()) {
                for (SinkMethodModel sinkModel : configuredSinks) {
                    String flow = sinkModel.category == SinkCategory.CONTEXT_CAPTURE
                            ? "value captured by configured diagnostic-context sink"
                            : "value rendered by configured output sink";
                    for (ModelValueSelector selector : sinkModel.values) {
                        TaintValue selected = selectedValue(selector, m, receiver, args, sinkModel.source);
                        Set<Source> sinkSources;
                        if (sinkModel.mode == ModelValueMode.DIRECT) sinkSources = directSources(selected);
                        else if (sinkModel.mode == ModelValueMode.RENDER) sinkSources = renderSources(selected);
                        else {
                            sinkSources = new TreeSet<>(deepRenderSources(selected));
                            sinkSources.addAll(model.serializedSources(selected.types));
                        }
                        reportOrSummarizeSink(sinkModel.category, m.owner, m.name + m.desc, flow, sinkSources,
                                cn.name, callLocation, selectorArgument(selector), contextKey, List.of(callLocation));
                    }
                }
            } else {
                SinkCategory directSinkCategory = sinkCategory(m);
                if (directSinkCategory != null) {
                    String flow = directSinkCategory == SinkCategory.CONTEXT_CAPTURE
                            ? "value captured in diagnostic context"
                            : "value rendered by log/print sink";
                    if (directSinkCategory == SinkCategory.LOG_OUTPUT && m.name.equals("printStackTrace") && receiver != null) {
                        Set<Source> exceptionSources = exceptionGraphSources(receiver);
                        reportOrSummarizeSink(directSinkCategory, m.owner, m.name + m.desc, flow,
                                exceptionSources, cn.name, callLocation, -1, contextKey, List.of(callLocation));
                    }
                    boolean deepArrays = sinkDeepRendersArrays(m);
                    for (int i = 0; i < args.size(); i++) {
                        TaintValue arg = args.get(i);
                        Set<Source> sinkSources = directSinkCategory == SinkCategory.CONTEXT_CAPTURE
                                ? new TreeSet<>(deepRenderSources(arg))
                                : new TreeSet<>(deepArrays ? deepRenderSources(arg) : renderSources(arg));
                        if (directSinkCategory == SinkCategory.LOG_OUTPUT && isSupplierArgument(m, i) && !arg.lambdas.isEmpty()) {
                            sinkSources.addAll(supplierResultSources(arg));
                        }
                        reportOrSummarizeSink(directSinkCategory, m.owner, m.name + m.desc, flow, sinkSources,
                                cn.name, callLocation, i, contextKey, List.of(callLocation));
                    }
                    if (directSinkCategory == SinkCategory.LOG_OUTPUT && sinkRendersReceiverContents(m) && receiver != null) {
                        reportOrSummarizeSink(directSinkCategory, m.owner, m.name + m.desc, flow,
                                renderSources(receiver), cn.name, callLocation, -1, contextKey, List.of(callLocation));
                    }
                }
            }

            CalleeResolution resolution = resolveCallee(m, receiver);
            if (!resolution.known && shouldReportCallbackEscape(m, called)) {
                reportEscapingCallbacks(m, args);
            }
            MethodSummary callee = resolution.summary;
            for (SinkSummary sink : callee.sinks) {
                Set<Source> mapped = mapCalleeSourcesToCaller(sink.sources, values);
                String calleeFlow = sink.category == SinkCategory.CONTEXT_CAPTURE
                        ? "callee captures value in diagnostic context: " + sink.sink
                        : "callee logs value: " + sink.sink;
                List<DiagnosticLocation> calleePath = prependPath(callLocation, sink.path);
                reportOrSummarizeSink(sink.category, called.owner, called.name + called.desc, calleeFlow, mapped,
                        sink.sinkArtifactOwner, callLocation, sink.sinkArgument, sink.contextKey, calleePath,
                        sink.suppression);
            }
            for (StoreSummary store : callee.stores) {
                Set<Source> direct = mapCalleeSourcesToCaller(store.directSources, values);
                Set<Source> render = mapCalleeSourcesToCaller(store.renderSources, values);
                Set<Source> deepRender = mapCalleeSourcesToCaller(store.deepRenderSources, values);
                Set<Source> failures = mapCalleeSourcesToCaller(store.completionFailureSources, values);
                Set<LambdaTemplate> lambdas = mapLambdaTemplatesToCaller(store.lambdas, values);
                noteFieldStore(store.target, TaintValue.ofWithCompletionFailures(1, direct, render, deepRender,
                        failures, store.types, Set.of(), Set.of(), Set.of(), lambdas));
            }
            for (MutationSummary mutation : callee.mutations) {
                if (mutation.targetParamOrdinal < values.size()) {
                    Set<Source> mapped = mapCalleeSourcesToCaller(mutation.contents, values);
                    addContentToValue(values.get(mutation.targetParamOrdinal), mapped);
                }
            }
            for (CallbackSummary callback : callee.callbacks) {
                TaintValue result = processCallback(callback, values);
                if (result != null) callbackResult = mergeCallbackResult(callbackResult, result);
            }

            for (MutationMethodModel mutationModel : model.methodModels.mutations(called)) {
                TaintValue target = selectedValue(mutationModel.target, m, receiver, args, mutationModel.source);
                Set<Source> content = selectedSources(mutationModel.values, mutationModel.mode, m, receiver, args, mutationModel.source);
                addContentToValue(target, content);
            }
            if (receiver != null && isContentMutation(m)) {
                Set<Source> content = new TreeSet<>();
                Set<LambdaTemplate> callbackContents = new TreeSet<>();
                for (int i = 0; i < args.size(); i++) {
                    TaintValue arg = args.get(i);
                    if (isSupplierArgument(m, i)) {
                        content.addAll(supplierResultSources(arg));
                    } else {
                        content.addAll(renderSources(arg));
                    }
                    callbackContents.addAll(lambdaTemplates(arg));
                }
                addContentToValue(receiver, content);
                addLambdasToValue(receiver, callbackContents);
            }
            if (receiver != null && m.name.equals("<init>") && shouldCaptureConstructorArgs(m, called)) {
                Set<Source> content = new TreeSet<>();
                for (TaintValue arg : args) content.addAll(renderSources(arg));
                addContentToValue(receiver, content);
                if (isThrowableValue(receiver, m.owner)) noteExceptionConstructor(receiver, args, m.desc);
            }
            if (receiver != null && isThrowableValue(receiver, m.owner) && m.name.equals("addSuppressed") && !args.isEmpty()) {
                noteExceptionSuppressed(receiver, args.get(0));
            }
            if (receiver != null && isThrowableValue(receiver, m.owner) && m.name.equals("initCause") && !args.isEmpty()) {
                noteExceptionCause(receiver, args.get(0));
            }

            Type rt = Type.getReturnType(m.desc);
            if (rt == Type.VOID_TYPE) return null;

            Set<Source> direct = new TreeSet<>(mapCalleeSourcesToCaller(callee.returnSources, values));
            direct.addAll(model.secureTypeSources(rt));
            Set<Source> render = new TreeSet<>(mapCalleeSourcesToCaller(callee.returnRenderSources, values));
            Set<Source> deepRender = new TreeSet<>(mapCalleeSourcesToCaller(callee.returnDeepRenderSources, values));
            Set<Source> completionFailures = new TreeSet<>(mapCalleeSourcesToCaller(callee.returnCompletionFailureSources, values));
            Set<TypeRef> types = new TreeSet<>();
            Set<Integer> propagatedExceptionIds = new TreeSet<>();
            TypeRef declared = TypeRef.declared(rt);
            if (declared != null) types.add(declared);
            types.addAll(callee.returnTypes);

            if (receiver != null && isThrowableValue(receiver, m.owner)) {
                if (m.name.equals("getMessage") || m.name.equals("getLocalizedMessage") || m.name.equals("toString")) {
                    TaintValue text = exceptionTextValue(receiver);
                    direct.addAll(directSources(text));
                    direct.addAll(renderSources(text));
                    propagatedExceptionIds.addAll(receiver.objectIds);
                } else if (m.name.equals("getCause")) {
                    TaintValue cause = exceptionCauseValue(receiver);
                    if (cause != null) {
                        direct.addAll(directSources(cause));
                        render.addAll(renderSources(cause));
                        deepRender.addAll(deepRenderSources(cause));
                        types.addAll(cause.types);
                        propagatedExceptionIds.addAll(cause.objectIds);
                    }
                } else if (m.name.equals("getSuppressed")) {
                    return exceptionSuppressedArray(receiver, idFor(insn));
                }
            }

            RendererMethodModel rendererModel = model.methodModels.renderer(called);
            if (rendererModel != null) {
                direct.addAll(selectedSources(rendererModel.values, rendererModel.mode, m, receiver, args, rendererModel.source));
            } else if (isStringRenderingCall(m)) {
                boolean deepArrays = stringCallDeepRendersArrays(m);
                for (TaintValue arg : args) direct.addAll(deepArrays ? deepRenderSources(arg) : renderSources(arg));
                if (receiver != null && isReceiverRendered(m)) direct.addAll(renderSources(receiver));
            } else if (isContainerFactory(m)) {
                for (TaintValue arg : args) render.addAll(deepRenderSources(arg));
            } else if (model.cfg.conservativeUnknownCalls && !resolution.known
                    && !isKnownAsyncBoundary(m)
                    && !isKnownThrowableAccessor(m, receiver)
                    && model.methodModels.callbacks(called).isEmpty()
                    && (receiver == null || receiver.lambdas.isEmpty())) {
                boolean definitelyValuePreserving = isKnownValuePreservingCall(m);
                UncertaintyReason unknownReason = model.unknownCallReason(m, receiver);
                for (TaintValue arg : args) {
                    Set<Source> sources = directSources(arg);
                    direct.addAll(definitelyValuePreserving ? sources : possibleSources(sources, unknownReason));
                }
                if (receiver != null) {
                    Set<Source> sources = directSources(receiver);
                    direct.addAll(definitelyValuePreserving ? sources : possibleSources(sources, unknownReason));
                }
                if (receiver != null && (m.name.equals("toString") || m.name.equals("getMessage") || m.name.equals("getLocalizedMessage")))
                    direct.addAll(possibleSources(renderSources(receiver), unknownReason));
                if (rt.getSort() == Type.OBJECT && rt.getInternalName().equals("java/lang/String")) {
                    for (TaintValue arg : args) direct.addAll(possibleSources(renderSources(arg), unknownReason));
                }
            }

            if (resolution.sanitizer != null) {
                Set<Source> tracked = new TreeSet<>();
                tracked.addAll(direct);
                tracked.addAll(render);
                tracked.addAll(deepRender);
                for (TaintValue arg : args) tracked.addAll(deepRenderSources(arg));
                if (receiver != null) tracked.addAll(deepRenderSources(receiver));
                direct = sanitizeSources(tracked, resolution.sanitizer);
                render = new TreeSet<>();
                deepRender = new TreeSet<>();
            }

            int callId = rt.getSort() == Type.OBJECT || rt.getSort() == Type.ARRAY ? idFor(insn) : 0;
            Set<Integer> resultObjectIds = new TreeSet<>(propagatedExceptionIds);
            if (callId != 0) resultObjectIds.add(callId);
            Set<LambdaTemplate> lambdas = mapLambdaTemplatesToCaller(callee.returnLambdas, values);
            if (isContainerFactory(m)) {
                for (TaintValue arg : args) lambdas.addAll(lambdaTemplates(arg));
            }
            TaintValue result = TaintValue.ofWithCompletionFailures(rt.getSize(), direct, render, deepRender,
                    completionFailures, types, resultObjectIds, Set.of(), Set.of(), lambdas);
            if (isFluentReturn(m) && receiver != null && !isCompletionStageOwner(m.owner)) result = result.merge(receiver);
            if (callbackResult != null) result = result.merge(callbackResult);
            if (isContainerFactory(m) && callId != 0) {
                objectContents.computeIfAbsent(callId, k -> new TreeSet<>()).addAll(render);
                objectLambdas.computeIfAbsent(callId, k -> new TreeSet<>()).addAll(lambdas);
            }
            return result;
        }

        TaintValue invokedynamic(InvokeDynamicInsnNode indy, List<? extends TaintValue> values) {
            Type rt = Type.getReturnType(indy.desc);
            Set<Source> direct = new TreeSet<>();
            Set<Source> render = new TreeSet<>();
            Set<Source> deepRender = new TreeSet<>();
            Set<TypeRef> types = new TreeSet<>();
            Set<LambdaTemplate> lambdas = new TreeSet<>();
            TypeRef declared = TypeRef.declared(rt);
            if (declared != null) types.add(declared);

            String bsmOwner = indy.bsm == null ? "" : indy.bsm.getOwner();
            if (bsmOwner.equals("java/lang/invoke/StringConcatFactory")) {
                for (TaintValue v : values) direct.addAll(renderSources(v));
            } else if (bsmOwner.equals("java/lang/runtime/ObjectMethods") && indy.name.equals("toString")) {
                direct.addAll(recordObjectMethodSources(indy));
            } else if (bsmOwner.equals("java/lang/invoke/LambdaMetafactory") || bsmOwner.equals("java/lang/invoke/InnerClassLambdaMetafactory")) {
                Handle impl = lambdaImplementationHandle(indy);
                if (impl != null) {
                    List<ValueTemplate> captures = new ArrayList<>();
                    for (TaintValue value : values) captures.add(valueTemplate(value));
                    lambdas.add(new LambdaTemplate(impl.getTag(), new MethodKey(impl.getOwner(), impl.getName(), impl.getDesc()), captures));
                }
            } else if (model.cfg.conservativeUnknownCalls) {
                for (TaintValue v : values) direct.addAll(possibleSources(directSources(v), UncertaintyReason.UNKNOWN_INVOKEDYNAMIC));
            }

            int id = rt.getSort() == Type.OBJECT || rt.getSort() == Type.ARRAY ? idFor(indy) : 0;
            return TaintValue.of(rt.getSize(), direct, render, deepRender, types,
                    id == 0 ? Set.of() : Set.of(id), Set.of(), Set.of(), lambdas);
        }

        Set<Source> recordObjectMethodSources(InvokeDynamicInsnNode indy) {
            Set<Source> out = new TreeSet<>();
            for (Object arg : indy.bsmArgs) {
                if (!(arg instanceof Handle h)) continue;
                if (h.getTag() != H_GETFIELD && h.getTag() != H_GETSTATIC) continue;
                FieldKey fk = new FieldKey(h.getOwner(), h.getName(), h.getDesc());
                out.addAll(model.fieldDirectSources(fk));
                out.addAll(model.fieldRenderSources(fk));
                out.addAll(model.renderingSources(model.fieldTypes(fk)));
            }
            return out;
        }

        Handle lambdaImplementationHandle(InvokeDynamicInsnNode indy) {
            for (Object arg : indy.bsmArgs) if (arg instanceof Handle h && h.getTag() >= H_INVOKEVIRTUAL && h.getTag() <= H_INVOKEINTERFACE) return h;
            return null;
        }

        @Override public void returnOperation(AbstractInsnNode insn, TaintValue value, TaintValue expected) {
            model.addReturnSources(method, directSources(value), latentSources(value), deepLatentSources(value),
                    completionFailureSources(value), value == null ? Set.of() : value.types,
                    value == null ? Set.of() : value.lambdas);
        }

        @Override public TaintValue merge(TaintValue v1, TaintValue v2) { return v1.merge(v2); }

        TaintValue fieldValue(FieldInsnNode f) {
            FieldKey fk = new FieldKey(f.owner, f.name, f.desc);
            Set<Source> direct = new TreeSet<>(model.fieldDirectSources(fk));
            Set<Source> render = new TreeSet<>(model.fieldRenderSources(fk));
            Set<Source> deepRender = new TreeSet<>(model.fieldDeepRenderSources(fk));
            Set<Source> completionFailures = new TreeSet<>(model.fieldCompletionFailureSources(fk));
            Set<TypeRef> types = new TreeSet<>(model.fieldTypes(fk));
            Type fieldType = Type.getType(f.desc);
            direct.addAll(model.secureTypeSources(fieldType));
            TypeRef declared = TypeRef.declared(fieldType);
            if (declared != null) types.add(declared);
            return TaintValue.ofWithCompletionFailures(fieldType.getSize(), direct, render, deepRender,
                    completionFailures, types, Set.of(), Set.of(), Set.of(fk), model.fieldLambdas(fk));
        }

        TaintValue arrayElement(TaintValue array, int size) {
            Set<Source> direct = new TreeSet<>();
            Set<Source> render = new TreeSet<>();
            Set<Source> deepRender = new TreeSet<>();
            Set<TypeRef> types = new TreeSet<>();
            Set<Integer> nestedArrays = new TreeSet<>();
            Set<LambdaTemplate> lambdas = new TreeSet<>();
            for (Integer id : array.arrayIds) {
                direct.addAll(arrayDirect.getOrDefault(id, Set.of()));
                render.addAll(arrayRender.getOrDefault(id, Set.of()));
                deepRender.addAll(deepArraySources(id, new HashSet<>()));
                types.addAll(arrayTypes.getOrDefault(id, Set.of()));
                nestedArrays.addAll(arrayNestedIds.getOrDefault(id, Set.of()));
                lambdas.addAll(arrayLambdas.getOrDefault(id, Set.of()));
            }
            return TaintValue.of(size, direct, render, deepRender, types, Set.of(), nestedArrays, Set.of(), lambdas);
        }

        Set<Source> deepArraySources(int id, Set<Integer> seen) {
            if (!seen.add(id)) return Set.of();
            Set<Source> out = new TreeSet<>(arrayRender.getOrDefault(id, Set.of()));
            for (Integer nested : arrayNestedIds.getOrDefault(id, Set.of())) out.addAll(deepArraySources(nested, seen));
            return out;
        }

        void noteFieldStore(FieldKey target, TaintValue value) {
            if (value == null) return;
            Set<Source> direct = directSources(value);
            Set<Source> rendered = renderSources(value);
            Set<Source> deepRendered = deepRenderSources(value);
            Set<Source> completionFailures = completionFailureSources(value);
            if (!Source.fieldsOnly(direct).isEmpty()) model.addTaintedField(target);
            model.addFieldDirectSources(target, direct);
            model.addFieldRenderSources(target, rendered);
            model.addFieldDeepRenderSources(target, deepRendered);
            model.addFieldCompletionFailureSources(target, completionFailures);
            model.addFieldTypes(target, value.types);
            Set<LambdaTemplate> effectiveLambdas = lambdaTemplates(value);
            model.addFieldLambdas(target, effectiveLambdas);
            Set<Source> directParams = Source.paramsOnly(direct);
            Set<Source> renderParams = Source.paramsOnly(rendered);
            Set<Source> deepRenderParams = Source.paramsOnly(deepRendered);
            Set<Source> failureParams = Source.paramsOnly(completionFailures);
            if (!directParams.isEmpty() || !renderParams.isEmpty() || !deepRenderParams.isEmpty() || !failureParams.isEmpty()
                    || !value.types.isEmpty() || !effectiveLambdas.isEmpty()) {
                model.addStoreSources(method, new StoreSummary(target, directParams, renderParams, deepRenderParams,
                        failureParams, value.types, effectiveLambdas));
            }
        }

        TaintValue selectedValue(ModelValueSelector selector, MethodInsnNode invocation, TaintValue receiver,
                                 List<? extends TaintValue> args, String modelSource) {
            if (selector.kind == ModelSelectorKind.RECEIVER) {
                if (receiver == null) {
                    model.addFinding(Finding.incomplete("Method model at " + modelSource
                            + " selects receiver for static invocation " + invocation.owner.replace('/', '.')
                            + "." + invocation.name + invocation.desc));
                    return TaintValue.oneSlot();
                }
                return receiver;
            }
            if (selector.argumentIndex < 0 || selector.argumentIndex >= args.size()) {
                model.addFinding(Finding.incomplete("Method model at " + modelSource
                        + " selects missing arg" + selector.argumentIndex + " for "
                        + invocation.owner.replace('/', '.') + "." + invocation.name + invocation.desc));
                return TaintValue.oneSlot();
            }
            return args.get(selector.argumentIndex);
        }

        Set<Source> selectedSources(List<ModelValueSelector> selectors, ModelValueMode mode,
                                    MethodInsnNode invocation, TaintValue receiver,
                                    List<? extends TaintValue> args, String modelSource) {
            Set<Source> out = new TreeSet<>();
            for (ModelValueSelector selector : selectors) {
                TaintValue value = selectedValue(selector, invocation, receiver, args, modelSource);
                if (mode == ModelValueMode.DIRECT) out.addAll(directSources(value));
                else if (mode == ModelValueMode.RENDER) out.addAll(renderSources(value));
                else {
                    out.addAll(deepRenderSources(value));
                    out.addAll(model.serializedSources(value.types));
                }
            }
            return out;
        }

        TaintValue applyConfiguredCallback(CallbackMethodModel callback, MethodInsnNode invocation,
                                           TaintValue receiver, List<? extends TaintValue> outerArgs) {
            TaintValue target = selectedValue(callback.target, invocation, receiver, outerArgs, callback.source);
            List<TaintValue> callbackArgs = new ArrayList<>();
            for (ModelValueSelector selector : callback.arguments) {
                callbackArgs.add(selectedValue(selector, invocation, receiver, outerArgs, callback.source));
            }
            TaintValue result = applyLambdaTemplates(target, callback.invocationName, callback.invocationDesc, callbackArgs);
            for (Source source : target.directSources) {
                if (source.kind == SourceKind.PARAM) {
                    List<ValueTemplate> templates = new ArrayList<>();
                    for (TaintValue arg : callbackArgs) templates.add(valueTemplate(arg));
                    model.addCallback(method, new CallbackSummary(source.paramOrdinal,
                            callback.invocationName, callback.invocationDesc, templates));
                }
            }
            return result;
        }

        boolean isThrowableValue(TaintValue value, String declaredOwner) {
            if (isThrowableType(declaredOwner)) return true;
            if (value == null) return false;
            for (TypeRef type : value.types) if (!type.array && isThrowableType(type.name)) return true;
            return false;
        }

        boolean isThrowableType(String internalName) {
            if (internalName == null || internalName.isBlank()) return false;
            if (internalName.equals("java/lang/Throwable") || internalName.endsWith("Exception") || internalName.endsWith("Error")) return true;
            String current = internalName;
            Set<String> seen = new HashSet<>();
            while (current != null && seen.add(current)) {
                ClassNode node = model.classes.get(current);
                if (node == null) return false;
                current = node.superName;
                if (current != null && (current.equals("java/lang/Throwable") || current.endsWith("Exception") || current.endsWith("Error"))) return true;
            }
            return false;
        }

        void noteExceptionConstructor(TaintValue receiver, List<? extends TaintValue> args, String descriptor) {
            Type[] parameters = Type.getArgumentTypes(descriptor);
            TaintValue message = null;
            TaintValue cause = null;
            for (int i = 0; i < parameters.length && i < args.size(); i++) {
                Type parameter = parameters[i];
                if (parameter.getSort() != Type.OBJECT) continue;
                String name = parameter.getInternalName();
                if (name.equals("java/lang/String") && message == null) message = args.get(i);
                else if (isThrowableType(name) && cause == null) cause = args.get(i);
            }
            if (message == null && cause != null && parameters.length == 1) {
                Set<Source> text = exceptionTextSources(cause);
                message = TaintValue.of(1, text, Set.of(), Set.of(), Set.of(TypeRef.exact("java/lang/String")), Set.of(), Set.of(), Set.of());
            }
            for (Integer id : receiver.objectIds) {
                if (message != null) exceptionMessages.merge(id, message, TaintValue::merge);
                if (cause != null) exceptionCauses.merge(id, cause, TaintValue::merge);
            }
        }

        void noteExceptionCause(TaintValue receiver, TaintValue cause) {
            Set<Source> graph = exceptionGraphReferenceSources(cause);
            addContentToValue(receiver, graph);
            for (Integer id : receiver.objectIds) exceptionCauses.merge(id, cause, TaintValue::merge);
        }

        void noteExceptionSuppressed(TaintValue receiver, TaintValue suppressed) {
            Set<Source> graph = exceptionGraphReferenceSources(suppressed);
            addContentToValue(receiver, graph);
            for (Integer id : receiver.objectIds) exceptionSuppressed.computeIfAbsent(id, ignored -> new ArrayList<>()).add(suppressed);
        }

        TaintValue exceptionTextValue(TaintValue throwable) {
            TaintValue result = null;
            if (throwable != null) {
                for (Integer id : throwable.objectIds) {
                    TaintValue message = exceptionMessages.get(id);
                    if (message != null) result = result == null ? message : result.merge(message);
                }
            }
            Set<Source> virtualText = model.exceptionTextSources(throwable == null ? Set.of() : throwable.types);
            if (!virtualText.isEmpty()) {
                TaintValue virtual = TaintValue.of(1, virtualText, Set.of(), Set.of(), Set.of(TypeRef.exact("java/lang/String")), Set.of(), Set.of(), Set.of());
                result = result == null ? virtual : result.merge(virtual);
            }
            if (result == null && throwable != null) {
                Set<Source> fallback = latentSources(throwable);
                if (!fallback.isEmpty()) result = TaintValue.of(1, fallback, Set.of(), Set.of(), Set.of(TypeRef.exact("java/lang/String")), Set.of(), Set.of(), Set.of());
            }
            return result == null ? TaintValue.empty(1).withType(TypeRef.exact("java/lang/String")) : result;
        }

        Set<Source> exceptionTextSources(TaintValue throwable) {
            TaintValue value = exceptionTextValue(throwable);
            Set<Source> out = new TreeSet<>(directSources(value));
            out.addAll(renderSources(value));
            return out;
        }

        TaintValue exceptionCauseValue(TaintValue throwable) {
            TaintValue result = null;
            if (throwable != null) {
                for (Integer id : throwable.objectIds) {
                    TaintValue cause = exceptionCauses.get(id);
                    if (cause != null) result = result == null ? cause : result.merge(cause);
                }
            }
            if (result != null) return result;
            return TaintValue.empty(1).withType(TypeRef.declaredObject("java/lang/Throwable"));
        }

        TaintValue exceptionSuppressedArray(TaintValue throwable, int arrayId) {
            Set<Source> direct = new TreeSet<>();
            Set<Source> render = new TreeSet<>();
            Set<TypeRef> types = new TreeSet<>();
            if (throwable != null) {
                for (Integer id : throwable.objectIds) {
                    for (TaintValue suppressed : exceptionSuppressed.getOrDefault(id, List.of())) {
                        direct.addAll(directSources(suppressed));
                        render.addAll(exceptionGraphSources(suppressed));
                        types.addAll(suppressed.types);
                    }
                }
            }
            arrayDirect.computeIfAbsent(arrayId, ignored -> new TreeSet<>()).addAll(direct);
            arrayRender.computeIfAbsent(arrayId, ignored -> new TreeSet<>()).addAll(render);
            arrayTypes.computeIfAbsent(arrayId, ignored -> new TreeSet<>()).addAll(types);
            return TaintValue.empty(1).withType(TypeRef.exactArray("[Ljava/lang/Throwable;")).withArrayId(arrayId).withObjectId(arrayId);
        }

        Set<Source> exceptionGraphReferenceSources(TaintValue throwable) {
            Set<Source> graph = exceptionGraphSources(throwable);
            Set<Source> out = new TreeSet<>();
            for (Source source : graph) {
                if (source.kind == SourceKind.PARAM) out.add(Source.deepRenderParam(source.paramOrdinal, source));
                else out.add(source);
            }
            return out;
        }

        Set<Source> exceptionGraphSources(TaintValue throwable) {
            Set<Source> out = new TreeSet<>();
            collectExceptionGraph(throwable, out, new HashSet<>());
            return out;
        }

        void collectExceptionGraph(TaintValue throwable, Set<Source> out, Set<Integer> seen) {
            if (throwable == null) return;
            out.addAll(directSources(throwable));
            out.addAll(latentSources(throwable));
            out.addAll(deepLatentSources(throwable));
            out.addAll(model.exceptionTextSources(throwable.types));
            for (Integer id : throwable.objectIds) {
                if (!seen.add(id)) continue;
                TaintValue message = exceptionMessages.get(id);
                if (message != null) out.addAll(renderSources(message));
                TaintValue cause = exceptionCauses.get(id);
                if (cause != null) collectExceptionGraph(cause, out, seen);
                for (TaintValue suppressed : exceptionSuppressed.getOrDefault(id, List.of())) collectExceptionGraph(suppressed, out, seen);
            }
        }

        void addContentToValue(TaintValue target, Set<Source> contents) {
            if (target == null || contents.isEmpty()) return;
            for (Integer id : target.objectIds) objectContents.computeIfAbsent(id, k -> new TreeSet<>()).addAll(contents);
            for (Integer id : target.arrayIds) arrayRender.computeIfAbsent(id, k -> new TreeSet<>()).addAll(contents);
            for (FieldKey origin : target.origins) model.addFieldRenderSources(origin, contents);
            for (Source s : target.directSources) {
                if (s.kind == SourceKind.PARAM) model.addMutation(method, new MutationSummary(s.paramOrdinal, contents));
            }
        }

        Set<LambdaTemplate> lambdaTemplates(TaintValue value) {
            Set<LambdaTemplate> out = new TreeSet<>();
            if (value == null) return out;
            out.addAll(value.lambdas);
            for (Integer id : value.objectIds) out.addAll(objectLambdas.getOrDefault(id, Set.of()));
            for (Integer id : value.arrayIds) out.addAll(arrayLambdas.getOrDefault(id, Set.of()));
            return out;
        }

        void addLambdasToValue(TaintValue target, Set<LambdaTemplate> lambdas) {
            if (target == null || lambdas.isEmpty()) return;
            for (Integer id : target.objectIds) objectLambdas.computeIfAbsent(id, ignored -> new TreeSet<>()).addAll(lambdas);
            for (Integer id : target.arrayIds) arrayLambdas.computeIfAbsent(id, ignored -> new TreeSet<>()).addAll(lambdas);
            for (FieldKey origin : target.origins) model.addFieldLambdas(origin, lambdas);
        }

        TaintValue withEffectiveLambdas(TaintValue value) {
            if (value == null) return null;
            Set<LambdaTemplate> lambdas = lambdaTemplates(value);
            if (lambdas.equals(value.lambdas)) return value;
            return TaintValue.ofWithCompletionFailures(value.size, value.directSources, value.renderSources,
                    value.deepRenderSources, value.completionFailureSources, value.types,
                    value.objectIds, value.arrayIds, value.origins, lambdas);
        }

        void reportOrSummarizeSink(SinkCategory category, String sinkOwner, String sinkName,
                                   String flow, Set<Source> sources) {
            reportOrSummarizeSink(category, sinkOwner, sinkName, flow, sources, cn.name,
                    diagnosticLocation(null), -1, "", List.of());
        }

        void reportOrSummarizeSink(SinkCategory category, String sinkOwner, String sinkName,
                                   String flow, Set<Source> sources, String sinkArtifactOwner) {
            reportOrSummarizeSink(category, sinkOwner, sinkName, flow, sources, sinkArtifactOwner,
                    diagnosticLocation(null), -1, "", List.of());
        }

        void reportOrSummarizeSink(SinkCategory category, String sinkOwner, String sinkName,
                                   String flow, Set<Source> sources, String sinkArtifactOwner,
                                   DiagnosticLocation location, int sinkArgument, String contextKey,
                                   List<DiagnosticLocation> inheritedPath) {
            reportOrSummarizeSink(category, sinkOwner, sinkName, flow, sources, sinkArtifactOwner,
                    location, sinkArgument, contextKey, inheritedPath, null);
        }

        void reportOrSummarizeSink(SinkCategory category, String sinkOwner, String sinkName,
                                   String flow, Set<Source> sources, String sinkArtifactOwner,
                                   DiagnosticLocation location, int sinkArgument, String contextKey,
                                   List<DiagnosticLocation> inheritedPath, SuppressionInfo inheritedSuppression) {
            if (sources.isEmpty()) return;
            SuppressionInfo effectiveSuppression = inheritedSuppression != null
                    ? inheritedSuppression : model.suppression(method);
            String sink = sinkOwner.replace('/', '.') + "." + sinkName;
            List<DiagnosticLocation> effectivePath = inheritedPath == null || inheritedPath.isEmpty()
                    ? (location == null ? List.of() : List.of(location))
                    : List.copyOf(inheritedPath);
            if (model.isDeferredLambdaBody(method)) {
                // Synthetic lambda bodies are executable code, but the invokedynamic call only creates the
                // callback. Retain a complete sink summary and report it only when a reachable callback site
                // invokes or possibly escapes the lambda.
                model.addSinkSources(method, new SinkSummary(category, sink, flow, sources, sinkArtifactOwner,
                        sinkArgument, contextKey, effectivePath, effectiveSuppression));
                return;
            }
            Set<Source> unsafeSources = Source.withState(sources, FlowState.UNSAFE);
            Set<Source> possibleSources = Source.withState(sources, FlowState.POSSIBLE);
            Set<Source> sanitizedSources = Source.withState(sources, FlowState.SANITIZED);
            Set<FieldKey> unsafeFields = Source.toFields(unsafeSources);
            Set<FieldKey> possibleFields = Source.toFields(possibleSources);
            Set<FieldKey> sanitizedFields = Source.toFields(sanitizedSources);
            possibleFields.removeAll(unsafeFields);
            sanitizedFields.removeAll(unsafeFields);
            sanitizedFields.removeAll(possibleFields);
            if (!unsafeFields.isEmpty()) {
                model.addFinding(new Finding("ERROR", category, cn.name, mn.name, mn.desc, sinkArtifactOwner,
                        sink, flow, unsafeFields, Set.of(), Set.of(), location, sinkArgument, contextKey, effectivePath,
                        effectiveSuppression));
            }
            if (!possibleFields.isEmpty()) {
                String possibleFlow = category == SinkCategory.CONTEXT_CAPTURE
                        ? "possibly secure value captured in diagnostic context"
                        : "possibly secure value rendered by log/print sink";
                model.addFinding(new Finding("POSSIBLE", category, cn.name, mn.name, mn.desc, sinkArtifactOwner,
                        sink, possibleFlow, possibleFields, Set.of(), Source.uncertainties(possibleSources),
                        location, sinkArgument, contextKey, effectivePath, effectiveSuppression));
            }
            for (FieldKey field : sanitizedFields) {
                Set<Source> reported = new TreeSet<>();
                for (Source source : sanitizedSources) {
                    if (source.kind == SourceKind.FIELD && source.field.equals(field)) reported.add(source);
                }
                String sanitizedFlow = category == SinkCategory.CONTEXT_CAPTURE
                        ? "sanitized value captured in diagnostic context"
                        : "sanitized value rendered by log/print sink";
                model.addFinding(new Finding("SANITIZED", category, cn.name, mn.name, mn.desc, sinkArtifactOwner,
                        sink, sanitizedFlow, Set.of(field), Source.sanitizers(reported), Set.of(),
                        location, sinkArgument, contextKey, effectivePath, effectiveSuppression));
            }
            Set<Source> params = Source.paramsOnly(sources);
            if (!params.isEmpty()) model.addSinkSources(method, new SinkSummary(category, sink, flow, params,
                    sinkArtifactOwner, sinkArgument, contextKey, effectivePath, effectiveSuppression));
        }

        ValueTemplate valueTemplate(TaintValue value) {
            if (value == null) return new ValueTemplate(1, Set.of(), Set.of(), Set.of(), Set.of(), Set.of(), Set.of());
            return new ValueTemplate(value.size, directSources(value), latentSources(value), deepLatentSources(value),
                    completionFailureSources(value), value.types, lambdaTemplates(value));
        }

        TaintValue valueFromTemplate(ValueTemplate value) {
            return TaintValue.ofWithCompletionFailures(value.size, value.directSources, value.renderSources,
                    value.deepRenderSources, value.completionFailureSources, value.types,
                    Set.of(), Set.of(), Set.of(), value.lambdas);
        }

        ValueTemplate mapValueTemplateToCaller(ValueTemplate value, List<? extends TaintValue> callerValues) {
            return new ValueTemplate(value.size,
                    mapCalleeSourcesToCaller(value.directSources, callerValues),
                    mapCalleeSourcesToCaller(value.renderSources, callerValues),
                    mapCalleeSourcesToCaller(value.deepRenderSources, callerValues),
                    mapCalleeSourcesToCaller(value.completionFailureSources, callerValues),
                    value.types,
                    mapLambdaTemplatesToCaller(value.lambdas, callerValues));
        }

        Set<LambdaTemplate> mapLambdaTemplatesToCaller(Set<LambdaTemplate> lambdas, List<? extends TaintValue> callerValues) {
            Set<LambdaTemplate> out = new TreeSet<>();
            for (LambdaTemplate lambda : lambdas) {
                List<ValueTemplate> captures = new ArrayList<>();
                for (ValueTemplate capture : lambda.captures) captures.add(mapValueTemplateToCaller(capture, callerValues));
                out.add(new LambdaTemplate(lambda.handleTag, lambda.implementation, captures));
            }
            return out;
        }

        TaintValue applyLambdaTemplates(TaintValue target, String samName, String samDesc, List<? extends TaintValue> samArgs) {
            Type samReturn = Type.getReturnType(samDesc);
            TaintValue aggregate = samReturn == Type.VOID_TYPE ? null : TaintValue.empty(samReturn.getSize());
            target = withEffectiveLambdas(target);
            if (target == null || target.lambdas.isEmpty()) return aggregate;

            for (LambdaTemplate lambda : target.lambdas) {
                List<TaintValue> captures = new ArrayList<>();
                for (ValueTemplate capture : lambda.captures) captures.add(valueFromTemplate(capture));
                List<TaintValue> implementationValues = lambdaImplementationValues(lambda, captures, samArgs);
                MethodSummary summary = model.summary(lambda.implementation);

                MethodInsnNode referencedCall = methodReferenceCall(lambda);
                MethodKey referencedKey = referencedCall == null ? null
                        : new MethodKey(referencedCall.owner, referencedCall.name, referencedCall.desc);
                List<? extends TaintValue> referencedArgs = referencedCall == null ? List.of()
                        : methodArguments(referencedCall, implementationValues);
                TaintValue referencedReceiver = referencedCall == null || referencedCall.getOpcode() == INVOKESTATIC
                        ? null : implementationValues.get(0);
                if (referencedCall != null) {
                    List<SinkMethodModel> configuredSinks = model.methodModels.sinks(referencedKey);
                    if (!configuredSinks.isEmpty()) {
                        for (SinkMethodModel sinkModel : configuredSinks) {
                            Set<Source> sinkSources = selectedSources(sinkModel.values, sinkModel.mode,
                                    referencedCall, referencedReceiver, referencedArgs, sinkModel.source);
                            String flow = sinkModel.category == SinkCategory.CONTEXT_CAPTURE
                                    ? "method reference captures value at configured diagnostic-context sink"
                                    : "method reference renders value at configured output sink";
                            reportOrSummarizeSink(sinkModel.category, referencedCall.owner,
                                    referencedCall.name + referencedCall.desc, flow, sinkSources);
                        }
                    } else {
                        SinkCategory referencedCategory = sinkCategory(referencedCall);
                        if (referencedCategory != null) {
                            Set<Source> sinkSources = new TreeSet<>();
                            if (referencedCategory == SinkCategory.CONTEXT_CAPTURE) {
                                for (TaintValue arg : referencedArgs) sinkSources.addAll(deepRenderSources(arg));
                            } else {
                                boolean deepArrays = sinkDeepRendersArrays(referencedCall);
                                for (TaintValue arg : referencedArgs) {
                                    sinkSources.addAll(deepArrays ? deepRenderSources(arg) : renderSources(arg));
                                }
                                if (sinkRendersReceiverContents(referencedCall) && referencedReceiver != null) {
                                    sinkSources.addAll(renderSources(referencedReceiver));
                                }
                            }
                            String flow = referencedCategory == SinkCategory.CONTEXT_CAPTURE
                                    ? "method reference captures value in diagnostic context"
                                    : "method reference renders value at log/print sink";
                            reportOrSummarizeSink(referencedCategory, referencedCall.owner,
                                    referencedCall.name + referencedCall.desc, flow, sinkSources);
                        }
                    }
                    for (MutationMethodModel mutationModel : model.methodModels.mutations(referencedKey)) {
                        TaintValue mutationTarget = selectedValue(mutationModel.target, referencedCall,
                                referencedReceiver, referencedArgs, mutationModel.source);
                        Set<Source> contents = selectedSources(mutationModel.values, mutationModel.mode,
                                referencedCall, referencedReceiver, referencedArgs, mutationModel.source);
                        addContentToValue(mutationTarget, contents);
                    }
                    for (CallbackMethodModel callbackModel : model.methodModels.callbacks(referencedKey)) {
                        applyConfiguredCallback(callbackModel, referencedCall, referencedReceiver, referencedArgs);
                    }
                }

                for (SinkSummary sink : summary.sinks) {
                    Set<Source> mapped = mapCalleeSourcesToCaller(sink.sources, implementationValues);
                    String nestedFlow = sink.category == SinkCategory.CONTEXT_CAPTURE
                            ? "lambda/method-reference captures value in diagnostic context: " + sink.sink
                            : "lambda/method-reference logs value: " + sink.sink;
                    DiagnosticLocation nestedLocation = sink.path.isEmpty() ? diagnosticLocation(null) : sink.path.get(0);
                    reportOrSummarizeSink(sink.category, lambda.implementation.owner,
                            lambda.implementation.name + lambda.implementation.desc, nestedFlow, mapped,
                            sink.sinkArtifactOwner, nestedLocation, sink.sinkArgument, sink.contextKey, sink.path,
                            sink.suppression);
                }
                for (StoreSummary store : summary.stores) {
                    Set<Source> direct = mapCalleeSourcesToCaller(store.directSources, implementationValues);
                    Set<Source> render = mapCalleeSourcesToCaller(store.renderSources, implementationValues);
                    Set<Source> deep = mapCalleeSourcesToCaller(store.deepRenderSources, implementationValues);
                    Set<Source> failures = mapCalleeSourcesToCaller(store.completionFailureSources, implementationValues);
                    Set<LambdaTemplate> storedLambdas = mapLambdaTemplatesToCaller(store.lambdas, implementationValues);
                    noteFieldStore(store.target, TaintValue.ofWithCompletionFailures(1, direct, render, deep,
                            failures, store.types, Set.of(), Set.of(), Set.of(), storedLambdas));
                }
                for (MutationSummary mutation : summary.mutations) {
                    if (mutation.targetParamOrdinal < implementationValues.size()) {
                        Set<Source> mapped = mapCalleeSourcesToCaller(mutation.contents, implementationValues);
                        addContentToValue(implementationValues.get(mutation.targetParamOrdinal), mapped);
                    }
                }
                for (CallbackSummary callback : summary.callbacks) processCallback(callback, implementationValues);

                if (samReturn != Type.VOID_TYPE) {
                    Set<Source> direct = mapCalleeSourcesToCaller(summary.returnSources, implementationValues);
                    Set<Source> render = mapCalleeSourcesToCaller(summary.returnRenderSources, implementationValues);
                    Set<Source> deep = mapCalleeSourcesToCaller(summary.returnDeepRenderSources, implementationValues);
                    RendererMethodModel rendererModel = model.methodModels.renderer(lambda.implementation);
                    if (rendererModel != null && referencedCall != null) {
                        direct.addAll(selectedSources(rendererModel.values, rendererModel.mode,
                                referencedCall, referencedReceiver, referencedArgs, rendererModel.source));
                    }
                    SanitizerInfo sanitizer = model.sanitizer(lambda.implementation);
                    if (sanitizer != null) {
                        Set<Source> tracked = new TreeSet<>();
                        tracked.addAll(direct);
                        tracked.addAll(render);
                        tracked.addAll(deep);
                        for (TaintValue value : implementationValues) tracked.addAll(deepRenderSources(value));
                        direct = sanitizeSources(tracked, sanitizer);
                        render = new TreeSet<>();
                        deep = new TreeSet<>();
                    }
                    Set<TypeRef> types = new TreeSet<>(summary.returnTypes);
                    Set<LambdaTemplate> returnedLambdas = mapLambdaTemplatesToCaller(summary.returnLambdas, implementationValues);
                    if (lambda.handleTag == H_NEWINVOKESPECIAL) {
                        types.add(TypeRef.exact(lambda.implementation.owner));
                        render.addAll(model.renderingSources(types));
                    }
                    TaintValue result = TaintValue.of(samReturn.getSize(), direct, render, deep, types, Set.of(), Set.of(), Set.of(), returnedLambdas);
                    aggregate = aggregate == null ? result : aggregate.merge(result);
                }
            }
            return aggregate;
        }

        MethodInsnNode methodReferenceCall(LambdaTemplate lambda) {
            int opcode;
            boolean itf = false;
            switch (lambda.handleTag) {
                case H_INVOKESTATIC -> opcode = INVOKESTATIC;
                case H_INVOKEVIRTUAL -> opcode = INVOKEVIRTUAL;
                case H_INVOKEINTERFACE -> { opcode = INVOKEINTERFACE; itf = true; }
                case H_INVOKESPECIAL -> opcode = INVOKESPECIAL;
                default -> { return null; }
            }
            return new MethodInsnNode(opcode, lambda.implementation.owner, lambda.implementation.name,
                    lambda.implementation.desc, itf);
        }

        List<TaintValue> lambdaImplementationValues(LambdaTemplate lambda, List<TaintValue> captures,
                                                     List<? extends TaintValue> samArgs) {
            List<TaintValue> out = new ArrayList<>();
            if (lambda.handleTag == H_INVOKESTATIC) {
                out.addAll(captures);
                out.addAll(samArgs);
                return out;
            }
            if (lambda.handleTag == H_NEWINVOKESPECIAL) {
                out.add(TaintValue.empty(1).withType(TypeRef.exact(lambda.implementation.owner)));
                out.addAll(captures);
                out.addAll(samArgs);
                return out;
            }
            if (!captures.isEmpty()) {
                out.add(captures.get(0));
                out.addAll(captures.subList(1, captures.size()));
                out.addAll(samArgs);
            } else if (!samArgs.isEmpty()) {
                out.add(samArgs.get(0));
                out.addAll(samArgs.subList(1, samArgs.size()));
            }
            return out;
        }

        TaintValue processCallback(CallbackSummary callback, List<? extends TaintValue> callerValues) {
            if (callback.targetParamOrdinal < 0 || callback.targetParamOrdinal >= callerValues.size()) return null;
            TaintValue target = callerValues.get(callback.targetParamOrdinal);
            List<TaintValue> args = new ArrayList<>();
            for (ValueTemplate argument : callback.arguments) args.add(valueFromTemplate(mapValueTemplateToCaller(argument, callerValues)));
            TaintValue result = applyLambdaTemplates(target, callback.methodName, callback.methodDesc, args);
            if (target != null) {
                for (Source source : target.directSources) {
                    if (source.kind == SourceKind.PARAM) {
                        List<ValueTemplate> mappedArgs = new ArrayList<>();
                        for (TaintValue arg : args) mappedArgs.add(valueTemplate(arg));
                        model.addCallback(method, new CallbackSummary(source.paramOrdinal, callback.methodName, callback.methodDesc, mappedArgs));
                    }
                }
            }
            return result;
        }

        void recordFunctionalCallback(TaintValue receiver, MethodInsnNode invocation, List<? extends TaintValue> args) {
            if (receiver == null || !isFunctionalInvocation(invocation)) return;
            List<ValueTemplate> templates = new ArrayList<>();
            for (TaintValue arg : args) templates.add(valueTemplate(arg));
            for (Source source : receiver.directSources) {
                if (source.kind == SourceKind.PARAM) {
                    model.addCallback(method, new CallbackSummary(source.paramOrdinal, invocation.name, invocation.desc, templates));
                }
            }
        }

        Set<Source> mapCalleeSourcesToCaller(Set<Source> calleeSources, List<? extends TaintValue> callerValues) {
            Set<Source> out = new TreeSet<>();
            for (Source s : calleeSources) {
                if (s.kind == SourceKind.FIELD) {
                    out.add(s);
                } else if (s.paramOrdinal >= 0 && s.paramOrdinal < callerValues.size()) {
                    TaintValue caller = callerValues.get(s.paramOrdinal);
                    Set<Source> mapped;
                    if (s.kind == SourceKind.PARAM) mapped = directSources(caller);
                    else if (s.kind == SourceKind.RENDER_PARAM) mapped = renderSources(caller);
                    else if (s.kind == SourceKind.DEEP_RENDER_PARAM) mapped = deepRenderSources(caller);
                    else mapped = supplierResultSources(caller);
                    if (s.state == FlowState.SANITIZED && s.sanitizer != null) out.addAll(sanitizeSources(mapped, s.sanitizer));
                    else if (s.state == FlowState.POSSIBLE) out.addAll(possibleSources(mapped, s.uncertainties));
                    else out.addAll(mapped);
                }
            }
            return out;
        }

        Set<Source> possibleSources(Set<Source> sources, UncertaintyReason reason) {
            return possibleSources(sources, Set.of(reason));
        }

        Set<Source> possibleSources(Set<Source> sources, Set<UncertaintyReason> reasons) {
            Set<Source> out = new TreeSet<>();
            for (Source source : sources) out.add(source.possible(reasons));
            return out;
        }

        Set<Source> sanitizeSources(Set<Source> sources, SanitizerInfo sanitizer) {
            Set<Source> out = new TreeSet<>();
            for (Source source : sources) out.add(source.sanitized(sanitizer));
            return out;
        }

        Set<Source> directSources(TaintValue v) {
            if (v == null) return new TreeSet<>();
            Set<Source> out = new TreeSet<>(v.directSources);
            for (Integer id : v.arrayIds) out.addAll(arrayDirect.getOrDefault(id, Set.of()));
            return out;
        }

        Set<Source> latentSources(TaintValue v) {
            if (v == null) return new TreeSet<>();
            Set<Source> out = new TreeSet<>(v.renderSources);
            for (Integer id : v.objectIds) out.addAll(objectContents.getOrDefault(id, Set.of()));
            return out;
        }

        Set<Source> deepLatentSources(TaintValue v) {
            if (v == null) return new TreeSet<>();
            Set<Source> out = new TreeSet<>(v.deepRenderSources);
            for (Integer id : v.arrayIds) out.addAll(deepArraySources(id, new HashSet<>()));
            return out;
        }

        Set<Source> completionFailureSources(TaintValue v) {
            return v == null ? new TreeSet<>() : new TreeSet<>(v.completionFailureSources);
        }

        Set<Source> renderSources(TaintValue v) {
            Set<Source> out = v == null ? new TreeSet<>() : new TreeSet<>(v.directSources);
            if (v == null) return out;
            out.addAll(latentSources(v));
            boolean parameterBacked = false;
            for (Source s : v.directSources) {
                if (s.kind == SourceKind.PARAM) {
                    parameterBacked = true;
                    out.add(Source.renderParam(s.paramOrdinal, s));
                }
            }
            Set<TypeRef> resolvable = new TreeSet<>();
            for (TypeRef type : v.types) {
                if (!parameterBacked || type.exact || model.shouldResolveParameterType(type)) resolvable.add(type);
            }
            out.addAll(model.renderingSources(resolvable));
            return out;
        }

        Set<Source> deepRenderSources(TaintValue v) {
            Set<Source> out = renderSources(v);
            if (v != null) {
                for (Source s : v.directSources) if (s.kind == SourceKind.PARAM) out.add(Source.deepRenderParam(s.paramOrdinal, s));
            }
            out.addAll(deepLatentSources(v));
            return out;
        }

        CalleeResolution resolveCallee(MethodInsnNode m, TaintValue receiver) {
            Set<MethodKey> keys = new LinkedHashSet<>();
            MethodKey declared = new MethodKey(m.owner, m.name, m.desc);
            keys.add(declared);
            if (receiver != null && (m.getOpcode() == INVOKEVIRTUAL || m.getOpcode() == INVOKEINTERFACE)) {
                for (TypeRef ref : receiver.types) {
                    for (String runtimeType : model.dispatchTypes(ref)) {
                        MethodKey resolved = model.resolveVirtual(runtimeType, m.name, m.desc);
                        if (resolved != null) keys.add(resolved);
                    }
                }
            }
            MethodSummary aggregate = new MethodSummary();
            boolean known = false;
            List<MethodKey> knownKeys = new ArrayList<>();
            for (MethodKey key : keys) {
                MethodSummary summary = model.summaries.get(key);
                if (summary == null) continue;
                known = true;
                knownKeys.add(key);
                aggregate.absorb(summary);
            }
            SanitizerInfo sanitizer = model.sanitizer(declared);
            if (sanitizer == null && !knownKeys.isEmpty()) {
                SanitizerInfo candidate = null;
                boolean allSanitized = true;
                for (MethodKey key : knownKeys) {
                    SanitizerInfo current = model.sanitizer(key);
                    if (current == null) { allSanitized = false; break; }
                    if (candidate == null) candidate = current;
                }
                if (allSanitized) sanitizer = candidate;
            }
            return new CalleeResolution(aggregate, known, sanitizer);
        }

        static List<? extends TaintValue> methodArguments(MethodInsnNode m, List<? extends TaintValue> values) {
            return m.getOpcode() == INVOKESTATIC ? values : values.subList(1, values.size());
        }



        boolean shouldReportCallbackEscape(MethodInsnNode invocation, MethodKey called) {
            if (sinkCategory(invocation) != null) return false;
            if (!model.methodModels.callbacks(called).isEmpty()) return false;
            if (isKnownAsyncBoundary(invocation)) return false;
            if (isContainerFactory(invocation) || isContentMutation(invocation)) return false;
            return !invocation.name.equals("<init>");
        }

        void reportEscapingCallbacks(MethodInsnNode escapeCall, List<? extends TaintValue> args) {
            for (TaintValue argument : args) {
                TaintValue callback = withEffectiveLambdas(argument);
                if (callback == null || callback.lambdas.isEmpty()) continue;
                for (LambdaTemplate lambda : callback.lambdas) {
                    List<TaintValue> implementationValues = escapedLambdaImplementationValues(lambda);
                    MethodSummary summary = model.summary(lambda.implementation);
                    for (SinkSummary sink : summary.sinks) {
                        Set<Source> mapped = mapCalleeSourcesToCaller(sink.sources, implementationValues);
                        Set<Source> escaped = new TreeSet<>();
                        for (Source source : mapped) {
                            escaped.add(source.state == FlowState.SANITIZED
                                    ? source
                                    : source.possible(Set.of(UncertaintyReason.CALLBACK_MAY_EXECUTE)));
                        }
                        String flow = "callback passed to unresolved method may execute and reach " + sink.sink
                                + " via " + escapeCall.owner.replace('/', '.') + "." + escapeCall.name + escapeCall.desc;
                        DiagnosticLocation escapeLocation = diagnosticLocation(escapeCall);
                        List<DiagnosticLocation> escapePath = prependPath(escapeLocation, sink.path);
                        reportOrSummarizeSink(sink.category, lambda.implementation.owner,
                                lambda.implementation.name + lambda.implementation.desc, flow, escaped,
                                sink.sinkArtifactOwner, escapeLocation, sink.sinkArgument, sink.contextKey, escapePath,
                                sink.suppression);
                    }
                }
            }
        }

        List<TaintValue> escapedLambdaImplementationValues(LambdaTemplate lambda) {
            List<TaintValue> captures = new ArrayList<>();
            for (ValueTemplate capture : lambda.captures) captures.add(valueFromTemplate(capture));
            List<TaintValue> values = lambdaImplementationValues(lambda, captures, List.of());
            int expected = Type.getArgumentTypes(lambda.implementation.desc).length
                    + (lambda.handleTag == H_INVOKESTATIC || lambda.handleTag == H_NEWINVOKESPECIAL ? 0 : 1);
            while (values.size() < expected) values.add(TaintValue.oneSlot());
            return values;
        }

        Set<Source> supplierResultSources(TaintValue supplier) {
            Set<Source> out = new TreeSet<>();
            TaintValue result = invokeCallback(supplier, "get", "()Ljava/lang/Object;", List.of());
            out.addAll(renderSources(result));
            if (supplier != null) {
                for (Source source : supplier.directSources) {
                    if (source.kind == SourceKind.PARAM) out.add(Source.supplierReturnParam(source.paramOrdinal, source));
                }
            }
            return out;
        }

        TaintValue invokeCallback(TaintValue target, String callbackName, String callbackDesc,
                                  List<? extends TaintValue> callbackArgs) {
            TaintValue result = applyLambdaTemplates(target, callbackName, callbackDesc, callbackArgs);
            if (target != null) {
                List<ValueTemplate> templates = new ArrayList<>();
                for (TaintValue argument : callbackArgs) templates.add(valueTemplate(argument));
                for (Source source : target.directSources) {
                    if (source.kind == SourceKind.PARAM) {
                        model.addCallback(method, new CallbackSummary(source.paramOrdinal,
                                callbackName, callbackDesc, templates));
                    }
                }
            }
            return result;
        }

        TaintValue mergeCallbackResult(TaintValue left, TaintValue right) {
            if (left == null) return right;
            return right == null ? left : left.merge(right);
        }

        TaintValue applyKnownAsyncCallback(MethodInsnNode m, TaintValue receiver, List<? extends TaintValue> args) {
            String owner = m.owner;
            String name = m.name;
            Type[] parameterTypes = Type.getArgumentTypes(m.desc);

            if (owner.equals("java/lang/Thread") && name.equals("<init>")) {
                for (int i = 0; i < args.size(); i++) {
                    if (isRunnableType(parameterTypes, i)) addLambdasToValue(receiver, lambdaTemplates(args.get(i)));
                }
                return null;
            }
            if (owner.equals("java/lang/Thread") && name.equals("start") && args.isEmpty()) {
                return invokeCallback(withEffectiveLambdas(receiver), "run", "()V", List.of());
            }
            if (owner.equals("java/lang/Thread") && name.equals("startVirtualThread") && !args.isEmpty()) {
                invokeCallback(args.get(0), "run", "()V", List.of());
                return callbackCarrier(args.get(0), TypeRef.declared(Type.getReturnType(m.desc)));
            }
            if (isThreadBuilder(owner) && name.equals("start") && !args.isEmpty()) {
                invokeCallback(args.get(0), "run", "()V", List.of());
                return callbackCarrier(args.get(0), TypeRef.declared(Type.getReturnType(m.desc)));
            }
            if (isThreadBuilder(owner) && name.equals("unstarted") && !args.isEmpty()) {
                return callbackCarrier(args.get(0), TypeRef.declared(Type.getReturnType(m.desc)));
            }
            if (owner.equals("java/util/concurrent/ThreadFactory") && name.equals("newThread") && !args.isEmpty()) {
                return callbackCarrier(args.get(0), TypeRef.declared(Type.getReturnType(m.desc)));
            }

            if (isExecutorOwner(owner)) {
                if (name.equals("execute") && !args.isEmpty()) {
                    return invokeCallback(args.get(0), "run", "()V", List.of());
                }
                if (name.equals("submit") && !args.isEmpty()) {
                    if (isCallableType(parameterTypes, 0)) {
                        return invokeCallback(args.get(0), "call", "()Ljava/lang/Object;", List.of());
                    }
                    invokeCallback(args.get(0), "run", "()V", List.of());
                    return args.size() > 1 ? args.get(1) : null;
                }
                if ((name.equals("invokeAll") || name.equals("invokeAny")) && !args.isEmpty()) {
                    return invokeCallback(withEffectiveLambdas(args.get(0)), "call", "()Ljava/lang/Object;", List.of());
                }
            }

            if (owner.equals("java/util/concurrent/ScheduledExecutorService") && !args.isEmpty()) {
                if (Set.of("scheduleAtFixedRate", "scheduleWithFixedDelay").contains(name)) {
                    return invokeCallback(args.get(0), "run", "()V", List.of());
                }
                if (name.equals("schedule")) {
                    if (isCallableType(parameterTypes, 0)) {
                        return invokeCallback(args.get(0), "call", "()Ljava/lang/Object;", List.of());
                    }
                    return invokeCallback(args.get(0), "run", "()V", List.of());
                }
            }

            if (owner.equals("java/util/concurrent/ForkJoinPool") && !args.isEmpty()) {
                if (Set.of("execute", "submit", "invoke").contains(name)) {
                    if (isCallableType(parameterTypes, 0)) {
                        return invokeCallback(args.get(0), "call", "()Ljava/lang/Object;", List.of());
                    }
                    return invokeCallback(args.get(0), "run", "()V", List.of());
                }
            }

            if (owner.equals("java/util/concurrent/ForkJoinTask") && name.equals("adapt") && !args.isEmpty()) {
                return callbackCarrier(args.get(0), TypeRef.declared(Type.getReturnType(m.desc)));
            }

            if (isCompletionStageOwner(owner)) {
                if (Set.of("completedFuture", "completedStage").contains(name) && !args.isEmpty()) {
                    return completionCarrier(args.get(0), Type.getReturnType(m.desc));
                }
                if (Set.of("failedFuture", "failedStage").contains(name) && !args.isEmpty()) {
                    return failedCompletionCarrier(args.get(0), Type.getReturnType(m.desc));
                }

                if (name.equals("runAsync") && !args.isEmpty()) {
                    invokeCallback(args.get(0), "run", "()V", List.of());
                    return completionCarrier(TaintValue.oneSlot(), Type.getReturnType(m.desc));
                }
                if (name.equals("supplyAsync") && !args.isEmpty()) {
                    return completionCarrier(invokeCallback(args.get(0), "get", "()Ljava/lang/Object;", List.of()),
                            Type.getReturnType(m.desc));
                }

                TaintValue completion = completionValue(receiver);
                TaintValue failure = completionFailureValue(receiver);
                Set<Source> inheritedFailures = completionFailureSources(receiver);
                if (Set.of("thenApply", "thenApplyAsync", "thenCompose", "thenComposeAsync").contains(name)
                        && !args.isEmpty()) {
                    TaintValue result = invokeCallback(args.get(0), "apply", "(Ljava/lang/Object;)Ljava/lang/Object;", List.of(completion));
                    return completionCarrier(result, inheritedFailures, Type.getReturnType(m.desc));
                }
                if (Set.of("thenAccept", "thenAcceptAsync").contains(name) && !args.isEmpty()) {
                    invokeCallback(args.get(0), "accept", "(Ljava/lang/Object;)V", List.of(completion));
                    return completionCarrier(TaintValue.oneSlot(), inheritedFailures, Type.getReturnType(m.desc));
                }
                if (Set.of("thenRun", "thenRunAsync").contains(name) && !args.isEmpty()) {
                    invokeCallback(args.get(0), "run", "()V", List.of());
                    return completionCarrier(TaintValue.oneSlot(), inheritedFailures, Type.getReturnType(m.desc));
                }
                if (Set.of("whenComplete", "whenCompleteAsync").contains(name) && !args.isEmpty()) {
                    invokeCallback(args.get(0), "accept", "(Ljava/lang/Object;Ljava/lang/Throwable;)V",
                            List.of(completion, failure));
                    return completionCarrier(completion, inheritedFailures, Type.getReturnType(m.desc));
                }
                if (Set.of("handle", "handleAsync").contains(name) && !args.isEmpty()) {
                    TaintValue result = invokeCallback(args.get(0), "apply",
                            "(Ljava/lang/Object;Ljava/lang/Throwable;)Ljava/lang/Object;",
                            List.of(completion, failure));
                    return completionCarrier(result, Type.getReturnType(m.desc));
                }
                if (name.startsWith("exceptionally") && !args.isEmpty()) {
                    TaintValue recovered = invokeCallback(args.get(0), "apply",
                            "(Ljava/lang/Throwable;)Ljava/lang/Object;", List.of(failure));
                    return completionCarrier(mergeCallbackResult(completion, recovered), Type.getReturnType(m.desc));
                }
                if (Set.of("thenCombine", "thenCombineAsync").contains(name) && args.size() > 1) {
                    TaintValue other = completionValue(args.get(0));
                    Set<Source> failures = new TreeSet<>(inheritedFailures);
                    failures.addAll(completionFailureSources(args.get(0)));
                    TaintValue result = invokeCallback(args.get(1), "apply",
                            "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", List.of(completion, other));
                    return completionCarrier(result, failures, Type.getReturnType(m.desc));
                }
                if (Set.of("thenAcceptBoth", "thenAcceptBothAsync").contains(name) && args.size() > 1) {
                    invokeCallback(args.get(1), "accept", "(Ljava/lang/Object;Ljava/lang/Object;)V",
                            List.of(completion, completionValue(args.get(0))));
                    Set<Source> failures = new TreeSet<>(inheritedFailures);
                    failures.addAll(completionFailureSources(args.get(0)));
                    return completionCarrier(TaintValue.oneSlot(), failures, Type.getReturnType(m.desc));
                }
                if (Set.of("applyToEither", "applyToEitherAsync").contains(name) && args.size() > 1) {
                    TaintValue either = completion.merge(completionValue(args.get(0)));
                    TaintValue result = invokeCallback(args.get(1), "apply",
                            "(Ljava/lang/Object;)Ljava/lang/Object;", List.of(either));
                    Set<Source> failures = new TreeSet<>(inheritedFailures);
                    failures.addAll(completionFailureSources(args.get(0)));
                    return completionCarrier(result, failures, Type.getReturnType(m.desc));
                }
                if (Set.of("acceptEither", "acceptEitherAsync").contains(name) && args.size() > 1) {
                    TaintValue either = completion.merge(completionValue(args.get(0)));
                    invokeCallback(args.get(1), "accept", "(Ljava/lang/Object;)V", List.of(either));
                    Set<Source> failures = new TreeSet<>(inheritedFailures);
                    failures.addAll(completionFailureSources(args.get(0)));
                    return completionCarrier(TaintValue.oneSlot(), failures, Type.getReturnType(m.desc));
                }
                if (Set.of("runAfterBoth", "runAfterBothAsync", "runAfterEither", "runAfterEitherAsync").contains(name)
                        && args.size() > 1) {
                    invokeCallback(args.get(1), "run", "()V", List.of());
                    Set<Source> failures = new TreeSet<>(inheritedFailures);
                    failures.addAll(completionFailureSources(args.get(0)));
                    return completionCarrier(TaintValue.oneSlot(), failures, Type.getReturnType(m.desc));
                }
            }
            return null;
        }

        TaintValue callbackCarrier(TaintValue callback, TypeRef declaredType) {
            Set<TypeRef> types = declaredType == null ? Set.of() : Set.of(declaredType);
            return TaintValue.of(1, Set.of(), Set.of(), Set.of(), types, Set.of(), Set.of(), Set.of(), lambdaTemplates(callback));
        }

        TaintValue completionCarrier(TaintValue value, Type returnType) {
            return completionCarrier(value, value == null ? Set.of() : completionFailureSources(value), returnType);
        }

        TaintValue completionCarrier(TaintValue value, Set<Source> failures, Type returnType) {
            if (value == null) value = TaintValue.oneSlot();
            TypeRef declared = TypeRef.declared(returnType);
            Set<TypeRef> types = new TreeSet<>(value.types);
            if (declared != null) types.add(declared);
            Set<Source> contents = new TreeSet<>(directSources(value));
            contents.addAll(latentSources(value));
            contents.addAll(deepLatentSources(value));
            Set<Source> allFailures = new TreeSet<>(failures);
            allFailures.addAll(completionFailureSources(value));
            return TaintValue.ofWithCompletionFailures(1, Set.of(), contents, contents, allFailures, types,
                    Set.of(), Set.of(), Set.of(), lambdaTemplates(value));
        }

        TaintValue failedCompletionCarrier(TaintValue failure, Type returnType) {
            TypeRef declared = TypeRef.declared(returnType);
            Set<TypeRef> types = declared == null ? new TreeSet<>() : new TreeSet<>(Set.of(declared));
            Set<Source> failures = exceptionGraphSources(failure);
            return TaintValue.ofWithCompletionFailures(1, Set.of(), Set.of(), Set.of(), failures, types,
                    Set.of(), Set.of(), Set.of(), lambdaTemplates(failure));
        }

        TaintValue completionValue(TaintValue stage) {
            if (stage == null) return TaintValue.oneSlot();
            Set<Source> contents = new TreeSet<>(deepRenderSources(stage));
            return TaintValue.of(1, contents, contents, contents, Set.of(TypeRef.declaredObject("java/lang/Object")),
                    Set.of(), Set.of(), Set.of(), lambdaTemplates(stage));
        }

        TaintValue completionFailureValue(TaintValue stage) {
            Set<Source> failures = completionFailureSources(stage);
            return TaintValue.of(1, failures, failures, failures,
                    Set.of(TypeRef.declaredObject("java/lang/Throwable")), Set.of(), Set.of(), Set.of());
        }

        static boolean isExecutorOwner(String owner) {
            return owner.equals("java/util/concurrent/Executor")
                    || owner.equals("java/util/concurrent/ExecutorService")
                    || owner.endsWith("Executor") || owner.endsWith("ExecutorService");
        }

        static boolean isCompletionStageOwner(String owner) {
            return owner.equals("java/util/concurrent/CompletableFuture")
                    || owner.equals("java/util/concurrent/CompletionStage");
        }

        static boolean isThreadBuilder(String owner) {
            return owner.equals("java/lang/Thread$Builder") || owner.startsWith("java/lang/Thread$Builder$");
        }

        static boolean isRunnableType(Type[] types, int index) {
            return index >= 0 && index < types.length && types[index].getSort() == Type.OBJECT
                    && types[index].getInternalName().equals("java/lang/Runnable");
        }

        static boolean isCallableType(Type[] types, int index) {
            return index >= 0 && index < types.length && types[index].getSort() == Type.OBJECT
                    && types[index].getInternalName().equals("java/util/concurrent/Callable");
        }

        static boolean isKnownAsyncBoundary(MethodInsnNode m) {
            String owner = m.owner;
            String name = m.name;
            if (owner.equals("java/lang/Thread") && (name.equals("<init>") || name.equals("start") || name.equals("startVirtualThread"))) return true;
            if (isThreadBuilder(owner) && (name.equals("start") || name.equals("unstarted"))) return true;
            if (owner.equals("java/util/concurrent/ThreadFactory") && name.equals("newThread")) return true;
            if (isExecutorOwner(owner) && Set.of("execute", "submit", "invokeAll", "invokeAny").contains(name)) return true;
            if (owner.equals("java/util/concurrent/ScheduledExecutorService")
                    && Set.of("schedule", "scheduleAtFixedRate", "scheduleWithFixedDelay").contains(name)) return true;
            if (owner.equals("java/util/concurrent/ForkJoinPool") && Set.of("execute", "submit", "invoke").contains(name)) return true;
            if (owner.equals("java/util/concurrent/ForkJoinTask") && name.equals("adapt")) return true;
            if (isCompletionStageOwner(owner)) return true;
            return false;
        }

        TaintValue applyKnownHigherOrderCallback(MethodInsnNode m, TaintValue receiver, List<? extends TaintValue> args) {
            if (args.isEmpty()) return null;
            String owner = m.owner;
            String name = m.name;
            TaintValue element = callbackElementValue(receiver);

            if (name.equals("forEach") && Type.getArgumentTypes(m.desc).length == 1) {
                TaintValue callback = args.get(0);
                if (owner.equals("java/util/Map") || owner.endsWith("Map")) {
                    return invokeCallback(callback, "accept", "(Ljava/lang/Object;Ljava/lang/Object;)V", List.of(element, element));
                }
                return invokeCallback(callback, "accept", "(Ljava/lang/Object;)V", List.of(element));
            }
            if (Set.of("ifPresent", "ifPresentOrElse").contains(name) && owner.equals("java/util/Optional")) {
                TaintValue result = invokeCallback(args.get(0), "accept", "(Ljava/lang/Object;)V", List.of(element));
                if (name.equals("ifPresentOrElse") && args.size() > 1) {
                    TaintValue emptyBranch = invokeCallback(args.get(1), "run", "()V", List.of());
                    if (emptyBranch != null) result = result == null ? emptyBranch : result.merge(emptyBranch);
                }
                return result;
            }
            if (Set.of("removeIf", "filter").contains(name)) {
                return invokeCallback(args.get(0), "test", "(Ljava/lang/Object;)Z", List.of(element));
            }
            if (Set.of("map", "flatMap", "mapMulti").contains(name)) {
                return invokeCallback(args.get(0), "apply", "(Ljava/lang/Object;)Ljava/lang/Object;", List.of(element));
            }
            if (name.equals("peek")) {
                return invokeCallback(args.get(0), "accept", "(Ljava/lang/Object;)V", List.of(element));
            }
            if (Set.of("compute", "computeIfAbsent", "computeIfPresent", "merge", "replaceAll").contains(name)
                    && (owner.equals("java/util/Map") || owner.endsWith("Map"))) {
                TaintValue callback = args.get(args.size() - 1);
                return invokeCallback(callback, "apply", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", List.of(element, element));
            }
            return null;
        }

        TaintValue callbackElementValue(TaintValue receiver) {
            if (receiver == null) return TaintValue.oneSlot();
            Set<Source> contents = new TreeSet<>(latentSources(receiver));
            contents.addAll(deepLatentSources(receiver));
            return TaintValue.of(1, contents, contents, contents, Set.of(), Set.of(), Set.of(), Set.of());
        }

        static boolean isFunctionalInvocation(MethodInsnNode m) {
            return Set.of("run", "call", "get", "accept", "apply", "test", "invoke", "consume").contains(m.name);
        }

        static boolean isSupplierArgument(MethodInsnNode m, int argumentIndex) {
            Type[] arguments = Type.getArgumentTypes(m.desc);
            if (argumentIndex < 0 || argumentIndex >= arguments.length) return false;
            Type type = arguments[argumentIndex];
            return type.getSort() == Type.OBJECT && (type.getInternalName().equals("java/util/function/Supplier")
                    || type.getInternalName().endsWith("Supplier"));
        }

        static boolean sinkRendersReceiverContents(MethodInsnNode m) {
            String last = m.owner.substring(m.owner.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
            return m.name.equals("log") && (last.contains("eventbuilder") || last.contains("loggingeventbuilder") || last.endsWith("builder"));
        }

        boolean isKnownThrowableAccessor(MethodInsnNode m, TaintValue receiver) {
            return receiver != null && isThrowableValue(receiver, m.owner)
                    && Set.of("getMessage", "getLocalizedMessage", "toString", "getCause", "getSuppressed",
                    "addSuppressed", "initCause", "fillInStackTrace", "printStackTrace").contains(m.name);
        }

        static boolean isKnownValuePreservingCall(MethodInsnNode m) {
            Set<String> wrappers = Set.of("java/lang/Boolean", "java/lang/Byte", "java/lang/Character", "java/lang/Short",
                    "java/lang/Integer", "java/lang/Long", "java/lang/Float", "java/lang/Double");
            if (!wrappers.contains(m.owner)) return false;
            Type returnType = Type.getReturnType(m.desc);
            Type[] args = Type.getArgumentTypes(m.desc);
            if (m.name.equals("valueOf") && args.length == 1 && returnType.getSort() == Type.OBJECT
                    && returnType.getInternalName().equals(m.owner)) return true;
            return args.length == 0 && m.name.endsWith("Value")
                    && returnType.getSort() >= Type.BOOLEAN && returnType.getSort() <= Type.DOUBLE;
        }

        static boolean isStringRenderingCall(MethodInsnNode m) {
            String o = m.owner, n = m.name;
            if (o.equals("java/lang/String") && Set.of("valueOf", "format", "formatted", "join").contains(n)) return true;
            if (o.equals("java/util/Objects") && n.equals("toString")) return true;
            if ((o.equals("java/lang/StringBuilder") || o.equals("java/lang/StringBuffer") || o.equals("java/util/StringJoiner"))
                    && Set.of("append", "insert", "add", "merge", "toString").contains(n)) return true;
            if (o.equals("java/util/Arrays") && (n.equals("toString") || n.equals("deepToString"))) return true;
            if (n.equals("toString") && m.desc.equals("()Ljava/lang/String;")) return true;
            return false;
        }

        static boolean isReceiverRendered(MethodInsnNode m) {
            return m.name.equals("toString") || m.name.equals("formatted");
        }

        static boolean stringCallDeepRendersArrays(MethodInsnNode m) {
            if (m.owner.equals("java/util/Arrays") && (m.name.equals("toString") || m.name.equals("deepToString"))) return true;
            return m.owner.equals("java/lang/String") && Set.of("format", "formatted", "join").contains(m.name);
        }

        static boolean isContainerFactory(MethodInsnNode m) {
            String o = m.owner, n = m.name;
            return (Set.of("java/util/List", "java/util/Set", "java/util/Map", "java/util/Optional", "java/util/stream/Stream").contains(o)
                        && Set.of("of", "ofEntries", "copyOf", "ofNullable").contains(n))
                    || (o.equals("java/util/Arrays") && (n.equals("asList") || n.equals("stream")))
                    || (o.equals("java/util/Collections") && (n.startsWith("singleton") || n.startsWith("unmodifiable") || n.startsWith("synchronized")));
        }

        static boolean isContentMutation(MethodInsnNode m) {
            String n = m.name;
            if (Set.of("add", "addAll", "offer", "offerFirst", "offerLast", "push", "put", "putAll", "putIfAbsent",
                    "replace", "replaceAll", "set", "append", "insert", "merge", "addArgument", "addKeyValue").contains(n)) return true;
            return n.startsWith("with") && Type.getArgumentTypes(m.desc).length > 0;
        }

        static boolean shouldCaptureConstructorArgs(MethodInsnNode m, MethodKey called) {
            if (!m.name.equals("<init>")) return false;
            String o = m.owner;
            return o.equals("java/lang/StringBuilder") || o.equals("java/lang/StringBuffer") || o.equals("java/util/StringJoiner")
                    || o.equals("java/lang/Throwable")
                    || ((o.endsWith("Exception") || o.endsWith("Error")) && o.startsWith("java/"))
                    || o.startsWith("java/util/") || o.startsWith("java/io/");
        }

        static boolean isFluentReturn(MethodInsnNode m) {
            Type rt = Type.getReturnType(m.desc);
            if (rt.getSort() != Type.OBJECT) return false;
            return rt.getInternalName().equals(m.owner) || Set.of("append", "insert", "addArgument", "addKeyValue").contains(m.name);
        }

        static boolean sinkDeepRendersArrays(MethodInsnNode m) {
            if (m.name.equals("format") || m.name.equals("printf")) return true;
            String owner = m.owner;
            if (owner.equals("java/io/PrintStream") || owner.equals("java/io/PrintWriter") || owner.equals("java/io/Console")) return false;
            return isLogSink(m);
        }

        static SinkCategory sinkCategory(MethodInsnNode m) {
            if (isContextCaptureSink(m)) return SinkCategory.CONTEXT_CAPTURE;
            if (isLogSink(m)) return SinkCategory.LOG_OUTPUT;
            return null;
        }

        static boolean isContextCaptureSink(MethodInsnNode m) {
            String owner = m.owner;
            String name = m.name;

            if (owner.equals("org/slf4j/MDC")) {
                return Set.of("put", "putCloseable", "setContextMap", "pushByKey").contains(name);
            }
            if (owner.equals("org/slf4j/spi/MDCAdapter") || owner.endsWith("MDCAdapter")) {
                return Set.of("put", "setContextMap", "pushByKey").contains(name);
            }
            if (owner.equals("org/apache/logging/log4j/ThreadContext")) {
                return Set.of("put", "putIfNull", "putAll", "push", "pushAll", "setStack").contains(name);
            }
            if (owner.equals("org/apache/logging/log4j/CloseableThreadContext")
                    || owner.equals("org/apache/logging/log4j/CloseableThreadContext$Instance")) {
                return Set.of("put", "putAll", "push", "pushAll").contains(name);
            }
            if (owner.equals("org/apache/log4j/MDC")) return name.equals("put");
            if (owner.equals("org/apache/log4j/NDC")) return name.equals("push");
            if (owner.equals("org/jboss/logging/MDC") || owner.equals("org/jboss/logmanager/MDC")) {
                return name.equals("put");
            }
            if (owner.equals("org/jboss/logging/NDC") || owner.equals("org/jboss/logmanager/NDC")) {
                return name.equals("push");
            }
            if (owner.equals("org/jboss/logging/LoggerProvider")) {
                return name.equals("putMdc") || name.equals("pushNdc");
            }
            if (owner.equals("org/jboss/logmanager/ExtLogRecord")) return name.equals("putMdc");
            return false;
        }

        static boolean isLogSink(MethodInsnNode m) {
            String owner = m.owner;
            String name = m.name;
            if (owner.equals("java/io/PrintStream") || owner.equals("java/io/PrintWriter"))
                return name.startsWith("print") || name.equals("format") || name.equals("printf") || name.equals("append");
            if (owner.equals("java/io/Console")) return name.equals("format") || name.equals("printf");
            if (name.equals("printStackTrace") && (owner.equals("java/lang/Throwable") || owner.endsWith("Exception") || owner.endsWith("Error"))) return true;
            if (owner.equals("java/util/logging/Logger"))
                return Set.of("log", "logp", "logrb", "severe", "warning", "info", "config", "fine", "finer", "finest").contains(name);
            if (owner.equals("java/lang/System$Logger")) return name.equals("log");
            String lowerOwner = owner.toLowerCase(Locale.ROOT);
            String last = owner.substring(owner.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
            int dollar = last.lastIndexOf('$');
            if (dollar >= 0) last = last.substring(dollar + 1);
            boolean loggerLike = last.equals("logger") || last.equals("log") || last.contains("loggingeventbuilder")
                    || lowerOwner.contains("/logging/") || lowerOwner.contains("/log4j/") || lowerOwner.contains("/slf4j/");
            return loggerLike && Set.of("trace", "debug", "info", "warn", "warning", "error", "fatal", "log", "logIfEnabled", "printf").contains(name);
        }

        int idFor(AbstractInsnNode insn) {
            return allocationIds.computeIfAbsent(insn, ignored -> nextAllocationId++);
        }

        static Object opcodeConstant(AbstractInsnNode insn) {
            return switch (insn.getOpcode()) {
                case ICONST_M1 -> -1;
                case ICONST_0 -> 0;
                case ICONST_1 -> 1;
                case ICONST_2 -> 2;
                case ICONST_3 -> 3;
                case ICONST_4 -> 4;
                case ICONST_5 -> 5;
                case LCONST_0 -> 0L;
                case LCONST_1 -> 1L;
                case FCONST_0 -> 0.0f;
                case FCONST_1 -> 1.0f;
                case FCONST_2 -> 2.0f;
                case DCONST_0 -> 0.0d;
                case DCONST_1 -> 1.0d;
                case BIPUSH, SIPUSH -> ((IntInsnNode) insn).operand;
                default -> null;
            };
        }

        static int sizeOfConstant(AbstractInsnNode insn) {
            int op = insn.getOpcode();
            if (op == LCONST_0 || op == LCONST_1 || op == DCONST_0 || op == DCONST_1) return 2;
            if (op == LDC) {
                Object c = ((LdcInsnNode) insn).cst;
                if (c instanceof Long || c instanceof Double) return 2;
            }
            return 1;
        }

        static int primitiveLoadSize(int op) { return op == LALOAD || op == DALOAD ? 2 : 1; }

        static String primitiveArrayDescriptor(int operand) {
            return switch (operand) {
                case T_BOOLEAN -> "[Z"; case T_CHAR -> "[C"; case T_FLOAT -> "[F"; case T_DOUBLE -> "[D";
                case T_BYTE -> "[B"; case T_SHORT -> "[S"; case T_INT -> "[I"; case T_LONG -> "[J";
                default -> "[Ljava/lang/Object;";
            };
        }

        static Map<Integer, Integer> localToParamOrdinal(boolean instance, String desc) {
            Map<Integer, Integer> m = new HashMap<>();
            int local = 0, ordinal = 0;
            if (instance) m.put(local++, ordinal++);
            for (Type t : Type.getArgumentTypes(desc)) {
                m.put(local, ordinal++);
                local += t.getSize();
            }
            return m;
        }
    }

    enum SourceKind { FIELD, PARAM, RENDER_PARAM, DEEP_RENDER_PARAM, SUPPLIER_RETURN_PARAM }
    enum FlowState { UNSAFE, POSSIBLE, SANITIZED }
    enum UncertaintyReason { INLINED_SECURE_CONSTANT, UNKNOWN_METHOD_RETURN, UNKNOWN_INVOKEDYNAMIC, UNRESOLVED_DEPENDENCY, UNRESOLVED_DISPATCH_TARGET, CALLBACK_MAY_EXECUTE }

    enum SinkCategory { LOG_OUTPUT, CONTEXT_CAPTURE, ANALYSIS }

    enum ModelValueMode { DIRECT, RENDER, DEEP }
    enum ModelSelectorKind { RECEIVER, ARG }

    static final class ModelValueSelector {
        final ModelSelectorKind kind;
        final int argumentIndex;

        private ModelValueSelector(ModelSelectorKind kind, int argumentIndex) {
            this.kind = Objects.requireNonNull(kind, "kind");
            this.argumentIndex = argumentIndex;
        }

        static ModelValueSelector receiver() { return new ModelValueSelector(ModelSelectorKind.RECEIVER, -1); }
        static ModelValueSelector argument(int index) { return new ModelValueSelector(ModelSelectorKind.ARG, index); }

        @Override public String toString() { return kind == ModelSelectorKind.RECEIVER ? "receiver" : "arg" + argumentIndex; }
    }

    static final class SinkMethodModel {
        final MethodKey method;
        final SinkCategory category;
        final List<ModelValueSelector> values;
        final ModelValueMode mode;
        final String source;

        SinkMethodModel(MethodKey method, SinkCategory category, List<ModelValueSelector> values,
                        ModelValueMode mode, String source) {
            this.method = method; this.category = category; this.values = List.copyOf(values);
            this.mode = mode; this.source = source;
        }
    }

    static final class RendererMethodModel {
        final MethodKey method;
        final List<ModelValueSelector> values;
        final ModelValueMode mode;
        final String source;

        RendererMethodModel(MethodKey method, List<ModelValueSelector> values, ModelValueMode mode, String source) {
            this.method = method; this.values = List.copyOf(values); this.mode = mode; this.source = source;
        }
    }

    static final class CallbackMethodModel {
        final MethodKey method;
        final ModelValueSelector target;
        final String invocationName;
        final String invocationDesc;
        final List<ModelValueSelector> arguments;
        final String source;

        CallbackMethodModel(MethodKey method, ModelValueSelector target, String invocationName,
                            String invocationDesc, List<ModelValueSelector> arguments, String source) {
            this.method = method; this.target = target; this.invocationName = invocationName;
            this.invocationDesc = invocationDesc; this.arguments = List.copyOf(arguments); this.source = source;
        }
    }

    static final class MutationMethodModel {
        final MethodKey method;
        final ModelValueSelector target;
        final List<ModelValueSelector> values;
        final ModelValueMode mode;
        final String source;

        MutationMethodModel(MethodKey method, ModelValueSelector target, List<ModelValueSelector> values,
                            ModelValueMode mode, String source) {
            this.method = method; this.target = target; this.values = List.copyOf(values);
            this.mode = mode; this.source = source;
        }
    }

    static final class MethodModelRegistry {
        final Map<MethodKey, List<SinkMethodModel>> sinks = new LinkedHashMap<>();
        final Map<MethodKey, RendererMethodModel> renderers = new LinkedHashMap<>();
        final Map<MethodKey, List<CallbackMethodModel>> callbacks = new LinkedHashMap<>();
        final Map<MethodKey, List<MutationMethodModel>> mutations = new LinkedHashMap<>();
        final List<String> descriptions = new ArrayList<>();

        void load(Path path, ScanModel model) throws IOException {
            if (!Files.isRegularFile(path)) throw new IOException("Not a readable model file: " + path);
            List<String> lines = Files.readAllLines(path);
            for (int i = 0; i < lines.size(); i++) {
                String location = path + ":" + (i + 1);
                try {
                    parseLine(lines.get(i), location, model);
                } catch (IllegalArgumentException ex) {
                    model.addFinding(Finding.incomplete("Invalid method model at " + location + ": " + ex.getMessage()));
                }
            }
        }

        void parseLine(String line, String source, ScanModel model) {
            List<String> tokens = tokenize(line);
            if (tokens.isEmpty()) return;
            String kind = tokens.get(0).toLowerCase(Locale.ROOT);
            switch (kind) {
                case "sink" -> parseSink(tokens, source);
                case "renderer" -> parseRenderer(tokens, source);
                case "callback" -> parseCallback(tokens, source);
                case "mutation" -> parseMutation(tokens, source);
                case "sanitizer" -> parseSanitizer(tokens, source, model);
                default -> throw new IllegalArgumentException("Unknown rule kind '" + tokens.get(0) + "'");
            }
        }

        void parseSink(List<String> tokens, String source) {
            if (tokens.size() < 4) throw new IllegalArgumentException("sink requires category, method, and values");
            SinkCategory category;
            try { category = SinkCategory.valueOf(tokens.get(1).toUpperCase(Locale.ROOT)); }
            catch (IllegalArgumentException ex) { throw new IllegalArgumentException("Unknown sink category '" + tokens.get(1) + "'"); }
            if (category == SinkCategory.ANALYSIS) throw new IllegalArgumentException("ANALYSIS is not a callable sink category");
            MethodKey method = parseMethod(tokens.get(2));
            Map<String, String> options = options(tokens, 3);
            List<ModelValueSelector> values = selectors(required(options, "values"), method, true);
            ModelValueMode mode = mode(options.getOrDefault("mode", "deep"));
            rejectUnknown(options, Set.of("values", "mode"));
            sinks.computeIfAbsent(method, ignored -> new ArrayList<>())
                    .add(new SinkMethodModel(method, category, values, mode, source));
            descriptions.add("sink " + category + " " + method + " values=" + values + " mode=" + mode + " (" + source + ")");
        }

        void parseRenderer(List<String> tokens, String source) {
            if (tokens.size() < 3) throw new IllegalArgumentException("renderer requires method and values");
            MethodKey method = parseMethod(tokens.get(1));
            if (Type.getReturnType(method.desc) == Type.VOID_TYPE) throw new IllegalArgumentException("renderer method must return a value");
            Map<String, String> options = options(tokens, 2);
            List<ModelValueSelector> values = selectors(required(options, "values"), method, true);
            ModelValueMode mode = mode(options.getOrDefault("mode", "deep"));
            rejectUnknown(options, Set.of("values", "mode"));
            RendererMethodModel prior = renderers.putIfAbsent(method, new RendererMethodModel(method, values, mode, source));
            if (prior != null) throw new IllegalArgumentException("Duplicate renderer model for " + method);
            descriptions.add("renderer " + method + " values=" + values + " mode=" + mode + " (" + source + ")");
        }

        void parseCallback(List<String> tokens, String source) {
            if (tokens.size() < 4) throw new IllegalArgumentException("callback requires method, target, and invoke");
            MethodKey method = parseMethod(tokens.get(1));
            Map<String, String> options = options(tokens, 2);
            ModelValueSelector target = singleSelector(required(options, "target"), method);
            String invocation = required(options, "invoke");
            int descriptorStart = invocation.indexOf('(');
            if (descriptorStart <= 0) throw new IllegalArgumentException("invoke must be name(descriptor), got " + invocation);
            String invocationName = invocation.substring(0, descriptorStart);
            String invocationDesc = invocation.substring(descriptorStart);
            validateMethodDescriptor(invocationDesc);
            List<ModelValueSelector> arguments = selectors(options.getOrDefault("values", "none"), method, true);
            if (Type.getArgumentTypes(invocationDesc).length != arguments.size()) {
                throw new IllegalArgumentException("callback invoke descriptor expects "
                        + Type.getArgumentTypes(invocationDesc).length + " arguments but values selects " + arguments.size());
            }
            rejectUnknown(options, Set.of("target", "invoke", "values"));
            callbacks.computeIfAbsent(method, ignored -> new ArrayList<>())
                    .add(new CallbackMethodModel(method, target, invocationName, invocationDesc, arguments, source));
            descriptions.add("callback " + method + " target=" + target + " invoke=" + invocationName + invocationDesc
                    + " values=" + arguments + " (" + source + ")");
        }

        void parseMutation(List<String> tokens, String source) {
            if (tokens.size() < 4) throw new IllegalArgumentException("mutation requires method, target, and values");
            MethodKey method = parseMethod(tokens.get(1));
            Map<String, String> options = options(tokens, 2);
            ModelValueSelector target = singleSelector(required(options, "target"), method);
            List<ModelValueSelector> values = selectors(required(options, "values"), method, true);
            ModelValueMode mode = mode(options.getOrDefault("mode", "deep"));
            rejectUnknown(options, Set.of("target", "values", "mode"));
            mutations.computeIfAbsent(method, ignored -> new ArrayList<>())
                    .add(new MutationMethodModel(method, target, values, mode, source));
            descriptions.add("mutation " + method + " target=" + target + " values=" + values
                    + " mode=" + mode + " (" + source + ")");
        }

        void parseSanitizer(List<String> tokens, String source, ScanModel model) {
            if (tokens.size() < 2) throw new IllegalArgumentException("sanitizer requires method");
            MethodKey method = parseMethod(tokens.get(1));
            if (Type.getReturnType(method.desc) == Type.VOID_TYPE) throw new IllegalArgumentException("sanitizer method must return a value");
            Map<String, String> options = options(tokens, 2);
            String description = options.getOrDefault("description", "");
            String justification = options.getOrDefault("justification", "");
            rejectUnknown(options, Set.of("description", "justification"));
            SanitizerInfo info = new SanitizerInfo(method, description, justification);
            SanitizerInfo prior = model.sanitizers.putIfAbsent(method, info);
            if (prior != null && !prior.equals(info)) throw new IllegalArgumentException("Conflicting sanitizer metadata for " + method);
            descriptions.add("sanitizer " + method + " (" + source + ")");
        }

        List<SinkMethodModel> sinks(MethodKey method) { return sinks.getOrDefault(method, List.of()); }
        RendererMethodModel renderer(MethodKey method) { return renderers.get(method); }
        List<CallbackMethodModel> callbacks(MethodKey method) { return callbacks.getOrDefault(method, List.of()); }
        List<MutationMethodModel> mutations(MethodKey method) { return mutations.getOrDefault(method, List.of()); }
        int size() { return descriptions.size(); }

        static MethodKey parseMethod(String spec) {
            int separator = spec.indexOf("::");
            int descriptorStart = spec.indexOf('(', separator + 2);
            if (separator <= 0 || descriptorStart <= separator + 2) {
                throw new IllegalArgumentException("Method must be owner::name(descriptor), got " + spec);
            }
            String owner = spec.substring(0, separator).replace('.', '/');
            String name = spec.substring(separator + 2, descriptorStart);
            String desc = spec.substring(descriptorStart);
            if (owner.isBlank() || name.isBlank()) throw new IllegalArgumentException("Invalid method " + spec);
            validateMethodDescriptor(desc);
            return new MethodKey(owner, name, desc);
        }

        static void validateMethodDescriptor(String desc) {
            try { Type.getMethodType(desc); }
            catch (IllegalArgumentException ex) { throw new IllegalArgumentException("Invalid JVM method descriptor " + desc); }
        }

        static Map<String, String> options(List<String> tokens, int start) {
            Map<String, String> out = new LinkedHashMap<>();
            for (int i = start; i < tokens.size(); i++) {
                String token = tokens.get(i);
                int equals = token.indexOf('=');
                if (equals <= 0) throw new IllegalArgumentException("Expected key=value option, got " + token);
                String key = token.substring(0, equals).toLowerCase(Locale.ROOT);
                String value = token.substring(equals + 1);
                if (out.putIfAbsent(key, value) != null) throw new IllegalArgumentException("Duplicate option " + key);
            }
            return out;
        }

        static String required(Map<String, String> options, String key) {
            String value = options.get(key);
            if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing " + key + " option");
            return value;
        }

        static void rejectUnknown(Map<String, String> options, Set<String> allowed) {
            for (String key : options.keySet()) if (!allowed.contains(key)) throw new IllegalArgumentException("Unknown option " + key);
        }

        static ModelValueMode mode(String text) {
            try { return ModelValueMode.valueOf(text.toUpperCase(Locale.ROOT)); }
            catch (IllegalArgumentException ex) { throw new IllegalArgumentException("Unknown mode '" + text + "' (use direct, render, or deep)"); }
        }

        static ModelValueSelector singleSelector(String text, MethodKey method) {
            List<ModelValueSelector> selectors = selectors(text, method, false);
            if (selectors.size() != 1) throw new IllegalArgumentException("Expected one selector, got " + text);
            return selectors.get(0);
        }

        static List<ModelValueSelector> selectors(String text, MethodKey method, boolean allowNone) {
            String normalized = text.trim();
            if (normalized.equalsIgnoreCase("none")) {
                if (!allowNone) throw new IllegalArgumentException("none is not valid here");
                return List.of();
            }
            List<ModelValueSelector> out = new ArrayList<>();
            int argumentCount = Type.getArgumentTypes(method.desc).length;
            for (String raw : normalized.split(",")) {
                String selector = raw.trim().toLowerCase(Locale.ROOT);
                if (selector.equals("receiver")) out.add(ModelValueSelector.receiver());
                else if (selector.equals("allargs") || selector.equals("args")) {
                    for (int i = 0; i < argumentCount; i++) out.add(ModelValueSelector.argument(i));
                } else if (selector.startsWith("arg")) {
                    int index;
                    try { index = Integer.parseInt(selector.substring(3)); }
                    catch (NumberFormatException ex) { throw new IllegalArgumentException("Invalid selector " + raw); }
                    if (index < 0 || index >= argumentCount) throw new IllegalArgumentException("Selector " + raw
                            + " is outside method argument range 0.." + Math.max(0, argumentCount - 1));
                    out.add(ModelValueSelector.argument(index));
                } else throw new IllegalArgumentException("Unknown selector " + raw);
            }
            if (out.isEmpty() && !allowNone) throw new IllegalArgumentException("At least one selector is required");
            return List.copyOf(out);
        }

        static List<String> tokenize(String line) {
            List<String> out = new ArrayList<>();
            StringBuilder token = new StringBuilder();
            boolean quoted = false;
            char quote = 0;
            boolean escaped = false;
            for (int i = 0; i < line.length(); i++) {
                char c = line.charAt(i);
                if (escaped) { token.append(c); escaped = false; continue; }
                if (c == '\\') { escaped = true; continue; }
                if (quoted) {
                    if (c == quote) quoted = false;
                    else token.append(c);
                    continue;
                }
                if (c == '\'' || c == '"') { quoted = true; quote = c; continue; }
                if (c == '#') break;
                if (Character.isWhitespace(c)) {
                    if (token.length() > 0) { out.add(token.toString()); token.setLength(0); }
                } else token.append(c);
            }
            if (escaped) token.append('\\');
            if (quoted) throw new IllegalArgumentException("Unterminated quoted value");
            if (token.length() > 0) out.add(token.toString());
            return out;
        }
    }

    static final class SuppressionInfo implements Comparable<SuppressionInfo> {
        final String reason;
        final String ticket;
        final String expires;
        final String declaredAt;

        SuppressionInfo(String reason, String ticket, String expires, String declaredAt) {
            this.reason = reason == null ? "" : reason;
            this.ticket = ticket == null ? "" : ticket;
            this.expires = expires == null ? "" : expires;
            this.declaredAt = declaredAt == null ? "" : declaredAt;
        }

        @Override public int compareTo(SuppressionInfo other) {
            int c = declaredAt.compareTo(other.declaredAt); if (c != 0) return c;
            c = reason.compareTo(other.reason); if (c != 0) return c;
            c = ticket.compareTo(other.ticket); if (c != 0) return c;
            return expires.compareTo(other.expires);
        }
        @Override public boolean equals(Object other) { return other instanceof SuppressionInfo s && compareTo(s) == 0; }
        @Override public int hashCode() { return Objects.hash(reason, ticket, expires, declaredAt); }
    }

    static final class SanitizerInfo implements Comparable<SanitizerInfo> {
        final MethodKey method;
        final String description;
        final String justification;

        SanitizerInfo(MethodKey method, String description, String justification) {
            this.method = Objects.requireNonNull(method, "method");
            this.description = description == null ? "" : description;
            this.justification = justification == null ? "" : justification;
        }

        @Override public boolean equals(Object o) {
            return o instanceof SanitizerInfo i && method.equals(i.method)
                    && description.equals(i.description) && justification.equals(i.justification);
        }
        @Override public int hashCode() { return Objects.hash(method, description, justification); }
        @Override public int compareTo(SanitizerInfo o) {
            int c = method.toString().compareTo(o.method.toString()); if (c != 0) return c;
            c = description.compareTo(o.description); if (c != 0) return c;
            return justification.compareTo(o.justification);
        }
        @Override public String toString() { return method.toString(); }
    }

    static final class Source implements Comparable<Source> {
        final SourceKind kind;
        final FieldKey field;
        final int paramOrdinal;
        final FlowState state;
        final SanitizerInfo sanitizer;
        final Set<UncertaintyReason> uncertainties;

        private Source(SourceKind kind, FieldKey field, int paramOrdinal, FlowState state, SanitizerInfo sanitizer,
                       Set<UncertaintyReason> uncertainties) {
            this.kind = kind;
            this.field = field;
            this.paramOrdinal = paramOrdinal;
            this.state = state;
            this.sanitizer = sanitizer;
            this.uncertainties = Collections.unmodifiableSet(new TreeSet<>(uncertainties));
        }

        static Source field(FieldKey f) { return new Source(SourceKind.FIELD, f, -1, FlowState.UNSAFE, null, Set.of()); }
        static Source possibleField(FieldKey f) { return new Source(SourceKind.FIELD, f, -1, FlowState.POSSIBLE, null,
                Set.of(UncertaintyReason.INLINED_SECURE_CONSTANT)); }
        static Source param(int ordinal) { return new Source(SourceKind.PARAM, null, ordinal, FlowState.UNSAFE, null, Set.of()); }
        static Source renderParam(int ordinal, Source source) {
            return new Source(SourceKind.RENDER_PARAM, null, ordinal, source.state, source.sanitizer, source.uncertainties);
        }
        static Source deepRenderParam(int ordinal, Source source) {
            return new Source(SourceKind.DEEP_RENDER_PARAM, null, ordinal, source.state, source.sanitizer, source.uncertainties);
        }
        static Source supplierReturnParam(int ordinal, Source source) {
            return new Source(SourceKind.SUPPLIER_RETURN_PARAM, null, ordinal, source.state, source.sanitizer, source.uncertainties);
        }

        Source possible(Set<UncertaintyReason> reasons) {
            if (state == FlowState.SANITIZED) return this;
            Set<UncertaintyReason> combined = new TreeSet<>(uncertainties);
            combined.addAll(reasons);
            return new Source(kind, field, paramOrdinal, FlowState.POSSIBLE, null, combined);
        }

        Source sanitized(SanitizerInfo info) {
            return new Source(kind, field, paramOrdinal, FlowState.SANITIZED, Objects.requireNonNull(info, "info"), Set.of());
        }

        String originKey() {
            return kind == SourceKind.FIELD ? "F:" + field : "P:" + kind + ":" + paramOrdinal;
        }

        static Set<Source> fieldsOnly(Set<Source> in) {
            Set<Source> out = new TreeSet<>();
            for (Source s : in) if (s.kind == SourceKind.FIELD) out.add(s);
            return out;
        }

        static Set<Source> paramsOnly(Set<Source> in) {
            Set<Source> out = new TreeSet<>();
            for (Source s : in) if (s.kind != SourceKind.FIELD) out.add(s);
            return out;
        }

        static Set<Source> withState(Set<Source> in, FlowState state) {
            Set<Source> out = new TreeSet<>();
            for (Source s : in) if (s.state == state) out.add(s);
            return out;
        }

        static Set<FieldKey> toFields(Set<Source> in) {
            Set<FieldKey> out = new TreeSet<>();
            for (Source s : in) if (s.kind == SourceKind.FIELD) out.add(s.field);
            return out;
        }

        static Set<SanitizerInfo> sanitizers(Set<Source> in) {
            Set<SanitizerInfo> out = new TreeSet<>();
            for (Source s : in) if (s.sanitizer != null) out.add(s.sanitizer);
            return out;
        }

        static Set<UncertaintyReason> uncertainties(Set<Source> in) {
            Set<UncertaintyReason> out = new TreeSet<>();
            for (Source s : in) out.addAll(s.uncertainties);
            return out;
        }

        @Override public boolean equals(Object o) {
            return o instanceof Source s && kind == s.kind && Objects.equals(field, s.field)
                    && paramOrdinal == s.paramOrdinal && state == s.state && Objects.equals(sanitizer, s.sanitizer)
                    && uncertainties.equals(s.uncertainties);
        }
        @Override public int hashCode() { return Objects.hash(kind, field, paramOrdinal, state, sanitizer, uncertainties); }
        @Override public int compareTo(Source o) {
            int c = kind.compareTo(o.kind); if (c != 0) return c;
            if (kind == SourceKind.FIELD) c = field.compareTo(o.field);
            else c = Integer.compare(paramOrdinal, o.paramOrdinal);
            if (c != 0) return c;
            c = state.compareTo(o.state); if (c != 0) return c;
            if (sanitizer == null && o.sanitizer != null) return -1;
            if (sanitizer != null && o.sanitizer == null) return 1;
            if (sanitizer != null) {
                c = sanitizer.compareTo(o.sanitizer);
                if (c != 0) return c;
            }
            return uncertainties.toString().compareTo(o.uncertainties.toString());
        }
        @Override public String toString() {
            String base;
            if (kind == SourceKind.FIELD) base = field.javaName();
            else if (kind == SourceKind.PARAM) base = "param#" + paramOrdinal;
            else if (kind == SourceKind.RENDER_PARAM) base = "render(param#" + paramOrdinal + ")";
            else if (kind == SourceKind.DEEP_RENDER_PARAM) base = "deep-render(param#" + paramOrdinal + ")";
            else base = "supplier-return(param#" + paramOrdinal + ")";
            if (state == FlowState.SANITIZED) return "sanitized(" + base + " via " + sanitizer + ")";
            if (state == FlowState.POSSIBLE) return "possible(" + base + " because " + uncertainties + ")";
            return base;
        }
    }

    static final class TypeRef implements Comparable<TypeRef> {
        final String name;
        final boolean array;
        final boolean exact;

        TypeRef(String name, boolean array, boolean exact) { this.name = name; this.array = array; this.exact = exact; }

        static TypeRef declared(Type t) {
            if (t == null) return null;
            if (t.getSort() == Type.OBJECT) return new TypeRef(t.getInternalName(), false, false);
            if (t.getSort() == Type.ARRAY) return new TypeRef(t.getDescriptor(), true, false);
            return null;
        }
        static TypeRef declaredObject(String internalName) { return new TypeRef(internalName, false, false); }
        static TypeRef exact(String internalName) { return new TypeRef(internalName, false, true); }
        static TypeRef exactArray(String descriptor) { return new TypeRef(descriptor, true, true); }

        @Override public boolean equals(Object o) { return o instanceof TypeRef t && name.equals(t.name) && array == t.array && exact == t.exact; }
        @Override public int hashCode() { return Objects.hash(name, array, exact); }
        @Override public int compareTo(TypeRef o) {
            int c = name.compareTo(o.name); if (c != 0) return c;
            c = Boolean.compare(array, o.array); if (c != 0) return c;
            return Boolean.compare(exact, o.exact);
        }
        @Override public String toString() { return (exact ? "=" : "~") + name; }
    }

    static final class TaintValue implements Value {
        final int size;
        final Set<Source> directSources;
        final Set<Source> renderSources;
        final Set<Source> deepRenderSources;
        final Set<Source> completionFailureSources;
        final Set<TypeRef> types;
        final Set<Integer> objectIds;
        final Set<Integer> arrayIds;
        final Set<FieldKey> origins;
        final Set<LambdaTemplate> lambdas;
        final Set<String> stringConstants;

        TaintValue(int size, Set<Source> directSources, Set<Source> renderSources, Set<Source> deepRenderSources,
                   Set<Source> completionFailureSources, Set<TypeRef> types, Set<Integer> objectIds,
                   Set<Integer> arrayIds, Set<FieldKey> origins, Set<LambdaTemplate> lambdas,
                   Set<String> stringConstants) {
            this.size = Math.max(1, size);
            this.directSources = immutableSorted(directSources);
            this.renderSources = immutableSorted(renderSources);
            this.deepRenderSources = immutableSorted(deepRenderSources);
            this.completionFailureSources = immutableSorted(completionFailureSources);
            this.types = immutableSorted(types);
            this.objectIds = immutableSorted(objectIds);
            this.arrayIds = immutableSorted(arrayIds);
            this.origins = immutableSorted(origins);
            this.lambdas = immutableSorted(lambdas);
            this.stringConstants = immutableSorted(stringConstants);
        }

        static <T extends Comparable<? super T>> Set<T> immutableSorted(Set<T> input) {
            return Collections.unmodifiableSet(new TreeSet<>(input));
        }

        static TaintValue empty(int size) {
            return new TaintValue(size, Set.of(), Set.of(), Set.of(), Set.of(), Set.of(), Set.of(), Set.of(),
                    Set.of(), Set.of(), Set.of());
        }

        static TaintValue oneSlot() { return empty(1); }

        static TaintValue of(int size, Set<Source> direct, Set<Source> render, Set<Source> deepRender,
                             Set<TypeRef> types, Set<Integer> objectIds, Set<Integer> arrayIds,
                             Set<FieldKey> origins) {
            return new TaintValue(size, direct, render, deepRender, Set.of(), types, objectIds, arrayIds,
                    origins, Set.of(), Set.of());
        }

        static TaintValue of(int size, Set<Source> direct, Set<Source> render, Set<Source> deepRender,
                             Set<TypeRef> types, Set<Integer> objectIds, Set<Integer> arrayIds,
                             Set<FieldKey> origins, Set<LambdaTemplate> lambdas) {
            return new TaintValue(size, direct, render, deepRender, Set.of(), types, objectIds, arrayIds,
                    origins, lambdas, Set.of());
        }

        static TaintValue ofWithCompletionFailures(int size, Set<Source> direct, Set<Source> render,
                                                    Set<Source> deepRender, Set<Source> completionFailures,
                                                    Set<TypeRef> types, Set<Integer> objectIds,
                                                    Set<Integer> arrayIds, Set<FieldKey> origins,
                                                    Set<LambdaTemplate> lambdas) {
            return new TaintValue(size, direct, render, deepRender, completionFailures, types, objectIds,
                    arrayIds, origins, lambdas, Set.of());
        }

        TaintValue withDirect(Source source) {
            Set<Source> next = new TreeSet<>(directSources);
            next.add(source);
            return copy(next, renderSources, deepRenderSources, completionFailureSources, types, objectIds,
                    arrayIds, origins, lambdas, stringConstants);
        }

        TaintValue withType(TypeRef type) {
            if (type == null) return this;
            Set<TypeRef> next = new TreeSet<>(types);
            next.add(type);
            return copy(directSources, renderSources, deepRenderSources, completionFailureSources, next,
                    objectIds, arrayIds, origins, lambdas, stringConstants);
        }

        TaintValue withObjectId(int id) {
            Set<Integer> next = new TreeSet<>(objectIds);
            next.add(id);
            return copy(directSources, renderSources, deepRenderSources, completionFailureSources, types,
                    next, arrayIds, origins, lambdas, stringConstants);
        }

        TaintValue withArrayId(int id) {
            Set<Integer> next = new TreeSet<>(arrayIds);
            next.add(id);
            return copy(directSources, renderSources, deepRenderSources, completionFailureSources, types,
                    objectIds, next, origins, lambdas, stringConstants);
        }

        TaintValue withLambda(LambdaTemplate lambda) {
            Set<LambdaTemplate> next = new TreeSet<>(lambdas);
            next.add(lambda);
            return copy(directSources, renderSources, deepRenderSources, completionFailureSources, types,
                    objectIds, arrayIds, origins, next, stringConstants);
        }

        TaintValue withLambdas(Set<LambdaTemplate> values) {
            Set<LambdaTemplate> next = new TreeSet<>(lambdas);
            next.addAll(values);
            return copy(directSources, renderSources, deepRenderSources, completionFailureSources, types,
                    objectIds, arrayIds, origins, next, stringConstants);
        }

        TaintValue withStringConstant(String value) {
            Set<String> next = new TreeSet<>(stringConstants);
            next.add(value);
            return copy(directSources, renderSources, deepRenderSources, completionFailureSources, types,
                    objectIds, arrayIds, origins, lambdas, next);
        }

        TaintValue withCompletionFailures(Set<Source> failures) {
            Set<Source> next = new TreeSet<>(completionFailureSources);
            next.addAll(failures);
            return copy(directSources, renderSources, deepRenderSources, next, types, objectIds, arrayIds,
                    origins, lambdas, stringConstants);
        }

        TaintValue copy(Set<Source> direct, Set<Source> render, Set<Source> deepRender,
                        Set<Source> completionFailures, Set<TypeRef> nextTypes, Set<Integer> objects,
                        Set<Integer> arrays, Set<FieldKey> nextOrigins, Set<LambdaTemplate> lambdaValues,
                        Set<String> constants) {
            return new TaintValue(size, direct, render, deepRender, completionFailures, nextTypes, objects,
                    arrays, nextOrigins, lambdaValues, constants);
        }

        TaintValue merge(TaintValue other) {
            if (other == null) return this;
            if (equals(other)) return this;
            return new TaintValue(Math.max(size, other.size), union(directSources, other.directSources),
                    union(renderSources, other.renderSources), union(deepRenderSources, other.deepRenderSources),
                    union(completionFailureSources, other.completionFailureSources), union(types, other.types),
                    union(objectIds, other.objectIds), union(arrayIds, other.arrayIds), union(origins, other.origins),
                    union(lambdas, other.lambdas), union(stringConstants, other.stringConstants));
        }

        static <T extends Comparable<? super T>> Set<T> union(Set<T> first, Set<T> second) {
            Set<T> merged = new TreeSet<>(first);
            merged.addAll(second);
            return merged;
        }

        @Override public int getSize() { return size; }

        @Override public boolean equals(Object other) {
            return other instanceof TaintValue value && size == value.size
                    && directSources.equals(value.directSources)
                    && renderSources.equals(value.renderSources)
                    && deepRenderSources.equals(value.deepRenderSources)
                    && completionFailureSources.equals(value.completionFailureSources)
                    && types.equals(value.types) && objectIds.equals(value.objectIds)
                    && arrayIds.equals(value.arrayIds) && origins.equals(value.origins)
                    && lambdas.equals(value.lambdas) && stringConstants.equals(value.stringConstants);
        }

        @Override public int hashCode() {
            return Objects.hash(size, directSources, renderSources, deepRenderSources,
                    completionFailureSources, types, objectIds, arrayIds, origins, lambdas, stringConstants);
        }

        @Override public String toString() {
            return "direct=" + directSources + ",render=" + renderSources + ",deep=" + deepRenderSources
                    + ",fail=" + completionFailureSources + ",types=" + types + ",lambdas=" + lambdas
                    + ",strings=" + stringConstants;
        }
    }

    static final class ValueTemplate implements Comparable<ValueTemplate> {
        final int size;
        final Set<Source> directSources, renderSources, deepRenderSources, completionFailureSources;
        final Set<TypeRef> types;
        final Set<LambdaTemplate> lambdas;

        ValueTemplate(int size, Set<Source> directSources, Set<Source> renderSources,
                      Set<Source> deepRenderSources, Set<Source> completionFailureSources,
                      Set<TypeRef> types, Set<LambdaTemplate> lambdas) {
            this.size = Math.max(1, size);
            this.directSources = Collections.unmodifiableSet(new TreeSet<>(directSources));
            this.renderSources = Collections.unmodifiableSet(new TreeSet<>(renderSources));
            this.deepRenderSources = Collections.unmodifiableSet(new TreeSet<>(deepRenderSources));
            this.completionFailureSources = Collections.unmodifiableSet(new TreeSet<>(completionFailureSources));
            this.types = Collections.unmodifiableSet(new TreeSet<>(types));
            this.lambdas = Collections.unmodifiableSet(new TreeSet<>(lambdas));
        }

        @Override public boolean equals(Object other) {
            return other instanceof ValueTemplate value && size == value.size
                    && directSources.equals(value.directSources)
                    && renderSources.equals(value.renderSources)
                    && deepRenderSources.equals(value.deepRenderSources)
                    && completionFailureSources.equals(value.completionFailureSources)
                    && types.equals(value.types) && lambdas.equals(value.lambdas);
        }

        @Override public int hashCode() {
            return Objects.hash(size, directSources, renderSources, deepRenderSources,
                    completionFailureSources, types, lambdas);
        }

        @Override public int compareTo(ValueTemplate other) {
            int comparison = Integer.compare(size, other.size); if (comparison != 0) return comparison;
            comparison = directSources.toString().compareTo(other.directSources.toString()); if (comparison != 0) return comparison;
            comparison = renderSources.toString().compareTo(other.renderSources.toString()); if (comparison != 0) return comparison;
            comparison = deepRenderSources.toString().compareTo(other.deepRenderSources.toString()); if (comparison != 0) return comparison;
            comparison = completionFailureSources.toString().compareTo(other.completionFailureSources.toString()); if (comparison != 0) return comparison;
            comparison = types.toString().compareTo(other.types.toString()); if (comparison != 0) return comparison;
            return lambdas.toString().compareTo(other.lambdas.toString());
        }

        @Override public String toString() {
            return "value(" + directSources + "," + renderSources + "," + deepRenderSources
                    + ",fail=" + completionFailureSources + "," + types + "," + lambdas + ")";
        }
    }

    static final class LambdaTemplate implements Comparable<LambdaTemplate> {
        final int handleTag;
        final MethodKey implementation;
        final List<ValueTemplate> captures;

        LambdaTemplate(int handleTag, MethodKey implementation, List<ValueTemplate> captures) {
            this.handleTag = handleTag;
            this.implementation = implementation;
            this.captures = List.copyOf(captures);
        }

        @Override public boolean equals(Object o) {
            return o instanceof LambdaTemplate l && handleTag == l.handleTag && implementation.equals(l.implementation) && captures.equals(l.captures);
        }
        @Override public int hashCode() { return Objects.hash(handleTag, implementation, captures); }
        @Override public int compareTo(LambdaTemplate o) {
            int c = implementation.toString().compareTo(o.implementation.toString()); if (c != 0) return c;
            c = Integer.compare(handleTag, o.handleTag); if (c != 0) return c;
            return captures.toString().compareTo(o.captures.toString());
        }
        @Override public String toString() { return implementation + "#" + handleTag + captures; }
    }

    static final class CallbackSummary implements Comparable<CallbackSummary> {
        final int targetParamOrdinal;
        final String methodName, methodDesc;
        final List<ValueTemplate> arguments;

        CallbackSummary(int targetParamOrdinal, String methodName, String methodDesc, List<ValueTemplate> arguments) {
            this.targetParamOrdinal = targetParamOrdinal;
            this.methodName = methodName;
            this.methodDesc = methodDesc;
            this.arguments = List.copyOf(arguments);
        }

        @Override public boolean equals(Object o) {
            return o instanceof CallbackSummary c && targetParamOrdinal == c.targetParamOrdinal
                    && methodName.equals(c.methodName) && methodDesc.equals(c.methodDesc) && arguments.equals(c.arguments);
        }
        @Override public int hashCode() { return Objects.hash(targetParamOrdinal, methodName, methodDesc, arguments); }
        @Override public int compareTo(CallbackSummary o) {
            int c = Integer.compare(targetParamOrdinal, o.targetParamOrdinal); if (c != 0) return c;
            c = methodName.compareTo(o.methodName); if (c != 0) return c;
            c = methodDesc.compareTo(o.methodDesc); if (c != 0) return c;
            return arguments.toString().compareTo(o.arguments.toString());
        }
    }

    static final class FieldKey implements Comparable<FieldKey> {
        final String owner, name, desc;
        FieldKey(String owner, String name, String desc) { this.owner = owner; this.name = name; this.desc = desc; }
        String javaName() { return owner.replace('/', '.') + "." + name + ":" + desc; }
        @Override public boolean equals(Object o) { return o instanceof FieldKey f && owner.equals(f.owner) && name.equals(f.name) && desc.equals(f.desc); }
        @Override public int hashCode() { return Objects.hash(owner, name, desc); }
        @Override public int compareTo(FieldKey o) {
            int c = owner.compareTo(o.owner); if (c != 0) return c;
            c = name.compareTo(o.name); if (c != 0) return c;
            return desc.compareTo(o.desc);
        }
        @Override public String toString() { return javaName(); }
    }

    static final class MethodKey {
        final String owner, name, desc;
        MethodKey(String owner, String name, String desc) { this.owner = owner; this.name = name; this.desc = desc; }
        static MethodKey of(ClassNode cn, MethodNode mn) { return new MethodKey(cn.name, mn.name, mn.desc); }
        @Override public boolean equals(Object o) { return o instanceof MethodKey m && owner.equals(m.owner) && name.equals(m.name) && desc.equals(m.desc); }
        @Override public int hashCode() { return Objects.hash(owner, name, desc); }
        @Override public String toString() { return owner.replace('/', '.') + "." + name + desc; }
    }

    static final class CalleeResolution {
        final MethodSummary summary;
        final boolean known;
        final SanitizerInfo sanitizer;
        CalleeResolution(MethodSummary summary, boolean known, SanitizerInfo sanitizer) {
            this.summary = summary;
            this.known = known;
            this.sanitizer = sanitizer;
        }
    }

    static final class MethodSummary {
        static final MethodSummary EMPTY = new MethodSummary();
        final Set<Source> returnSources = new TreeSet<>();
        final Set<Source> returnRenderSources = new TreeSet<>();
        final Set<Source> returnDeepRenderSources = new TreeSet<>();
        final Set<Source> returnCompletionFailureSources = new TreeSet<>();
        final Set<TypeRef> returnTypes = new TreeSet<>();
        final Set<LambdaTemplate> returnLambdas = new TreeSet<>();
        final Set<SinkSummary> sinks = new TreeSet<>();
        final Set<StoreSummary> stores = new TreeSet<>();
        final Set<MutationSummary> mutations = new TreeSet<>();
        final Set<CallbackSummary> callbacks = new TreeSet<>();
        void absorb(MethodSummary other) {
            returnSources.addAll(other.returnSources);
            returnRenderSources.addAll(other.returnRenderSources);
            returnDeepRenderSources.addAll(other.returnDeepRenderSources);
            returnCompletionFailureSources.addAll(other.returnCompletionFailureSources);
            returnTypes.addAll(other.returnTypes);
            returnLambdas.addAll(other.returnLambdas);
            sinks.addAll(other.sinks);
            stores.addAll(other.stores);
            mutations.addAll(other.mutations);
            callbacks.addAll(other.callbacks);
        }
    }

    static final class SinkSummary implements Comparable<SinkSummary> {
        final SinkCategory category;
        final String sink, flow, sinkArtifactOwner, contextKey;
        final int sinkArgument;
        final Set<Source> sources;
        final List<DiagnosticLocation> path;
        final SuppressionInfo suppression;
        SinkSummary(SinkCategory category, String sink, String flow, Set<Source> sources, String sinkArtifactOwner) {
            this(category, sink, flow, sources, sinkArtifactOwner, -1, "", List.of(), null);
        }
        SinkSummary(SinkCategory category, String sink, String flow, Set<Source> sources, String sinkArtifactOwner,
                    int sinkArgument, String contextKey, List<DiagnosticLocation> path) {
            this(category, sink, flow, sources, sinkArtifactOwner, sinkArgument, contextKey, path, null);
        }
        SinkSummary(SinkCategory category, String sink, String flow, Set<Source> sources, String sinkArtifactOwner,
                    int sinkArgument, String contextKey, List<DiagnosticLocation> path, SuppressionInfo suppression) {
            this.category = Objects.requireNonNull(category, "category");
            this.sink = sink; this.flow = flow; this.sinkArtifactOwner = sinkArtifactOwner;
            this.sinkArgument = sinkArgument; this.contextKey = contextKey == null ? "" : contextKey;
            this.sources = Collections.unmodifiableSet(new TreeSet<>(sources));
            this.path = List.copyOf(path);
            this.suppression = suppression;
        }
        @Override public boolean equals(Object o) {
            return o instanceof SinkSummary s && category == s.category && sink.equals(s.sink)
                    && flow.equals(s.flow) && sinkArtifactOwner.equals(s.sinkArtifactOwner)
                    && sinkArgument == s.sinkArgument && contextKey.equals(s.contextKey)
                    && sources.equals(s.sources) && path.equals(s.path)
                    && Objects.equals(suppression, s.suppression);
        }
        @Override public int hashCode() { return Objects.hash(category, sink, flow, sinkArtifactOwner, sinkArgument, contextKey, sources, path, suppression); }
        @Override public int compareTo(SinkSummary o) {
            int c = category.compareTo(o.category); if (c != 0) return c;
            c = sinkArtifactOwner.compareTo(o.sinkArtifactOwner); if (c != 0) return c;
            c = sink.compareTo(o.sink); if (c != 0) return c;
            c = flow.compareTo(o.flow); if (c != 0) return c;
            c = Integer.compare(sinkArgument, o.sinkArgument); if (c != 0) return c;
            c = contextKey.compareTo(o.contextKey); if (c != 0) return c;
            c = path.toString().compareTo(o.path.toString()); if (c != 0) return c;
            c = sources.toString().compareTo(o.sources.toString()); if (c != 0) return c;
            if (suppression == null && o.suppression != null) return -1;
            if (suppression != null && o.suppression == null) return 1;
            return suppression == null ? 0 : suppression.compareTo(o.suppression);
        }
    }

    static final class StoreSummary implements Comparable<StoreSummary> {
        final FieldKey target;
        final Set<Source> directSources, renderSources, deepRenderSources, completionFailureSources;
        final Set<TypeRef> types;
        final Set<LambdaTemplate> lambdas;

        StoreSummary(FieldKey target, Set<Source> directSources, Set<Source> renderSources,
                     Set<Source> deepRenderSources, Set<Source> completionFailureSources,
                     Set<TypeRef> types, Set<LambdaTemplate> lambdas) {
            this.target = target;
            this.directSources = Collections.unmodifiableSet(new TreeSet<>(directSources));
            this.renderSources = Collections.unmodifiableSet(new TreeSet<>(renderSources));
            this.deepRenderSources = Collections.unmodifiableSet(new TreeSet<>(deepRenderSources));
            this.completionFailureSources = Collections.unmodifiableSet(new TreeSet<>(completionFailureSources));
            this.types = Collections.unmodifiableSet(new TreeSet<>(types));
            this.lambdas = Collections.unmodifiableSet(new TreeSet<>(lambdas));
        }

        @Override public boolean equals(Object other) {
            return other instanceof StoreSummary summary && target.equals(summary.target)
                    && directSources.equals(summary.directSources)
                    && renderSources.equals(summary.renderSources)
                    && deepRenderSources.equals(summary.deepRenderSources)
                    && completionFailureSources.equals(summary.completionFailureSources)
                    && types.equals(summary.types) && lambdas.equals(summary.lambdas);
        }

        @Override public int hashCode() {
            return Objects.hash(target, directSources, renderSources, deepRenderSources,
                    completionFailureSources, types, lambdas);
        }

        @Override public int compareTo(StoreSummary other) {
            int comparison = target.compareTo(other.target); if (comparison != 0) return comparison;
            comparison = directSources.toString().compareTo(other.directSources.toString()); if (comparison != 0) return comparison;
            comparison = renderSources.toString().compareTo(other.renderSources.toString()); if (comparison != 0) return comparison;
            comparison = deepRenderSources.toString().compareTo(other.deepRenderSources.toString()); if (comparison != 0) return comparison;
            comparison = completionFailureSources.toString().compareTo(other.completionFailureSources.toString()); if (comparison != 0) return comparison;
            comparison = types.toString().compareTo(other.types.toString()); if (comparison != 0) return comparison;
            return lambdas.toString().compareTo(other.lambdas.toString());
        }
    }

    static final class MutationSummary implements Comparable<MutationSummary> {
        final int targetParamOrdinal;
        final Set<Source> contents;
        MutationSummary(int targetParamOrdinal, Set<Source> contents) {
            this.targetParamOrdinal = targetParamOrdinal;
            this.contents = Collections.unmodifiableSet(new TreeSet<>(contents));
        }
        @Override public boolean equals(Object o) { return o instanceof MutationSummary m && targetParamOrdinal == m.targetParamOrdinal && contents.equals(m.contents); }
        @Override public int hashCode() { return Objects.hash(targetParamOrdinal, contents); }
        @Override public int compareTo(MutationSummary o) {
            int c = Integer.compare(targetParamOrdinal, o.targetParamOrdinal); if (c != 0) return c;
            return contents.toString().compareTo(o.contents.toString());
        }
    }

    static final class DiagnosticLocation implements Comparable<DiagnosticLocation> {
        final String owner, method, desc, sourceFile, artifact;
        final int line, instructionIndex;
        DiagnosticLocation(String owner, String method, String desc, String sourceFile, int line,
                           int instructionIndex, String artifact) {
            this.owner = owner == null ? "" : owner;
            this.method = method == null ? "" : method;
            this.desc = desc == null ? "" : desc;
            this.sourceFile = sourceFile == null ? "" : sourceFile;
            this.line = line;
            this.instructionIndex = instructionIndex;
            this.artifact = artifact == null ? "" : artifact;
        }
        static DiagnosticLocation analysis() {
            return new DiagnosticLocation("securelogscan/SecureLogScan", "analysis", "()V", "", -1, -1, "");
        }
        String methodDisplay() { return owner.replace('/', '.') + "." + method + desc; }
        String display() {
            StringBuilder out = new StringBuilder(methodDisplay());
            if (!sourceFile.isBlank()) {
                out.append(" (").append(sourceFile);
                if (line > 0) out.append(':').append(line);
                out.append(')');
            }
            if (instructionIndex >= 0) out.append(" [instruction ").append(instructionIndex).append(']');
            return out.toString();
        }
        @Override public int compareTo(DiagnosticLocation o) {
            int c = owner.compareTo(o.owner); if (c != 0) return c;
            c = method.compareTo(o.method); if (c != 0) return c;
            c = desc.compareTo(o.desc); if (c != 0) return c;
            c = sourceFile.compareTo(o.sourceFile); if (c != 0) return c;
            c = Integer.compare(line, o.line); if (c != 0) return c;
            c = Integer.compare(instructionIndex, o.instructionIndex); if (c != 0) return c;
            return artifact.compareTo(o.artifact);
        }
        @Override public boolean equals(Object o) { return o instanceof DiagnosticLocation d && compareTo(d) == 0; }
        @Override public int hashCode() { return Objects.hash(owner, method, desc, sourceFile, line, instructionIndex, artifact); }
        @Override public String toString() { return display(); }
    }

    static final class Finding implements Comparable<Finding> {
        final String severity, owner, method, desc, sinkArtifactOwner, sink, flow, contextKey;
        final SinkCategory category;
        final Set<FieldKey> fields;
        final Set<SanitizerInfo> sanitizers;
        final Set<UncertaintyReason> uncertainties;
        final DiagnosticLocation location;
        final int sinkArgument;
        final List<DiagnosticLocation> path;
        final SuppressionInfo suppression;

        Finding(String severity, SinkCategory category, String owner, String method, String desc, String sinkArtifactOwner,
                String sink, String flow, Set<FieldKey> fields, Set<SanitizerInfo> sanitizers,
                Set<UncertaintyReason> uncertainties) {
            this(severity, category, owner, method, desc, sinkArtifactOwner, sink, flow, fields, sanitizers,
                    uncertainties, new DiagnosticLocation(owner, method, desc, "", -1, -1, ""), -1, "", List.of(), null);
        }

        Finding(String severity, SinkCategory category, String owner, String method, String desc, String sinkArtifactOwner,
                String sink, String flow, Set<FieldKey> fields, Set<SanitizerInfo> sanitizers,
                Set<UncertaintyReason> uncertainties, DiagnosticLocation location, int sinkArgument,
                String contextKey, List<DiagnosticLocation> path) {
            this(severity, category, owner, method, desc, sinkArtifactOwner, sink, flow, fields, sanitizers,
                    uncertainties, location, sinkArgument, contextKey, path, null);
        }

        Finding(String severity, SinkCategory category, String owner, String method, String desc, String sinkArtifactOwner,
                String sink, String flow, Set<FieldKey> fields, Set<SanitizerInfo> sanitizers,
                Set<UncertaintyReason> uncertainties, DiagnosticLocation location, int sinkArgument,
                String contextKey, List<DiagnosticLocation> path, SuppressionInfo suppression) {
            this.severity = severity; this.category = Objects.requireNonNull(category, "category");
            this.owner = owner; this.method = method; this.desc = desc; this.sinkArtifactOwner = sinkArtifactOwner;
            this.sink = sink; this.flow = flow; this.location = location == null ? DiagnosticLocation.analysis() : location;
            this.sinkArgument = sinkArgument; this.contextKey = contextKey == null ? "" : contextKey;
            this.path = List.copyOf(path);
            this.fields = Collections.unmodifiableSet(new TreeSet<>(fields));
            this.sanitizers = Collections.unmodifiableSet(new TreeSet<>(sanitizers));
            this.uncertainties = Collections.unmodifiableSet(new TreeSet<>(uncertainties));
            this.suppression = suppression;
        }

        static Finding incomplete(String message) {
            return new Finding("INCOMPLETE", SinkCategory.ANALYSIS, "securelogscan/SecureLogScan", "analysis", "()V",
                    "securelogscan/SecureLogScan", "analysis", message, Set.of(), Set.of(), Set.of(),
                    DiagnosticLocation.analysis(), -1, "", List.of(), null);
        }

        String location() { return owner.replace('/', '.') + "." + method + desc; }

        String fingerprint() {
            String material = severity + "|" + category + "|" + owner + "|" + method + "|" + desc + "|"
                    + sink + "|" + sinkArgument + "|" + contextKey + "|" + location.line + "|" + fields;
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(material.getBytes(StandardCharsets.UTF_8));
                StringBuilder out = new StringBuilder(64);
                for (byte value : digest) out.append(String.format(Locale.ROOT, "%02x", value & 0xff));
                return out.toString();
            } catch (NoSuchAlgorithmException ex) {
                throw new IllegalStateException(ex);
            }
        }

        boolean sameSinkLocation(Finding other) {
            return category == other.category && owner.equals(other.owner) && method.equals(other.method)
                    && desc.equals(other.desc) && sinkArtifactOwner.equals(other.sinkArtifactOwner) && sink.equals(other.sink)
                    && sinkArgument == other.sinkArgument && contextKey.equals(other.contextKey);
        }

        @Override public int compareTo(Finding other) {
            int c = severity.compareTo(other.severity); if (c != 0) return c;
            c = category.compareTo(other.category); if (c != 0) return c;
            c = owner.compareTo(other.owner); if (c != 0) return c;
            c = method.compareTo(other.method); if (c != 0) return c;
            c = desc.compareTo(other.desc); if (c != 0) return c;
            c = sink.compareTo(other.sink); if (c != 0) return c;
            c = Integer.compare(sinkArgument, other.sinkArgument); if (c != 0) return c;
            c = contextKey.compareTo(other.contextKey); if (c != 0) return c;
            c = location.compareTo(other.location); if (c != 0) return c;
            c = path.toString().compareTo(other.path.toString()); if (c != 0) return c;
            c = flow.compareTo(other.flow); if (c != 0) return c;
            c = fields.toString().compareTo(other.fields.toString()); if (c != 0) return c;
            c = sanitizers.toString().compareTo(other.sanitizers.toString()); if (c != 0) return c;
            c = uncertainties.toString().compareTo(other.uncertainties.toString()); if (c != 0) return c;
            if (suppression == null && other.suppression != null) return -1;
            if (suppression != null && other.suppression == null) return 1;
            return suppression == null ? 0 : suppression.compareTo(other.suppression);
        }

        @Override public boolean equals(Object other) { return other instanceof Finding finding && compareTo(finding) == 0; }
        @Override public int hashCode() {
            return Objects.hash(severity, category, owner, method, desc, sinkArtifactOwner, sink, flow, fields,
                    sanitizers, uncertainties, location, sinkArgument, contextKey, path, suppression);
        }
    }
}
