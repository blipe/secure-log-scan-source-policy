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
                else if (a.startsWith("--dependency-findings=")) c.dependencyFindingsPolicy = parseEnum(DependencyFindingsPolicy.class, a.substring("--dependency-findings=".len