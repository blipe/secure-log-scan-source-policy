package models;

import secure.Secure;

import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;

public final class MethodModelCases {
    static final class Bean {
        @Secure String ssn = "123-45-6789";
    }

    static final class Wrapper {
        Bean bean = new Bean();
    }

    static void configuredSink() {
        ExternalApis.audit(new Bean().ssn);
    }

    static void configuredContextSink() {
        ExternalApis.context("ssn", new Bean().ssn);
    }

    static void configuredRenderer() {
        System.out.println(ExternalApis.serialize(new Bean()));
    }

    static void configuredNestedRenderer() {
        System.out.println(ExternalApis.serialize(new Wrapper()));
    }

    static void configuredCallbackCaptured() {
        String ssn = new Bean().ssn;
        ExternalApis.dispatch(() -> System.out.println(ssn));
    }

    static void configuredCallbackArgument() {
        ExternalApis.consume(new Bean().ssn, System.out::println);
    }

    static void configuredCallbackReturn() {
        String value = ExternalApis.transform(new Bean().ssn, item -> item);
        System.out.println(value);
    }

    static void configuredSanitizedCallbackReturn() {
        String value = ExternalApis.transform(new Bean().ssn, ExternalApis::mask);
        System.out.println(value);
    }

    static void callbackHelper(Runnable callback) {
        ExternalApis.dispatch(callback);
    }

    static void configuredCallbackThroughHelper() {
        String ssn = new Bean().ssn;
        callbackHelper(() -> System.out.println(ssn));
    }

    static void configuredMutation() {
        ExternalApis.Box box = new ExternalApis.Box();
        ExternalApis.fill(box, new Bean().ssn);
        System.out.println(box);
    }

    static void configuredReceiverMutation() {
        ExternalApis.Box box = new ExternalApis.Box();
        box.addExternal(new Bean().ssn);
        System.out.println(box);
    }

    static void configuredSanitizer() {
        System.out.println(ExternalApis.mask(new Bean().ssn));
    }

    static void sanitizedConfiguredContext() {
        ExternalApis.context("ssn", ExternalApis.mask(new Bean().ssn));
    }

    static void configuredSinkMethodReference() {
        Consumer<Object> sink = ExternalApis::audit;
        sink.accept(new Bean().ssn);
    }

    static void configuredRendererMethodReference() {
        Function<Object, String> renderer = ExternalApis::serialize;
        System.out.println(renderer.apply(new Bean()));
    }

    static void configuredSanitizerMethodReference() {
        Function<String, String> sanitizer = ExternalApis::mask;
        System.out.println(sanitizer.apply(new Bean().ssn));
    }

    static void configuredMutationMethodReference() {
        ExternalApis.Box box = new ExternalApis.Box();
        BiConsumer<ExternalApis.Box, Object> mutation = ExternalApis::fill;
        mutation.accept(box, new Bean().ssn);
        System.out.println(box);
    }

    static void directModeDoesNotRenderObject() {
        ExternalApis.directOnly(new Bean());
    }

    static void untrackedConfiguredSink() {
        ExternalApis.audit("ordinary");
    }
}
