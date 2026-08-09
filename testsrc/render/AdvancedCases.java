package render;

import secure.Secure;
import java.util.*;
import java.util.logging.Logger;

public class AdvancedCases {
    static final Logger LOG = Logger.getLogger("advanced");

    static class Base {
        @Secure String secret = "s";
        @Override public String toString() { return "Base[secret=" + secret + "]"; }
    }
    static class Child extends Base { }
    static class SafeChild extends Base {
        @Override public String toString() { return "SafeChild"; }
    }

    interface Action { void log(Base value); }
    static class ActionImpl implements Action {
        public void log(Base value) { LOG.info("value=" + value); }
    }

    static class Holder {
        Object value;
        Holder(Object value) { this.value = value; }
    }

    static void mutate(List<Object> target, Object value) { target.add(value); }

    static void inheritedToString() { System.out.println(new Child()); }
    static void safeOverride() { System.out.println(new SafeChild()); }

    static void interfaceDispatch() {
        Action action = new ActionImpl();
        action.log(new Child());
    }

    static void helperMutation() {
        List<Object> list = new ArrayList<>();
        mutate(list, new Child());
        LOG.info(list.toString());
    }

    static void stringTransform() {
        Base b = new Base();
        LOG.info(b.secret.trim().toUpperCase(Locale.ROOT));
    }

    static void listFactory() { LOG.info(List.of(new Child()).toString()); }
    static void mapFactory() { LOG.info(Map.of("x", new Child()).toString()); }

    static void nestedCollection() {
        List<Object> inner = new ArrayList<>();
        inner.add(new Child());
        List<Object> outer = new ArrayList<>();
        outer.add(inner);
        LOG.info(outer.toString());
    }

    static void constructorField() {
        Holder holder = new Holder(new Child());
        System.out.println(holder.value);
    }

    static void arrayIdentityIsSafe() {
        Object[] values = {new Child()};
        System.out.println(values);
    }

    static void arraysToStringLeaks() {
        Object[] values = {new Child()};
        System.out.println(Arrays.toString(values));
    }
}
