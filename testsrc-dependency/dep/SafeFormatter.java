package dep;

public final class SafeFormatter implements Formatter {
    @Override
    public String format(Customer customer) {
        return "customer";
    }
}
