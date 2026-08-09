package dep;

public final class UnsafeFormatter implements Formatter {
    @Override
    public String format(Customer customer) {
        return customer.ssn;
    }
}
