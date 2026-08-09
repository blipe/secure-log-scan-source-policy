package external;

public interface Registry {
    void register(Runnable callback);
    void registerSupplier(java.util.function.Supplier<?> callback);
}
