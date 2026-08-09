package app;

import dep.Customer;
import dep.DepAudit;
import dep.DepSanitizer;
import dep.Formatter;
import dep.Transform;
import dep.UnsafeFormatter;

public final class AppCases {
    public void dependencyToString(Customer customer) {
        System.out.println(customer);
    }

    public void dependencyVirtualDispatch(Customer customer) {
        Formatter formatter = new UnsafeFormatter();
        System.out.println(formatter.format(customer));
    }

    public void dependencySanitizer(Customer customer) {
        System.out.println(DepSanitizer.mask(customer.ssn));
    }

    public void dependencyOwnedSink(AppBean bean) {
        DepAudit.log(bean.ssn);
    }

    public void unresolvedDependency(AppBean bean) {
        System.out.println(new Transform().transform(bean.ssn));
    }
}
