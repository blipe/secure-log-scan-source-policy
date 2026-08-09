package demo;
import secure.Secure;
import java.util.logging.Logger;

public class Demo {
  static final Logger LOG = Logger.getLogger(Demo.class.getName());
  static class Customer {
    @Secure String ssn = "111-22-3333";
    String shadow;
    String getSsn() { return ssn; }
    void copy() { shadow = ssn; }
  }
  static void logIt(String x) { LOG.info("x=" + x); }
  static String wrap(String x) { return "wrap(" + x + ")"; }
  public static void main(String[] args) {
    Customer c = new Customer();
    System.out.println(c.ssn);
    LOG.warning("ssn " + c.getSsn());
    logIt(c.ssn);
    System.err.printf("ssn=%s%n", c.ssn);
    c.copy();
    LOG.info(c.shadow);
    LOG.info(wrap(c.ssn));
  }
}
