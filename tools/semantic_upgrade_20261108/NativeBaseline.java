import org.flywaydb.core.Flyway;
public class NativeBaseline {
 public static void main(String[] a) {
  Flyway.configure().dataSource(a[0],"fixture","fixture-only").schemas("ouf_sem").defaultSchema("ouf_sem")
   .locations("filesystem:"+a[1]).target("10").load().migrate();
 }
}
