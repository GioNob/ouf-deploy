import org.flywaydb.core.Flyway;
public class NativeUdpBaseline {
 public static void main(String[] a) {
  Flyway.configure().dataSource(a[0],"fixture","fixture-only").schemas("ouf_udp").defaultSchema("ouf_udp")
   .locations("filesystem:"+a[1]).target("36").load().migrate();
 }
}
