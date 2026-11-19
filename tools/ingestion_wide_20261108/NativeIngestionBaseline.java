import org.flywaydb.core.Flyway;
public class NativeIngestionBaseline {
 public static void main(String[] a) {
  Flyway.configure().dataSource(a[0],"fixture","fixture-only").schemas("ouf_ingestion").defaultSchema("ouf_ingestion")
   .locations("filesystem:"+a[1]).target("18").load().migrate();
 }
}
