import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;

/** Fixture only: never copied to, loaded or executed on the target VPS. */
public final class NativeFlyway {
  public static void main(String[] args) {
    if (args.length != 2 || !(args[0].equals("migrate") || args[0].equals("validate")))
      throw new IllegalArgumentException("FIXTURE_MODE");
    Flyway flyway = Flyway.configure()
      .dataSource(System.getenv("OUF_FIXTURE_JDBC"),System.getenv("OUF_FIXTURE_USER"),System.getenv("OUF_FIXTURE_PASSWORD"))
      .schemas("ouf_ingestion").defaultSchema("ouf_ingestion")
      .locations("filesystem:"+args[1]).load();
    if (args[0].equals("migrate")) flyway.migrate();
    flyway.validate();
    for (MigrationInfo migration : flyway.info().applied()) {
      if (migration.getVersion() != null)
        System.out.println("OUF_NATIVE_SQL_CHECKSUM="+migration.getScript()+"\t"+migration.getChecksum());
    }
    System.out.println("OUF_NATIVE_FLYWAY_VALIDATION=PASS");
  }
}
