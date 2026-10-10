import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.output.ValidateResult;
public final class FlywayFixture {
  public static void main(String[] args) {
    if (args.length != 3 || !java.util.Set.of("semantic", "restored", "restored_v10").contains(args[1])) throw new IllegalArgumentException("FIXTURE_ARGUMENTS");
    Flyway flyway = Flyway.configure()
      .dataSource("jdbc:postgresql://127.0.0.1:55439/"+args[1], "postgres", "ci-fixture-only")
      .schemas("ouf_sem").defaultSchema("ouf_sem")
      .locations("filesystem:"+args[2]).load();
    switch (args[0]) {
      case "migrate":
        flyway.migrate();
        flyway.validate();
        System.out.println("OUF_FLYWAY_FIXTURE=MIGRATED_AND_VALIDATED");
        break;
      case "validate":
        flyway.validate();
        System.out.println("OUF_FLYWAY_FIXTURE=VALIDATED");
        break;
      case "observe":
        ValidateResult observation = flyway.validateWithResult();
        System.out.println("OUF_FLYWAY_VALIDATION="+(observation.validationSuccessful ? "VALIDATED_WITH_CURRENT_SCHEMA" : "VALIDATION_DENIED"));
        break;
      case "reject":
        ValidateResult result = flyway.validateWithResult();
        if (result.validationSuccessful) throw new IllegalStateException("CHECKSUM_DRIFT_ACCEPTED");
        if (!"CHECKSUM_MISMATCH".equals(result.invalidMigrations.get(0).errorDetails.errorCode.toString()))
          throw new IllegalStateException("UNEXPECTED_VALIDATION_DENIAL");
        System.out.println("OUF_FLYWAY_FIXTURE=CHECKSUM_DRIFT_REJECTED");
        break;
      default: throw new IllegalArgumentException("FIXTURE_MODE");
    }
  }
}
