import org.flywaydb.core.Flyway;
import java.util.Arrays;

public class FlywayFixture {
    public static void main(String[] args) throws Exception {
        var flags = Arrays.asList(args);
        boolean enabled = !"false".equals(System.getenv("SPRING_FLYWAY_ENABLED"))
            && !flags.contains("--spring.flyway.enabled=false");
        if (enabled) {
            if (flags.contains("--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY")) {
                throw new IllegalStateException("VALIDATE_ONLY requires Flyway disabled");
            }
            Flyway.configure()
                .dataSource(System.getenv("FIXTURE_URL"), System.getenv("FIXTURE_USER"), "")
                .schemas("release_fixture")
                .locations("classpath:BOOT-INF/classes/db/migration")
                .load().migrate();
        }
        if (flags.contains("--migrate-only")) return;
        Fixture.main(args);
    }
}
