import org.flywaydb.core.Flyway;

public class FlywayFixture {
    public static void main(String[] args) throws Exception {
        Flyway.configure()
            .dataSource(System.getenv("FIXTURE_URL"), System.getenv("FIXTURE_USER"), "")
            .schemas("release_fixture")
            .locations("classpath:BOOT-INF/classes/db/migration")
            .load().migrate();
        Fixture.main(args);
    }
}
