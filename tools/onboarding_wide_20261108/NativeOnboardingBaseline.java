import org.flywaydb.core.Flyway;
public class NativeOnboardingBaseline {
 public static void main(String[] a) {
  Flyway.configure().dataSource(a[0],"fixture","fixture-only").schemas("ouf_onboarding").defaultSchema("ouf_onboarding")
   .locations("filesystem:"+a[1]).target("38").load().migrate();
 }
}
