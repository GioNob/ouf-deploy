import java.sql.*;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;

/** Run only packaged Flyway V11/V12; never start the Spring application. */
public final class SemanticMigration {
  static final int[] CHECKSUMS={-229176171,-370046820,1421470298,-1092036175,1905797703,648864672,1546537302,-319796023,521654427,1273060826,-1352811484,-969370259};
  static void need(boolean ok,String code) { if(!ok) throw new IllegalStateException(code); }
  static String property(StandardEnvironment env,String key) { return env.getRequiredProperty(key); }
  static List<String> history(Connection c) throws Exception {
    var out=new ArrayList<String>();
    try(var s=c.createStatement();var r=s.executeQuery("select installed_rank,version,type,script,checksum,success from ouf_sem.flyway_schema_history order by installed_rank")) {
      while(r.next()) { var row=new ArrayList<String>();for(int i=1;i<=6;i++)row.add(Objects.toString(r.getString(i),"<null>"));out.add(String.join("|",row)); }
    }
    return out;
  }
  static void baseline(Connection c) throws Exception {
    try(var s=c.createStatement();var r=s.executeQuery("select version,checksum,success from ouf_sem.flyway_schema_history where version is not null order by installed_rank")) {
      int n=0;while(r.next()) {need(n<10&&Integer.toString(n+1).equals(r.getString(1))&&r.getInt(2)==CHECKSUMS[n]&&r.getBoolean(3),"HISTORY_PREFIX_CHANGED");n++;}need(n==10,"EXACT_V10_REQUIRED");
    }
    try(var s=c.createStatement();var r=s.executeQuery("select count(*) from ouf_sem.discovery_request")) {need(r.next()&&r.getLong(1)==0,"DISCOVERY_REQUESTS_CHANGED");}
  }
  public static void main(String[] args) {
    String phase="CONFIGURATION";
    try {
      need(args.length==3,"BOUND_DATABASE_ARGUMENTS_REQUIRED");
      need(System.getenv("SPRING_APPLICATION_JSON")==null,"JSON_CONFIGURATION_UNSUPPORTED");
      StandardEnvironment env=new StandardEnvironment();
      ConfigurationPropertySources.attach(env);
      ConfigDataEnvironmentPostProcessor.applyTo(env);
      String url=property(env,"spring.datasource.url"),user=property(env,"spring.datasource.username"),password=property(env,"spring.datasource.password");
      need(url.equals(args[0])&&user.equals(args[1]),"RESOLVED_DATASOURCE_DIFFERS_FROM_DECLARATION");
      need("false".equals(property(env,"ouf.semantic.discovery-worker.enabled"))&&"false".equals(property(env,"ouf.semantic.providers.schema-gov.enabled")),"PROVIDER_AND_WORKER_MUST_REMAIN_DISABLED");
      need("ouf_sem".equals(property(env,"spring.flyway.schemas"))&&"ouf_sem".equals(property(env,"spring.flyway.default-schema")),"EXPECTED_FLYWAY_SCHEMA_REQUIRED");
      for(String key:List.of("spring.flyway.url","spring.flyway.user","spring.flyway.password","spring.flyway.locations","spring.flyway.table","spring.flyway.target"))need(env.getProperty(key)==null,"CUSTOM_FLYWAY_BINDING_UNSUPPORTED");
      phase="DATABASE_PREFLIGHT";
      // Connection bounds also cover name lookup/network failure in the installed JDBC driver.
      String bounded=url+(url.contains("?")?"&":"?")+"connectTimeout=5&socketTimeout=35&tcpKeepAlive=true";
      try(var c=DriverManager.getConnection(bounded,user,password)) {
        c.setReadOnly(true);
        try(var s=c.createStatement();var r=s.executeQuery("select oid::text from pg_database where datname=current_database()")){need(r.next()&&args[2].equals(r.getString(1)),"DATABASE_OID_CHANGED");}
        baseline(c);
        List<String> before=history(c);
        Flyway flyway=Flyway.configure().dataSource(bounded,user,password)
          .schemas("ouf_sem").defaultSchema("ouf_sem").locations("classpath:db/migration")
          .target("12").group(true).mixed(false).cleanDisabled(true).baselineOnMigrate(false)
          .validateOnMigrate(true).outOfOrder(false).connectRetries(0).lockRetryCount(0)
          .initSql("SET lock_timeout='3s'; SET statement_timeout='20s';")
          .load();
        flyway.validate();
        var pending=flyway.info().pending();
        need(pending.length==2&&"11".equals(pending[0].getVersion().toString())&&"12".equals(pending[1].getVersion().toString())
          &&Objects.equals(pending[0].getChecksum(),CHECKSUMS[10])&&Objects.equals(pending[1].getChecksum(),CHECKSUMS[11]),"EXACT_V11_V12_REQUIRED");
        phase="MIGRATION_DISPATCHED";
        System.out.println("OUF_SEMANTIC_UPGRADE {\"status\":\"MIGRATION_DISPATCHED\",\"versions\":[11,12]}");System.out.flush();
        var result=flyway.migrate();
        need(result.success&&result.migrationsExecuted==2,"MIGRATION_RESULT_UNEXPECTED");
        phase="READBACK";
        flyway.validate();
        var after=history(c);need(after.size()==before.size()+2&&after.subList(0,before.size()).equals(before),"PRIOR_HISTORY_CHANGED");
        try(var s=c.createStatement();var r=s.executeQuery("select count(*) from information_schema.columns where table_schema='ouf_sem' and table_name='discovery_request' and column_name in ('idempotency_key_hash','request_fingerprint','worker_generation','recovery_state','next_attempt_at','budget_started_at','budget_deadline')")){need(r.next()&&r.getInt(1)==7,"MIGRATED_COLUMNS_MISSING");}
        try(var s=c.createStatement();var r=s.executeQuery("select count(*) from information_schema.tables where table_schema='ouf_sem' and table_name in ('discovery_dependency','discovery_incident','discovery_attempt')")){need(r.next()&&r.getInt(1)==3,"MIGRATED_TABLES_MISSING");}
        System.out.println("OUF_SEMANTIC_UPGRADE {\"status\":\"SEMANTIC_V11_V12_MIGRATED_VALIDATED\",\"migrationsExecuted\":2,\"priorHistoryPreserved\":true,\"recoveryColumnPresent\":true,\"springApplicationStarted\":false,\"providerStarted\":false}");
      }
    } catch(Throwable error) {
      String code=error instanceof IllegalStateException&&error.getMessage()!=null&&error.getMessage().matches("[A-Z][A-Z0-9_]{0,100}")?error.getMessage():error.getClass().getSimpleName();
      System.out.println("OUF_SEMANTIC_UPGRADE {\"status\":\"HELD\",\"phase\":\""+phase+"\",\"reason\":\""+code+"\"}");
      System.exit(1);
    }
  }
}
