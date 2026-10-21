import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.flywaydb.core.Flyway;
import it.comune.trieste.ouf.ingestion.*;

/** CI fixture only; actual candidate beans and PostgreSQL, no target delivery. */
public final class StartupProfileProbe {
  public static void main(String[] arguments)throws Exception{
    String mode=arguments[0];
    if(mode.equals("health")){
      PGSimpleDataSource source=new PGSimpleDataSource();
      source.setURL(System.getenv("OUF_ING_DB_URL"));source.setUser(System.getenv("OUF_ING_DB_USER"));source.setPassword(System.getenv("OUF_ING_DB_PASSWORD"));
      var health=new IngestionReadinessHealthIndicator(source).health();
      emit(Map.of("status",health.getStatus().getCode(),"details",health.getDetails()));return;
    }
    var app=new SpringApplication(IngestionRuntimeApplication.class);
    app.setRegisterShutdownHook(false);
    try(ConfigurableApplicationContext context=app.run(Arrays.copyOfRange(arguments,1,arguments.length))){
      if(mode.equals("blocked"))throw new AssertionError("MIGRATE_GUARD_NOT_ENFORCED");
      if(!"false".equals(context.getEnvironment().getProperty("spring.flyway.enabled"))
          ||context.getBeansOfType(IngestionValidateOnlyStartup.class).size()!=1
          ||!context.getBeansOfType(Flyway.class).isEmpty()
          ||context.containsBean("flywayInitializer"))throw new AssertionError("VALIDATE_ONLY_CONTEXT_REQUIRED");
      var health=context.getBean(IngestionReadinessHealthIndicator.class).health();
      if(!"UP".equals(health.getStatus().getCode()))throw new AssertionError("COMPATIBLE_READINESS_REQUIRED");
      emit(Map.of("status","UP","effectiveFlywayEnabled",false,"flywayBeans",0,"guardPresent",true,
          "readiness",health.getDetails()));
    }catch(Exception failure){
      if(!mode.equals("blocked"))throw failure;
      Throwable cursor=failure;boolean found=false;
      for(int i=0;i<20&&cursor!=null;i++,cursor=cursor.getCause())
        found|="ING_STARTUP_MIGRATE_FORBIDDEN".equals(cursor.getMessage());
      if(!found)throw new AssertionError("EXPECTED_STARTUP_GUARD_REQUIRED");
      emit(Map.of("status","BLOCKED","reason","ING_STARTUP_MIGRATE_FORBIDDEN"));
    }
  }
  static void emit(Map<String,Object> value)throws Exception{
    System.out.println("OUF_STARTUP_PROFILE_PROOF="+new ObjectMapper().writeValueAsString(value));
  }
}
