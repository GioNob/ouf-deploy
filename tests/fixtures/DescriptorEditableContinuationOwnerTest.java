package it.comune.trieste.ouf.onboarding;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import it.comune.trieste.ouf.authorization.*;
import it.comune.trieste.ouf.authorization.AuthorizationPolicy.*;
import it.comune.trieste.ouf.onboarding.authorization.*;
import java.net.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.*;
import org.springframework.test.web.servlet.MockMvc;

/** Real deployed-owner code/HTTP serialization/PG17. Principal and TTY decisions are CI synthetic. */
@SpringBootTest(properties={"ouf.authorization.bootstrap.admin-issuer=fixture-issuer","ouf.authorization.bootstrap.superadmin-role=ente:bootstrap","ouf.authorization.bootstrap.admin-tenant=ouf-lab"})
@AutoConfigureMockMvc
class DescriptorEditableContinuationOwnerTest {
 @DynamicPropertySource static void database(DynamicPropertyRegistry r){r.add("spring.datasource.url",()->System.getenv("OUF_ONB_DB_URL"));r.add("spring.datasource.username",()->System.getenv("OUF_ONB_DB_USER"));r.add("spring.datasource.password",()->System.getenv("OUF_ONB_DB_PASSWORD"));}
 @Autowired AuthorizationAdminService admin;@Autowired AuthorizationPolicyRegistry registry;
 @Autowired AuthorizationReviewService review;
 @Autowired JdbcClient db;@Autowired MockMvc http;@Autowired ObjectMapper json;
 @MockitoBean AuthorizationRuntimeSynchronizer runtime;
 static final String ROOT="/api/trusted-human/v1/authorization";
 final List<String> added=List.of("ingestion.contract.read","ingestion.lineage.read","urban.object.read","lineage.object.read","lineage.property.read");
 PrincipalContext caller;AuthorizationAdminService.Actor actor;AuthorizationAdminService.Draft draft;List<Grant> grants;
 CapabilityDescriptor read(String id){return new CapabilityDescriptor(id,"READ",id,Set.of(PrincipalContext.ActorType.HUMAN));}
 @BeforeEach void setup(){
  db.sql("truncate ouf_authorization.role_catalogue,ouf_authorization.superadmin_history,ouf_authorization.superadmin_transfer,ouf_authorization.superadmin_binding,ouf_authorization.admin_audit,ouf_authorization.policy_draft,ouf_authorization.capability_registration,ouf_authorization.authorization_decision_audit,ouf_authorization.active_policy_bundle,ouf_authorization.policy_bundle,ouf_authorization.bootstrap_latch cascade").update();
  db.sql("insert into ouf_authorization.bootstrap_latch(singleton_key,completed) values(true,false)").update();
  caller=new PrincipalContext("ci-synthetic-admin","ouf-lab",PrincipalContext.ActorType.HUMAN,null,"auth","fixture-issuer","aud",Set.of("authorization.bootstrap","authorization.policy.admin"),new PrincipalContext.IdentityClaims(Set.of("ente:bootstrap"),"1",Set.of(),Instant.now()));
  actor=new AuthorizationAdminService.Actor(caller.subjectId(),caller.tenantId(),"HUMAN","ci:owner",UUID.randomUUID().toString(),caller);
  var management=new CapabilityDescriptor("authorization.policy.admin","EXECUTE","authorization.policy.admin",Set.of(PrincipalContext.ActorType.HUMAN));
  var baseCaps=List.of(management,read("ingestion.run.read"),read("unrelated.read"));
  for(var c:baseCaps)admin.register(c.capabilityId().startsWith("ingestion.")?"ingestion":"other",c,actor);
  grants=new ArrayList<>();for(int i=0;i<106;i++)grants.add(new Grant("retained-"+i,"unrelated.read",i==105?"other-tenant":"ouf-lab","retained-subject",null,null,Instant.parse("2020-01-01T00:00:00Z"),Instant.parse("2036-01-01T00:00:00Z")));
  // Establish bootstrap with only this tenant's grants. The multi-tenant48
  // baseline is an explicit CI seed, representing retained existing history;
  // create() correctly forbids inventing another tenant's grant at bootstrap.
  var base=admin.create(new PolicyBundle("ouf-lab-authorization",47,Instant.parse("2026-10-25T05:00:00Z"),baseCaps,grants.stream().filter(g->g.tenantId().equals("ouf-lab")).toList()),actor);
  admin.publish(base.id(),0,actor);
  registry.publishAndActivate(new PolicyBundle("ouf-lab-authorization",48,Instant.parse("2026-10-25T06:00:00Z"),baseCaps,grants),"ci-existing-multitenant-history");
  for(var id:added)admin.register(id.startsWith("ingestion.")?"ingestion":"udp",read(id),actor);
  var caps=new ArrayList<>(baseCaps);for(var id:added)caps.add(read(id));
  draft=admin.create(new PolicyBundle("ouf-lab-authorization",49,Instant.parse("2026-10-25T12:00:00Z"),caps,grants),actor);
  assertThat(draft.revision()).isZero();
 }
 @Test void actualOwnerSuccess()throws Exception{run("success");}
 @Test void actualOwnerDeclinedExactReview()throws Exception{run("decline");}
 @Test void actualOwnerCommittedButResponseLostNoReplay()throws Exception{run("lost");}
 void run(String mode)throws Exception{
  long before=db.sql("select count(*) from ouf_authorization.admin_audit where action in('REGISTER_CAPABILITY','CREATE_DRAFT')").query(Long.class).single();
  var publishes=new AtomicInteger();var previews=new AtomicInteger();
  var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
  var pool=Executors.newFixedThreadPool(2);server.setExecutor(pool);
  server.createContext(ROOT,exchange->{
   try{
    if(!"Bearer CI_SYNTHETIC_PRINCIPAL_NOT_IAM".equals(exchange.getRequestHeaders().getFirst("Authorization")))throw new IllegalStateException("CI bearer missing");
    var builder=request(HttpMethod.valueOf(exchange.getRequestMethod()),exchange.getRequestURI())
     .with(r->{TestAuthorization.bind(r,caller.subjectId(),"HUMAN",Set.of("authorization.policy.admin"));r.setAttribute(ServletAuthorization.TRUSTED_PRINCIPAL,new TrustedPrincipal(caller));r.setAttribute("ouf.statelessBearerWriteValidated",true);return r;});
    // The bridge's bearer is a CI marker, not an IAM credential. MockMvc receives
    // the explicit synthetic TrustedPrincipal used by the owner's own tests.
    exchange.getRequestHeaders().forEach((k,v)->{if(!k.equalsIgnoreCase("Authorization"))builder.header(k,v.toArray());});
    var response=http.perform(builder).andReturn().getResponse();
    if(exchange.getRequestURI().getPath().endsWith(":preview"))previews.incrementAndGet();
    if(exchange.getRequestURI().getPath().endsWith(":publish")){
     publishes.incrementAndGet();
     if(mode.equals("lost")){assertThat(response.getStatus()).isEqualTo(200);exchange.close();return;}
    }
    for(var name:response.getHeaderNames())exchange.getResponseHeaders().put(name,new ArrayList<>(response.getHeaders(name)));
    byte[] body=response.getContentAsByteArray();exchange.sendResponseHeaders(response.getStatus(),body.length);exchange.getResponseBody().write(body);exchange.close();
   }catch(Exception e){e.printStackTrace();exchange.close();}
  });server.start();
  Path input=Files.createTempFile("synthetic-owner-wire-",".json");
  try{
   json.writeValue(input.toFile(),Map.of("origin","http://127.0.0.1:"+server.getAddress().getPort()+ROOT,"draft",draft,"active",admin.activePolicy(actor),"initialPreview",review.preview(caller,draft.id(),0)));
   var p=new ProcessBuilder("python3","-I","-S","-B",System.getenv("OUF_DEPLOY_ROOT")+"/tests/qualify_descriptor_editable_continuation_owner_driver.py",input.toString(),mode).inheritIO().start();
   assertThat(p.waitFor(150,TimeUnit.SECONDS)).isTrue();assertThat(p.exitValue()).isZero();
   assertThat(db.sql("select count(*) from ouf_authorization.admin_audit where action in('REGISTER_CAPABILITY','CREATE_DRAFT')").query(Long.class).single()).isEqualTo(before);
   assertThat(db.sql("select count(*) from ouf_authorization.policy_draft").query(Long.class).single()).isEqualTo(2);
   if(mode.equals("decline")){assertThat(publishes.get()).isZero();assertThat(previews.get()).isEqualTo(0);assertThat(registry.active().orElseThrow().version()).isEqualTo(48);}
   else{assertThat(publishes.get()).isEqualTo(1);assertThat(previews.get()).isEqualTo(1);assertThat(registry.active().orElseThrow().version()).isEqualTo(49);assertThat(admin.get(draft.id()).revision()).isEqualTo(1);assertThat(registry.load("ouf-lab-authorization",49).grants()).isEqualTo(grants);}
  }finally{Files.deleteIfExists(input);server.stop(0);pool.shutdownNow();}
 }
}
