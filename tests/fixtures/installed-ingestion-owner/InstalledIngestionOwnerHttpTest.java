package it.comune.trieste.ouf.onboarding;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import it.comune.trieste.ouf.authorization.*;
import it.comune.trieste.ouf.ingestion.*;
import it.comune.trieste.ouf.onboarding.application.*;
import it.comune.trieste.ouf.onboarding.authorization.AuthorizationPolicyRegistry;
import it.comune.trieste.ouf.onboarding.domain.CanonicalHash;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/** Actual pinned client -> TCP -> installed owner controllers/services/PostgreSQL.
 * JWT cryptography is the only mocked receiving boundary. The real security
 * chain, principal bridge and constrained/audited owner policy still execute.
 * No APISIX, real IAM, source activation, ingestion run or target proof.
 */
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,properties={
    "ouf.authorization.ths.public-origin=https://review.example",
    "ouf.iam.enabled=true","ouf.iam.issuer=https://issuer.example","ouf.iam.audience=test-audience"})
class InstalledIngestionOwnerHttpTest {
  static final String SOURCE="installed-contract",READ="ouf.onboarding.configuration.read",ATTEST="ouf.ingestion.configuration.attest";
  @DynamicPropertySource static void properties(DynamicPropertyRegistry r){
    r.add("spring.datasource.url",()->required("OUF_ONB_DB_URL"));
    r.add("spring.datasource.username",()->required("OUF_ONB_DB_USER"));
    r.add("spring.datasource.password",()->required("OUF_ONB_DB_PASSWORD"));
  }
  @Autowired ManagedOnboardingReviewService reviews;
  @Autowired ManagedFileService files;
  @Autowired OnboardingService onboarding;
  @Autowired CanonicalHash hashes;
  @Autowired JdbcClient db;
  @Autowired ObjectMapper json;
  @Autowired AuthorizationPolicyRegistry policy;
  @MockitoBean JwtDecoder decoder;
  @LocalServerPort int port;
  @TempDir Path temporary;
  final OnboardingService.Actor human=new OnboardingService.Actor("test-human","HUMAN_USER");
  UUID version,challenge;String hash;Map<String,Object> frozen;

  @BeforeEach void prepare() throws Exception {
    db.sql("truncate ouf_onboarding.source,ouf_onboarding.managed_file_asset,ouf_authorization.authorization_decision_audit,ouf_authorization.active_policy_bundle,ouf_authorization.policy_bundle restart identity cascade").update();
    when(decoder.decode(anyString())).thenAnswer(call->{
      String token=call.getArgument(0);
      if(!Set.of("fixture-service","fixture-human","fixture-tenant","fixture-client","fixture-readonly").contains(token))
        throw new BadJwtException("disposable fixture token denied");
      Instant now=Instant.now();
      return Jwt.withTokenValue(token).header("alg","RS256").issuer("https://issuer.example")
        .subject("service-user").audience(List.of("test-audience")).issuedAt(now).expiresAt(now.plusSeconds(120))
        .claim("tenant_id",token.equals("fixture-tenant")?"other-tenant":"test-tenant")
        .claim("ouf_actor_type",token.equals("fixture-human")?"HUMAN":"SERVICE")
        .claim("client_id",token.equals("fixture-client")?"other-ingestion":"test-ingestion")
        .claim("acr","test-acr").claim("scope",token.equals("fixture-readonly")?READ:READ+" "+ATTEST).build();
    });
    Instant now=Instant.now();String prepare=ManagedOnboardingReviewService.PREPARE;
    var constraints=new AuthorizationPolicy.GrantConstraints("ALLOW",null,"published-configuration",SOURCE,
        Map.of("module","ONBOARDING"),Set.of(),Set.of(),null,Set.of(),null);
    policy.publishAndActivate(new AuthorizationPolicy.PolicyBundle("installed-client-owner",1,now,
      List.of(new AuthorizationPolicy.CapabilityDescriptor(prepare,"COMMAND",prepare,Set.of(PrincipalContext.ActorType.HUMAN)),
        new AuthorizationPolicy.CapabilityDescriptor(READ,"READ",READ,Set.of(PrincipalContext.ActorType.SERVICE)),
        new AuthorizationPolicy.CapabilityDescriptor(ATTEST,"COMMAND",ATTEST,Set.of(PrincipalContext.ActorType.SERVICE))),
      List.of(new AuthorizationPolicy.Grant("prepare",prepare,"test-tenant","test-human",null,null,now.minusSeconds(60),now.plusSeconds(3600)),
        new AuthorizationPolicy.Grant("read",READ,"test-tenant",null,"test-ingestion",null,now.minusSeconds(60),now.plusSeconds(3600),constraints),
        new AuthorizationPolicy.Grant("attest",ATTEST,"test-tenant",null,"test-ingestion",null,now.minusSeconds(60),now.plusSeconds(3600),constraints))),"fixture-policy-admin");
    version=draft();
    var actor=new PrincipalContext("test-human","test-tenant",PrincipalContext.ActorType.HUMAN,"test-mcp","test-acr",
        "https://issuer.example","test-audience",Set.of(prepare),new PrincipalContext.IdentityClaims(Set.of(),"test-acr",Set.of(),null));
    var prepared=reviews.prepare(actor,new ManagedOnboardingReviewService.Prepare(SOURCE,version,1,"installed:prepare",null),"fixture");
    challenge=(UUID)prepared.get("challengeId");hash=prepared.get("configurationHash").toString();
    onboarding.confirm(SOURCE,version,challenge,human,"fixture","test-auth");
    frozen=onboarding.version(SOURCE,version);
  }

  PublicationGatewayClient client(String token) throws Exception {
    Path file=temporary.resolve(token+".token");Files.writeString(file,token);
    return new PublicationGatewayClient(json,"http://127.0.0.1:"+port,file.toString(),"test-tenant");
  }

  @Test void exactInstalledClientReadsAndAttestsOverRealOwnerHttpWithoutChangingFrozenSource() throws Exception {
    var gateway=client("fixture-service");
    assertThat(gateway.frozenConfiguration(SOURCE,version,hash)).containsEntry("state","APPROVED").containsEntry("configuration_hash",hash);
    assertThat(gateway.compatibility(SOURCE,version,hash)).containsEntry("status","ABSENT");
    var first=gateway.attestCompatibility(SOURCE,version,hash,1);
    var second=gateway.attestCompatibility(SOURCE,version,hash,1);
    assertThat(first).containsEntry("compatible",true).containsEntry("consumer","INGESTION_RUNTIME");
    assertThat(second.get("attestation_id")).isEqualTo(first.get("attestation_id"));
    assertThat(gateway.compatibility(SOURCE,version,hash)).containsEntry("status","PRESENT").containsEntry("compatible",true);
    var objects=mock(ExecutionGatewayClient.class);
    try(var readiness=new Readiness(new OnboardingReadinessService(json,gateway,objects))){
      assertThat(readiness.service.verify(SOURCE,version,hash,()->{})).containsEntry("status","PASS").containsEntry("reconciled",true);
    }
    verifyNoInteractions(objects);
    assertUnchanged(1);
    assertThat(policy.decisionAuditCount("test-tenant")).isGreaterThanOrEqualTo(8);
  }

  @Test void actualOwnerRejectsWrongHashAndDoesNotCreateAnAttestation() throws Exception {
    var gateway=client("fixture-service");String changed="sha256:"+"0".repeat(64);
    assertThatThrownBy(()->gateway.frozenConfiguration(SOURCE,version,changed)).hasMessage("ING_ACTIVATION_GATEWAY_412");
    assertThatThrownBy(()->gateway.attestCompatibility(SOURCE,version,changed,1)).hasMessage("ING_ACTIVATION_GATEWAY_412");
    assertUnchanged(0);
  }

  @Test void realPrincipalBridgeAndOwnerPolicyRejectWrongActorTenantClientScopeAndInvalidBearer() throws Exception {
    for(String identity:List.of("fixture-human","fixture-tenant","fixture-client")){
      var gateway=client(identity);
      assertThatThrownBy(()->gateway.frozenConfiguration(SOURCE,version,hash)).as(identity).hasMessage("ING_ACTIVATION_GATEWAY_403");
      assertThatThrownBy(()->gateway.attestCompatibility(SOURCE,version,hash,1)).as(identity).hasMessage("ING_ACTIVATION_GATEWAY_403");
    }
    var readOnly=client("fixture-readonly");
    assertThat(readOnly.frozenConfiguration(SOURCE,version,hash)).containsEntry("state","APPROVED");
    assertThatThrownBy(()->readOnly.attestCompatibility(SOURCE,version,hash,1)).hasMessage("ING_ACTIVATION_GATEWAY_403");
    var invalid=client("fixture-invalid");
    assertThatThrownBy(()->invalid.frozenConfiguration(SOURCE,version,hash)).hasMessage("ING_ACTIVATION_GATEWAY_401");
    assertUnchanged(0);
  }

  void assertUnchanged(long attestations){
    assertThat(onboarding.version(SOURCE,version)).isEqualTo(frozen);
    assertThat(onboarding.approvalCard(challenge)).containsEntry("status","CONFIRMED");
    assertThat(db.sql("select count(*) from ouf_onboarding.approval_decision").query(Long.class).single()).isOne();
    assertThat(db.sql("select count(*) from ouf_onboarding.consumer_compatibility_attestation").query(Long.class).single()).isEqualTo(attestations);
    assertThat(db.sql("select count(*) from ouf_onboarding.published_configuration").query(Long.class).single()).isZero();
  }

  @SuppressWarnings("unchecked") UUID draft(){
    byte[] csv="id,name\n1,Test\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    UUID asset=(UUID)files.register(null,"object://fixture/installed.csv",hashes.ofBytes(csv),"text/csv",csv.length,"test-human","retention://test").get("asset_id");
    UUID profile=(UUID)files.profile(asset,csv,"object://fixture/installed-sample.json").get("profile_id");
    UUID id=(UUID)files.onboard(asset,profile,SOURCE,"Test CSV","Test owner","urn:test:Object",List.of("test@1"),List.of("id"),human,"fixture").get("onboarding_version_id");
    var config=(Map<String,Object>)onboarding.version(SOURCE,id).get("configuration");
    var runtime=(Map<String,Object>)((Map<String,Object>)config.get("extractionProfile")).get("runtime");
    runtime.put("execution",Map.of("acquisitionMode","INTERNAL_MANAGED_CSV","adapterId","managed-csv","adapterRuntimeVersion","1","sourceSchemaRef","test-schema","sourceSchemaId","test-schema","sourceSchemaVersion","1","semanticPublicationSetRef","test-set","adapterProfileRef","test-profile","observationPolicy","CONTENT_HASH"));
    runtime.put("udp",Map.of("resolution",Map.of("strategyId","EXACT_SOURCE_KEY"),"materialization",Map.of("policyRef","test-policy")));
    config.put("semanticReferenceBindings",List.of(Map.of("semanticId","test","semanticVersion","1","revisionId","test-revision","publicationSetId","test-set")));
    onboarding.patchVersion(SOURCE,id,0,config,human,"fixture-complete");return id;
  }
  record Readiness(OnboardingReadinessService service) implements AutoCloseable {public void close(){service.close();}}
  static String required(String key){return Objects.requireNonNull(System.getenv(key),key+" required");}
}
