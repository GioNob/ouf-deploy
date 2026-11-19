package it.comune.trieste.ouf.udp;

import static org.assertj.core.api.Assertions.*;
import it.comune.trieste.ouf.authorization.*;
import it.comune.trieste.ouf.authorization.AuthorizationPolicy.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;

/** Real installed SDK evaluator; synthetic identities, no target operation. */
class PropertySearchConstraintQualificationTest {
  final Instant now=Instant.parse("2026-10-18T00:00:00Z");
  final String cap="urban.object.search";
  final Set<String> labels=Set.of("OPEN","ANONYMOUS","PERSONAL","SENSITIVE","RESTRICTED");
  final Set<String> details=Set.of("PUBLIC_OPERATIONAL","RESTRICTED_OPERATIONAL","SECURITY_SENSITIVE","TENANT_OPERATIONAL");
  PrincipalContext actor(String subject,String tenant,Set<String> scopes){
    return new PrincipalContext(subject,tenant,PrincipalContext.ActorType.HUMAN,null,"authentication","issuer","audience",scopes);
  }
  PolicyBundle policy(Set<String> operationalDetails,Map<String,String> sourceScope,boolean deny){
    var constraints=new GrantConstraints("ALLOW",null,null,null,sourceScope,labels,operationalDetails,null,Set.of(),null);
    var descriptor=new CapabilityDescriptor(cap,"READ",cap,Set.of(PrincipalContext.ActorType.HUMAN));
    var grants=new ArrayList<Grant>();
    grants.add(new Grant("legacy",cap,"tenant","operator",null,null,now.minusSeconds(60),now.plusSeconds(600)));
    grants.add(new Grant("role",cap,"tenant","operator",null,null,now.minusSeconds(60),now.plusSeconds(600),constraints));
    if(deny)grants.add(new Grant("deny",cap,"tenant","operator",null,null,now.minusSeconds(60),now.plusSeconds(600),
      new GrantConstraints("DENY",null,null,null,Map.of(),Set.of("RESTRICTED"),Set.of(),null,Set.of(),null)));
    return new PolicyBundle("fixture",1,now,List.of(descriptor),grants);
  }
  boolean allowed(PolicyBundle policy,PrincipalContext principal,String tenant,String label,String source){
    var attributes=new HashMap<String,String>();
    attributes.put("module","UDP");attributes.put("requiresDataAccessLabel","true");
    attributes.put("dataAccessLabel",label);attributes.put("sourceRef",source);
    attributes.put("propertyIri","urn:fixture:property");attributes.put("revisionRef","fixture-revision");
    return AuthorizationPolicy.evaluate(policy,principal,new ResourceContext("object","fixture-object",tenant,null,attributes),cap,"READ",now).allowed();
  }
  @Test void currentCombinedConstraintsExplainIdentityOnlyVisibility(){
    var p=actor("operator","tenant",Set.of(cap));var before=policy(details,Map.of(),false);
    assertThat(allowed(before,p,"tenant","OPEN","source")).isTrue();
    assertThat(allowed(before,p,"tenant","RESTRICTED","source")).isFalse();
    assertThat(allowed(before,p,"tenant","PERSONAL","source")).isFalse();
  }
  @Test void removingOnlyOperationalDetailConstraintRetainsDataAndIdentityBoundaries(){
    var corrected=policy(Set.of(),Map.of(),false);var p=actor("operator","tenant",Set.of(cap));
    for(String label:labels)assertThat(allowed(corrected,p,"tenant",label,"source")).isTrue();
    assertThat(allowed(corrected,p,"tenant","UNKNOWN","source")).isFalse();
    assertThat(allowed(corrected,actor("other","tenant",Set.of(cap)),"tenant","RESTRICTED","source")).isFalse();
    assertThat(allowed(corrected,actor("operator","other",Set.of(cap)),"tenant","RESTRICTED","source")).isFalse();
    assertThat(allowed(corrected,actor("operator","tenant",Set.of()),"tenant","RESTRICTED","source")).isFalse();
  }
  @Test void sourceRestrictionAndExplicitDenyStillWin(){
    var p=actor("operator","tenant",Set.of(cap));
    var scoped=policy(Set.of(),Map.of("sourceRef","source"),false);
    assertThat(allowed(scoped,p,"tenant","RESTRICTED","source")).isTrue();
    assertThat(allowed(scoped,p,"tenant","RESTRICTED","other")).isFalse();
    assertThat(allowed(policy(Set.of(),Map.of(),true),p,"tenant","RESTRICTED","source")).isFalse();
  }
}
