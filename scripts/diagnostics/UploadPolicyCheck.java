package it.comune.trieste.ouf.authorization;
import java.time.Instant;
import java.util.*;
import it.comune.trieste.ouf.authorization.AuthorizationPolicy.*;
public class UploadPolicyCheck {
 static final String CAP="ouf.managed-source.file.upload";
 static final Instant NOW=Instant.parse("2026-11-07T15:00:00Z");
 static final Set<String> LABELS=Set.of("ANONYMOUS","OPEN","PERSONAL","RESTRICTED","SENSITIVE");
 static final Set<String> DETAILS=Set.of("PUBLIC_OPERATIONAL","RESTRICTED_OPERATIONAL","SECURITY_SENSITIVE","TENANT_OPERATIONAL");
 static int checked;
 static PrincipalContext principal(String subject,String tenant,PrincipalContext.ActorType actor,boolean scoped) {
  return new PrincipalContext(subject,tenant,actor,actor==PrincipalContext.ActorType.SERVICE?"service-fixture":null,"fixture-context","fixture-issuer","fixture-audience",scoped?Set.of(CAP):Set.of());
 }
 static GrantConstraints constraints(boolean labels,boolean details,String type,String effect) {
  return new GrantConstraints(effect,null,type,null,Map.of(),labels?LABELS:Set.of(),details?DETAILS:Set.of(),null,Set.of(),null);
 }
 static Grant grant(String id,GrantConstraints c,Instant until) {
  return new Grant(id,CAP,"tenant-fixture","admin-fixture",null,null,Instant.parse("2026-09-28T00:00:00Z"),until,c);
 }
 static String decision(GrantConstraints c,PrincipalContext p,ResourceContext resource,boolean expired,boolean deny) {
  var grants=new ArrayList<Grant>();
  grants.add(grant("existing-role",c,Instant.parse(expired?"2026-10-25T00:00:00Z":"2036-09-15T07:13:50.968730Z")));
  grants.add(grant("expired-direct",null,Instant.parse("2026-10-25T00:00:00Z")));
  if(deny)grants.add(grant("explicit-deny",constraints(false,false,"capability","DENY"),Instant.parse("2036-09-15T07:13:50.968730Z")));
  var bundle=new PolicyBundle("fixture-policy",59,NOW,List.of(new CapabilityDescriptor(CAP,"WRITE",CAP,Set.of(PrincipalContext.ActorType.HUMAN))),grants);
  return AuthorizationPolicy.evaluate(bundle,p,resource,CAP,"WRITE",NOW).decisionCode();
 }
 static void check(String name,String actual,String expected) {
  if(!actual.equals(expected))throw new AssertionError(name+": "+actual+" != "+expected);
  checked++;System.out.println(name+"="+actual);
 }
 public static void main(String[] args) {
  var admin=principal("admin-fixture","tenant-fixture",PrincipalContext.ActorType.HUMAN,true);
  var page=new ResourceContext("capability",null,"tenant-fixture",null,Map.of());
  var proposed=constraints(false,false,"capability","ALLOW");
  check("current-role-on-picker",decision(constraints(true,true,null,"ALLOW"),admin,page,false,false),"NO_APPLICABLE_GRANT");
  check("removing-only-labels-insufficient",decision(constraints(false,true,null,"ALLOW"),admin,page,false,false),"NO_APPLICABLE_GRANT");
  check("removing-only-detail-insufficient",decision(constraints(true,false,null,"ALLOW"),admin,page,false,false),"NO_APPLICABLE_GRANT");
  check("proposed-role-on-picker",decision(proposed,admin,page,false,false),"ALLOW");
  check("other-subject",decision(proposed,principal("other","tenant-fixture",PrincipalContext.ActorType.HUMAN,true),page,false,false),"NO_APPLICABLE_GRANT");
  check("other-tenant",decision(proposed,principal("admin-fixture","other-tenant",PrincipalContext.ActorType.HUMAN,true),page,false,false),"TENANT_MISMATCH");
  check("missing-scope",decision(proposed,principal("admin-fixture","tenant-fixture",PrincipalContext.ActorType.HUMAN,false),page,false,false),"SCOPE_MISSING");
  check("nonhuman",decision(proposed,principal("admin-fixture","tenant-fixture",PrincipalContext.ActorType.SERVICE,true),page,false,false),"ACTOR_NOT_ALLOWED");
  check("expired-assignment",decision(proposed,admin,page,true,false),"NO_APPLICABLE_GRANT");
  check("explicit-deny",decision(proposed,admin,page,false,true),"EXPLICIT_DENY");
  check("other-resource-type",decision(proposed,admin,new ResourceContext("managed-file","fixture-id","tenant-fixture",null,Map.of()),false,false),"NO_APPLICABLE_GRANT");
  check("restricted-payload-not-granted",decision(proposed,admin,new ResourceContext("capability",null,"tenant-fixture",null,Map.of("dataAccessLabel","RESTRICTED")),false,false),"NO_APPLICABLE_GRANT");
  check("sensitive-detail-not-granted",decision(proposed,admin,new ResourceContext("capability",null,"tenant-fixture",null,Map.of("detailLevel","SECURITY_SENSITIVE")),false,false),"NO_APPLICABLE_GRANT");
  System.out.println("checks="+checked+" PASS");
 }
}
