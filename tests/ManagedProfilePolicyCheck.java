package it.comune.trieste.ouf.authorization;
import java.time.Instant;
import java.util.*;
import it.comune.trieste.ouf.authorization.AuthorizationPolicy.*;
/** Original evaluator plus redacted configured-grant fixtures; no tokens, DB or live service. */
public class ManagedProfilePolicyCheck {
 static final Instant NOW=Instant.parse("2026-11-07T16:42:29Z");
 static final String PROFILE="ouf.managed-source.file.profile", PREVIEW="ouf.managed-source.preview";
 static int checked;
 static List<Grant> grants(boolean fixed) {
  var grants=new ArrayList<Grant>();
    grants.add(new Grant("fixture-0","ouf.managed-source.preview","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-10-27T13:09:04Z"),Instant.parse("2026-10-27T14:09:04Z"),new GrantConstraints("ALLOW",null,"capability",null,Map.ofEntries(),Set.of(),Set.of(),null,Set.of(),null)));
    grants.add(new Grant("fixture-1","ouf.managed-source.onboarding.create","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-09-25T00:00:00Z"),Instant.parse("2026-10-25T00:00:00Z"),null));
    grants.add(new Grant("fixture-2","ouf.managed-source.preview","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-09-25T00:00:00Z"),Instant.parse("2026-10-25T00:00:00Z"),null));
    grants.add(new Grant("fixture-3","ouf.managed-source.file.profile","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-09-25T00:00:00Z"),Instant.parse("2026-10-25T00:00:00Z"),null));
    grants.add(new Grant("fixture-4","ouf.managed-source.file.upload","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-09-25T00:00:00Z"),Instant.parse("2026-10-25T00:00:00Z"),null));
    grants.add(new Grant("fixture-5","ouf.managed-source.file.upload","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-09-28T00:00:00Z"),Instant.parse("2036-09-15T07:13:50.968730Z"),new GrantConstraints("ALLOW",null,"capability",null,Map.ofEntries(),Set.of(),Set.of(),null,Set.of(),null)));
    grants.add(new Grant("fixture-6","ouf.managed-source.preview","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-09-28T00:00:00Z"),Instant.parse("2036-09-15T07:13:50.968730Z"),(fixed ? new GrantConstraints("ALLOW",null,"managed-profile-job",null,Map.ofEntries(Map.entry("module","ONBOARDING")),Set.of(),Set.of("TENANT_OPERATIONAL"),null,Set.of(),null) : new GrantConstraints("ALLOW",null,null,null,Map.ofEntries(),Set.of("ANONYMOUS","OPEN","PERSONAL","RESTRICTED","SENSITIVE"),Set.of("PUBLIC_OPERATIONAL","RESTRICTED_OPERATIONAL","SECURITY_SENSITIVE","TENANT_OPERATIONAL"),null,Set.of(),null))));
    grants.add(new Grant("fixture-7","ouf.managed-source.file.profile","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-09-28T00:00:00Z"),Instant.parse("2036-09-15T07:13:50.968730Z"),(fixed ? new GrantConstraints("ALLOW",null,"capability",null,Map.ofEntries(),Set.of(),Set.of(),null,Set.of(),null) : new GrantConstraints("ALLOW",null,null,null,Map.ofEntries(),Set.of("ANONYMOUS","OPEN","PERSONAL","RESTRICTED","SENSITIVE"),Set.of("PUBLIC_OPERATIONAL","RESTRICTED_OPERATIONAL","SECURITY_SENSITIVE","TENANT_OPERATIONAL"),null,Set.of(),null))));
    grants.add(new Grant("fixture-8","ouf.managed-source.onboarding.create","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-09-28T00:00:00Z"),Instant.parse("2036-09-15T07:13:50.968730Z"),fixed ? new GrantConstraints("ALLOW",null,"capability",null,Map.of(),Set.of(),Set.of(),null,Set.of(),null) : new GrantConstraints("ALLOW",null,null,null,Map.ofEntries(),Set.of("ANONYMOUS","OPEN","PERSONAL","RESTRICTED","SENSITIVE"),Set.of("PUBLIC_OPERATIONAL","RESTRICTED_OPERATIONAL","SECURITY_SENSITIVE","TENANT_OPERATIONAL"),null,Set.of(),null)));
    grants.add(new Grant("fixture-9","ouf.managed-source.file.profile","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-10-28T08:29:35.837Z"),Instant.parse("2036-09-15T07:13:50.968730Z"),new GrantConstraints("ALLOW",null,"managed-profile-job","prior-job",Map.ofEntries(Map.entry("assetRef","prior-assetRef"),Map.entry("detailLevel","TENANT_OPERATIONAL"),Map.entry("jobRef","prior-jobRef"),Map.entry("module","ONBOARDING")),Set.of(),Set.of("TENANT_OPERATIONAL"),null,Set.of(),null)));
    grants.add(new Grant("fixture-10","ouf.managed-source.onboarding.read","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-09-28T00:00:00Z"),Instant.parse("2036-09-15T07:13:50.968730Z"),new GrantConstraints("ALLOW",null,"source",null,Map.ofEntries(),Set.of(),Set.of(),null,Set.of(),null)));
    grants.add(new Grant("fixture-11","ouf.managed-source.file.profile","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-10-26T16:34:29.450Z"),Instant.parse("2026-10-26T18:34:29.450Z"),new GrantConstraints("ALLOW",null,"capability",null,Map.ofEntries(),Set.of(),Set.of(),null,Set.of(),null)));
    grants.add(new Grant("fixture-12","ouf.managed-source.preview","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-10-28T08:29:35.837Z"),Instant.parse("2036-09-15T07:13:50.968730Z"),new GrantConstraints("ALLOW",null,"managed-profile-job","prior-job",Map.ofEntries(Map.entry("assetRef","prior-assetRef"),Map.entry("detailLevel","TENANT_OPERATIONAL"),Map.entry("jobRef","prior-jobRef"),Map.entry("module","ONBOARDING")),Set.of(),Set.of("TENANT_OPERATIONAL"),null,Set.of(),null)));
    grants.add(new Grant("fixture-13","ouf.managed-source.file.upload","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-10-26T16:34:29.450Z"),Instant.parse("2026-10-26T18:34:29.450Z"),new GrantConstraints("ALLOW",null,"capability",null,Map.ofEntries(),Set.of(),Set.of(),null,Set.of(),null)));
    grants.add(new Grant("fixture-14","ouf.managed-source.preview","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-10-28T22:34:26Z"),Instant.parse("2036-09-15T07:13:50.968730Z"),new GrantConstraints("ALLOW",null,"capability",null,Map.ofEntries(),Set.of(),Set.of(),null,Set.of(),null)));
    grants.add(new Grant("fixture-15","ouf.managed-source.preview","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-10-26T16:34:29.450Z"),Instant.parse("2026-10-26T18:34:29.450Z"),new GrantConstraints("ALLOW",null,"capability",null,Map.ofEntries(),Set.of(),Set.of(),null,Set.of(),null)));
    grants.add(new Grant("fixture-16","ouf.managed-source.onboarding.review.prepare","tenant-fixture","caller-fixture",null,null,Instant.parse("2026-09-28T00:00:00Z"),Instant.parse("2036-09-15T07:13:50.968730Z"),new GrantConstraints("ALLOW",null,"source",null,Map.ofEntries(),Set.of(),Set.of(),null,Set.of(),null)));
  return grants;
 }
 static PrincipalContext principal(String subject,String tenant,boolean scope,boolean human) {
  return new PrincipalContext(subject,tenant,human?PrincipalContext.ActorType.HUMAN:PrincipalContext.ActorType.SERVICE,
   human?null:"service-fixture","fixture-context","fixture-issuer","fixture-audience",
   scope?Set.of(PROFILE,PREVIEW,"ouf.managed-source.file.upload","ouf.managed-source.onboarding.create"):Set.of());
 }
 static ResourceContext capability(){return new ResourceContext("capability",null,"tenant-fixture",null,Map.of());}
 static ResourceContext job(String module,String detail){
  return new ResourceContext("managed-profile-job","current-job","tenant-fixture",null,Map.of("module",module,"assetRef","current-asset","jobRef","current-job","detailLevel",detail));
 }
 static String decide(boolean fixed,String cap,ResourceContext resource,PrincipalContext p,boolean explicitDeny) {
  var gs=new ArrayList<Grant>(grants(fixed));
  if(explicitDeny)gs.add(new Grant("fixture-deny",cap,"tenant-fixture","caller-fixture",null,null,NOW.minusSeconds(1),NOW.plusSeconds(60),
   new GrantConstraints("DENY",null,resource.resourceType(),null,Map.of(),Set.of(),resource.attributes().containsKey("detailLevel")?Set.of(resource.attributes().get("detailLevel")):Set.of(),null,Set.of(),null)));
  var caps=List.of(new CapabilityDescriptor(PROFILE,"COMMAND",PROFILE,Set.of(PrincipalContext.ActorType.HUMAN)),
   new CapabilityDescriptor(PREVIEW,"READ",PREVIEW,Set.of(PrincipalContext.ActorType.HUMAN)),
   new CapabilityDescriptor("ouf.managed-source.file.upload","COMMAND","ouf.managed-source.file.upload",Set.of(PrincipalContext.ActorType.HUMAN)),
   new CapabilityDescriptor("ouf.managed-source.onboarding.create","COMMAND","ouf.managed-source.onboarding.create",Set.of(PrincipalContext.ActorType.HUMAN)),
   new CapabilityDescriptor("ouf.managed-source.onboarding.read","READ","ouf.managed-source.onboarding.read",Set.of(PrincipalContext.ActorType.HUMAN)),
   new CapabilityDescriptor("ouf.managed-source.onboarding.review.prepare","COMMAND","ouf.managed-source.onboarding.review.prepare",Set.of(PrincipalContext.ActorType.HUMAN)));
  var policy=new PolicyBundle("fixture",60,NOW,caps,gs);
  return AuthorizationPolicy.evaluate(policy,p,resource,cap,cap.equals(PREVIEW)?"READ":"COMMAND",NOW).decisionCode();
 }
 static void check(String name,String actual,String expected) {
  if(!actual.equals(expected))throw new AssertionError(name+"="+actual+", expected "+expected);
  checked++;System.out.println(name+"="+actual);
 }
 public static void main(String[] args) {
  var caller=principal("caller-fixture","tenant-fixture",true,true);
  check("current-profile",decide(false,PROFILE,capability(),caller,false),"NO_APPLICABLE_GRANT");
  check("proposed-profile",decide(true,PROFILE,capability(),caller,false),"ALLOW");
  check("current-new-job-read",decide(false,PREVIEW,job("ONBOARDING","TENANT_OPERATIONAL"),caller,false),"NO_APPLICABLE_GRANT");
  check("proposed-new-job-read",decide(true,PREVIEW,job("ONBOARDING","TENANT_OPERATIONAL"),caller,false),"ALLOW");
  check("existing-profile-preview-preserved",decide(true,PREVIEW,capability(),caller,false),"ALLOW");
  check("published-upload-preserved",decide(true,"ouf.managed-source.file.upload",capability(),caller,false),"ALLOW");
  check("current-create",decide(false,"ouf.managed-source.onboarding.create",capability(),caller,false),"NO_APPLICABLE_GRANT");
  check("proposed-create",decide(true,"ouf.managed-source.onboarding.create",capability(),caller,false),"ALLOW");
  check("missing-scope",decide(true,PROFILE,capability(),principal("caller-fixture","tenant-fixture",false,true),false),"SCOPE_MISSING");
  check("other-subject",decide(true,PROFILE,capability(),principal("other","tenant-fixture",true,true),false),"NO_APPLICABLE_GRANT");
  check("other-tenant",decide(true,PROFILE,capability(),principal("caller-fixture","other",true,true),false),"TENANT_MISMATCH");
  check("service-actor",decide(true,PROFILE,capability(),principal("caller-fixture","tenant-fixture",true,false),false),"ACTOR_NOT_ALLOWED");
  check("other-module",decide(true,PREVIEW,job("INGESTION","TENANT_OPERATIONAL"),caller,false),"NO_APPLICABLE_GRANT");
  check("security-detail",decide(true,PREVIEW,job("ONBOARDING","SECURITY_SENSITIVE"),caller,false),"NO_APPLICABLE_GRANT");
  check("explicit-deny",decide(true,PREVIEW,job("ONBOARDING","TENANT_OPERATIONAL"),caller,true),"EXPLICIT_DENY");
  check("sensitive-profile-resource",decide(true,PROFILE,new ResourceContext("capability",null,"tenant-fixture",null,Map.of("dataAccessLabel","SENSITIVE")),caller,false),"NO_APPLICABLE_GRANT");
  System.out.println("checks="+checked+" PASS; synthetic principal, no live token validation");
 }
}

