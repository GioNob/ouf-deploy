package ouf.fixture;

import com.fasterxml.jackson.databind.ObjectMapper;
import it.comune.trieste.ouf.onboarding.application.ConfigurationValidator;
import it.comune.trieste.ouf.onboarding.application.ManagedFileExecutionProposal;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Disposable owner-contract fixture. All semantic/HUMAN decisions are synthetic. */
public final class OnboardingPhase {
  static Map<String,Object> map(Object... values){var out=new LinkedHashMap<String,Object>();for(int i=0;i<values.length;i+=2)out.put((String)values[i],values[i+1]);return out;}
  public static void main(String[] args)throws Exception {
    var json=new ObjectMapper();String source="csv-typed-fixture",ontology="urn:fixture:ontology",type="urn:fixture:Facility";
    String asset="00000000-0000-4000-8000-000000000001",profile="00000000-0000-4000-8000-000000000002";
    String revision="00000000-0000-4000-8000-000000000003",publication="00000000-0000-4000-8000-000000000004";
    byte[] csv="id;amount;day\nA;12,3400;29/02/2024\n".getBytes(StandardCharsets.UTF_8);
    String hash="sha256:"+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(csv));
    var mappings=new ArrayList<Map<String,Object>>();var labels=new ArrayList<Map<String,Object>>();
    var properties=new ArrayList<Map<String,Object>>();var signals=new ArrayList<Map<String,Object>>();
    for(String field:List.of("id","amount","day")) {
      String iri="urn:fixture:"+field;
      String transform=field.equals("amount")?"DECIMAL_COMMA_V1":field.equals("day")?"DATE_DMY_V1":"IDENTITY";
      String datatype="http://www.w3.org/2001/XMLSchema#"+(field.equals("amount")?"decimal":field.equals("day")?"date":"string");
      mappings.add(map("sourceField",field,"targetPropertyIri",iri,"transform",transform));
      labels.add(map("scope","PROPERTY","target",iri,"label","RESTRICTED"));
      properties.add(map("sourceField",iri,"propertyIri",iri,"datatype",datatype,"accessLabel","RESTRICTED","authorityOrder",List.of(source)));
      signals.add(map("id",iri,"semanticRef",iri+"@"+publication,"comparator",field.equals("amount")?"DECIMAL_V1":"TEXT_V1",
        "excludesOnDisagreement",false,"uniqueWithinScope",false,"assertionRef","urn:fixture:reviewed-assertion"));
    }
    var runtime=map("mode","MANAGED","recordModel","ONE_ROW_ONE_SOURCE_OBJECT","rowIdentityBasis","APPROVED_SOURCE_FIELDS",
      "assetId",asset,"fileProfileId",profile,"stagingRef","managed://fixture/source.csv","contentHash",hash,"csvDelimiter",";");
    var semantic=map("mappingId","sm-typed-fixture","sourceType",map("sourceId",source,"typeCode","FILE"),
      "targetClasses",List.of(map("ontologyId",ontology,"ontologyVersion","1","classIri",type)),
      "propertyMappings",mappings,"vocabularyMappings",List.of(),"semanticRefs",List.of(ontology+"@1"));
    var config=map("syncProfile",map("bootstrap","FULL_SNAPSHOT","incremental","NONE"),
      "sourceObjectIdentityPolicy",map("strategy","NATIVE_KEY","sourceFields",List.of("id"),"normalizationRuleRef","normalization://managed-file/native-key-v1"),
      "changeRepresentationProfile",map("mode","FULL_SNAPSHOT"),"semanticMapping",semantic,"dataAccessPolicies",labels,
      "extractionProfile",map("profileId","ep-typed","sourceId",source,"version","1","selection",map("assetId",asset,"fileProfileId",profile),
        "projection",map("FILE",List.of("id","amount","day")),"sync",map(),"runtime",runtime),
      "bundle",map("bundleId","bundle-typed-fixture","bundleVersion","1","environment","fixture",
        "source",map("sourceId",source,"sourceKind","INTERNAL_MANAGED","acquisitionMode","MANAGED"),
        "schemaRef","profile://managed-files/"+asset+"/profiles/"+profile,"createdFromOnboardingVersion","fixture-only",
        "effectiveFrom","2026-01-01T00:00:00Z","checksum","sha256:fixture-only","status","APPROVED"));
    var policy=map("ref","urn:fixture:identity-policy","version","1","tenantId","default","canonicalClass",type,"sourceId",source,
      "maxCandidates",10,"allowAutoNew",true,"signals",signals,"sufficientRules",List.of(map("id","stable-id","signalIds",List.of("urn:fixture:id"),"assertionRef","urn:fixture:reviewed-rule")));
    var udp=map("resolution",map("strategyId","GOVERNED_IDENTITY","strategyVersion","1","policyRef","urn:fixture:identity-policy","governedIdentity",policy),
      "materialization",map("policyRef","urn:fixture:authority-policy","properties",properties,"bitemporalProperties",List.of(),"checkpointInterval",1));
    var proposal=new ManagedFileExecutionProposal.Proposal(List.of(new ManagedFileExecutionProposal.SemanticBinding(ontology,"1",revision,publication)),publication,udp,new ManagedFileExecutionProposal.Limits(100,20,1000));
    var compiled=ManagedFileExecutionProposal.compile(config,map("asset_id",UUID.fromString(asset),"source_id",source,"staging_ref","managed://fixture/source.csv","content_hash",hash,"size_bytes",(long)csv.length),"default",proposal);
    var validation=new ConfigurationValidator().validate(source,compiled);
    if(!validation.valid())throw new IllegalStateException("COMPOSED_ONBOARDING_VALIDATION_FAILED:"+validation.findings());
    json.writeValue(Path.of(args[0]).toFile(),map("configuration",compiled,"sourceId",source,"canonicalType",type,"csvBase64",Base64.getEncoder().encodeToString(csv)));
    System.out.println("OUF_TYPED_OWNER_PHASE=ONBOARDING_COMPILED_NO_AUTHORITY");
  }
}
