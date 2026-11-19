package ouf.fixture;

import com.fasterxml.jackson.databind.ObjectMapper;
import it.comune.trieste.ouf.udp.*;
import java.math.BigDecimal;
import java.nio.file.*;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.support.TransactionTemplate;

/** Actual UDP intake, governed identity, index and materializer on disposable PG. */
public final class UdpPhase {
  @SuppressWarnings("unchecked") static Map<String,Object> object(Map<String,Object> value,String key){return (Map<String,Object>)value.get(key);}
  static void require(boolean ok,String code){if(!ok)throw new IllegalStateException(code);}
  @SuppressWarnings("unchecked") public static void main(String[] args)throws Exception {
    var json=new ObjectMapper().findAndRegisterModules();var input=json.readValue(Path.of(args[0]).toFile(),Map.class);
    var configuration=object(input,"configuration");var runtime=object(object(configuration,"extractionProfile"),"runtime");
    var udp=object(runtime,"udp");var profile=json.convertValue(udp.get("materialization"),UdpPorts.MaterializationProfile.class);
    var mapped=new HashSet<String>();profile.properties().forEach(p->mapped.add(p.propertyIri()));
    var policy=PublishedIdentityPolicy.decode(json,object(udp,"resolution"),"default",(String)input.get("sourceId"),(String)input.get("canonicalType"),mapped);
    var ds=new DriverManagerDataSource(System.getenv("OUF_CSV_DB_URL"),System.getenv("OUF_CSV_DB_USER"),System.getenv("OUF_CSV_DB_PASSWORD"));
    // Explicit fixture bootstrap, never a production startup migration path.
    Flyway.configure().dataSource(ds).schemas("ouf_udp").defaultSchema("ouf_udp").createSchemas(true).locations("filesystem:"+args[2]).load().migrate();
    var db=JdbcClient.create(ds);var tx=new TransactionTemplate(new DataSourceTransactionManager(ds));
    var locks=new GovernedIdentityScopeLock(db);
    var intake=new HandoffIntakeService(db,json,new FrozenContractValidator(json),null,tx,false,0,"","","default");
    var resolution=new GovernedIdentityResolutionService(db,json,locks,new ScopedIdentityCandidateRepository(db,json),new GovernedIdentityReviewRepository(db,json));
    var materializer=new CanonicalMaterializer(db,json,locks);var index=new GovernedIdentityIndexBackfill(db,json,locks);
    tx.execute(status->index.rebuild(policy));
    UUID objectId=null,revisionId=null;int acquisition=0;
    for(var handoff:(List<Map<String,Object>>)input.get("handoffs")) {
      String id=(String)handoff.get("handoffId");var receipt=intake.accept(handoff);require(receipt.durable(),"COMPOSED_UDP_INTAKE_NOT_DURABLE");
      final int ordinal=acquisition++;
      var proof=tx.execute(status->{
        materializer.rememberProfile(id,(String)input.get("canonicalType"),(String)object(handoff,"contractRefs").get("bundleRef"),profile);
        var decision=resolution.resolve(id,handoff,profile,policy);
        require((ordinal==0?"NEW_OBJECT":"MATCH").equals(decision.outcome()),"COMPOSED_IDENTITY_OUTCOME_CHANGED");
        require(!decision.duplicate()&&decision.coverageRef()!=null,"COMPOSED_IDENTITY_COVERAGE_MISSING");
        var result=materializer.materialize(id,decision.targetUrbanObjectId(),handoff,profile);
        index.refreshOne(policy,decision.targetUrbanObjectId(),decision.coverageRef());
        require(result.materialChange()==(ordinal==0),"COMPOSED_GRATUITOUS_CANONICAL_REVISION");
        return new Object[]{decision.targetUrbanObjectId(),result.revisionId()};
      });
      if(ordinal==0){objectId=(UUID)proof[0];revisionId=(UUID)proof[1];}
      else require(objectId.equals(proof[0])&&revisionId.equals(proof[1]),"COMPOSED_IDENTITY_OR_REVISION_DRIFT");
    }
    require(acquisition==2,"COMPOSED_EXPECTED_TWO_ACQUISITIONS");
    require(db.sql("select count(*) from ouf_udp.urban_object").query(Long.class).single()==1,"COMPOSED_CANONICAL_OBJECT_COUNT");
    require(db.sql("select count(*) from ouf_udp.object_revision").query(Long.class).single()==1,"COMPOSED_CANONICAL_REVISION_COUNT");
    require(db.sql("select count(*) from ouf_udp.materialization_observation").query(Long.class).single()==2,"COMPOSED_OBSERVATION_COUNT");
    var properties=db.sql("select property_iri,value_json::text value,datatype from ouf_udp.property_value").query().listOfRows();
    require(properties.size()==3,"COMPOSED_PROPERTY_COUNT");
    for(var property:properties){
      String iri=(String)property.get("property_iri");Object value=json.readValue((String)property.get("value"),Object.class);
      String datatype="http://www.w3.org/2001/XMLSchema#";
      if(iri.equals("urn:fixture:amount"))require(value instanceof Number&&new BigDecimal(value.toString()).compareTo(new BigDecimal("12.34"))==0&&(datatype+"decimal").equals(property.get("datatype")),"COMPOSED_DECIMAL_VALUE_OR_DATATYPE");
      else if(iri.equals("urn:fixture:day"))require("2024-02-29".equals(value)&&(datatype+"date").equals(property.get("datatype")),"COMPOSED_DATE_VALUE_OR_DATATYPE");
      else require("urn:fixture:id".equals(iri)&&"A".equals(value)&&(datatype+"string").equals(property.get("datatype")),"COMPOSED_STRING_VALUE_OR_DATATYPE");
    }
    require(db.sql("select count(distinct provenance_json->>'lineageRef') from ouf_udp.property_contribution").query(Long.class).single()==2,"COMPOSED_LINEAGE_NOT_RETAINED");
    require(db.sql("select count(distinct provenance_json->>'rawObjectRef') from ouf_udp.property_contribution").query(Long.class).single()==2,"COMPOSED_RAW_PROVENANCE_NOT_RETAINED");
    var proof=new LinkedHashMap<String,Object>();proof.put("composedTypedOwnerContract",true);proof.put("canonicalObjects",1);proof.put("canonicalRevisions",1);
    proof.put("acquisitions",2);proof.put("materializationObservations",2);proof.put("syntheticSemanticAndLakeBindings",true);
    proof.put("runtimeAuthorityIssued",false);proof.put("notReleaseAcceptance",true);proof.put("functionalMilestonesProven",4);
    json.writeValue(Path.of(args[1]).toFile(),proof);System.out.println("OUF_TYPED_OWNER_PROOF="+json.writeValueAsString(proof));
  }
}
