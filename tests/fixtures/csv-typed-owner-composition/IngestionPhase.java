package it.comune.trieste.ouf.ingestion;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import it.comune.trieste.ouf.ingestion.*;
import java.nio.file.*;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.support.TransactionTemplate;

/** Real production mapper/pipeline and PG persistence; synthetic semantic/lake ports. */
public final class IngestionPhase {
  @SuppressWarnings("unchecked") static Map<String,Object> object(Map<String,Object> value,String key){return (Map<String,Object>)value.get(key);}
  public static void main(String[] args)throws Exception {
    var json=new ObjectMapper().findAndRegisterModules();var input=json.readValue(Path.of(args[0]).toFile(),Map.class);
    var configuration=object(input,"configuration");String source=(String)input.get("sourceId");
    byte[] csv=Base64.getDecoder().decode((String)input.get("csvBase64"));
    var candidate=new LinkedHashMap<String,Object>();candidate.put("sourceId",source);
    candidate.put("onboardingVersionId","00000000-0000-4000-8000-000000000005");candidate.put("version","1");
    candidate.put("state","IN_REVIEW");candidate.put("configuration",configuration);
    String hash=FrozenConfigurationProbe.configurationHash(json,configuration);candidate.put("configurationHash",hash);
    var probe=new FrozenConfigurationProbe(json,(ref,size,expected)->csv,refs->{
      if(!List.of("urn:fixture:ontology@1").equals(List.copyOf(refs)))throw new IllegalStateException("FIXTURE_SEMANTIC_PIN_CHANGED");
    }).probe(candidate);
    if(!"PASS".equals(probe.get("status"))||((Number)probe.get("validatedRows")).longValue()!=1)throw new IllegalStateException("COMPOSED_COMPATIBILITY_FAILED");
    var published=new LinkedHashMap<String,Object>(object(configuration,"bundle"));
    for(String key:List.of("extractionProfile","semanticMapping","sourceObjectIdentityPolicy","changeRepresentationProfile","dataAccessPolicies","semanticReferenceBindings"))published.put(key,configuration.get(key));
    published.put("semanticRefs",object(configuration,"semanticMapping").get("semanticRefs"));
    var snapshot=new ExecutionBundle((String)published.get("bundleId"),"1",hash,source,"MANAGED",null,
      Map.of("publishedBundle",published,"pinnedReferences",published.get("semanticRefs")));
    var bundle=PublishedExecutionMapper.map(snapshot);
    var ds=new DriverManagerDataSource(System.getenv("OUF_CSV_DB_URL"),System.getenv("OUF_CSV_DB_USER"),System.getenv("OUF_CSV_DB_PASSWORD"));
    // A dedicated disposable database only; this is not rollout/admission code.
    Flyway.configure().dataSource(ds).schemas("ouf_ingestion").defaultSchema("ouf_ingestion").createSchemas(true).locations("filesystem:"+args[2]).load().migrate();
    var sql=JdbcClient.create(ds);var transactions=new TransactionTemplate(new DataSourceTransactionManager(ds));
    var durable=new DurablePipelineRepository(sql,json);
    var metrics=new IngestionMetrics(new SimpleMeterRegistry(),sql);
    var quarantine=new QuarantineService(sql,json,metrics,new StaticListableBeanFactory().getBeanProvider(RuntimePorts.ActiveBundlePort.class));
    var raw=new ArrayList<byte[]>();
    RuntimePorts.DataLakePort lake=(zone,run,record,bytes,digest,key)->{
      if(zone==RuntimePorts.DataLakePort.Zone.RAW)raw.add(bytes.clone());
      return new RuntimePorts.DataLakePort.Receipt("lake://fixture/"+zone.name().toLowerCase()+"/"+run+"/"+key,true);
    };
    var pipeline=new CanonicalRecordPipeline(json,new FrozenContractValidator(json),durable,quarantine,lake);
    var handoffs=new ArrayList<Map<String,Object>>();var records=new HashSet<String>();
    for(int acquisition=0;acquisition<2;acquisition++) {
      UUID run=UUID.randomUUID();
      sql.sql("insert into ouf_ingestion.ing_run(run_id,source_id,bundle_id,bundle_version,bundle_checksum,mode,state,correlation_id) values(:r,:s,:b,'1',:h,'MANAGED_ONCE','RUNNING','typed-fixture')")
        .param("r",run).param("s",source).param("b",bundle.bundleId()).param("h",hash).update();
      sql.sql("insert into ouf_ingestion.ing_partition(run_id,partition_key,state) values(:r,'default','RUNNING')").param("r",run).update();
      try(var cursor=new ManagedTabularAdapter((ref,size,expected)->csv).open(bundle,new AdapterSpi.Checkpoint(Map.of()))) {
        var record=cursor.next().orElseThrow();records.add(record.sourceObjectId());
        if(cursor.next().isPresent())throw new IllegalStateException("FIXTURE_EXPECTED_ONE_ROW");
        var result=transactions.execute(status->pipeline.process(new CanonicalRecordPipeline.Command(run,"default",1,1,"managed-tabular-v1",bundle,record,"typed-fixture",Map.of("ordinal",1),Map.of("ordinal",1))));
        if(result==null||!result.succeeded())throw new IllegalStateException("COMPOSED_INGESTION_FAILED");
        String payload=sql.sql("select payload_json::text from ouf_ingestion.handoff_outbox where handoff_id=:h").param("h",result.handoffId()).query(String.class).single();
        handoffs.add(json.readValue(payload,Map.class));
        String lineage=sql.sql("select evidence_json::text from ouf_ingestion.ing_lineage where lineage_id=:l").param("l",result.lineageId()).query(String.class).single();
        if(!lineage.contains("DECIMAL_COMMA_V1")||!lineage.contains("DATE_DMY_V1"))throw new IllegalStateException("COMPOSED_RULE_LINEAGE_MISSING");
      }
    }
    if(records.size()!=1||raw.size()!=2||!new String(raw.getFirst(),java.nio.charset.StandardCharsets.UTF_8).contains("12,3400"))throw new IllegalStateException("COMPOSED_RAW_OR_IDENTITY_DRIFT");
    input.put("handoffs",handoffs);input.put("configurationHash",hash);
    json.writeValue(Path.of(args[1]).toFile(),input);
    System.out.println("OUF_TYPED_OWNER_PHASE=INGESTION_TWO_NEW_ACQUISITIONS_RAW_LINEAGE_OUTBOX_PROVEN_NO_ACK_CLAIM");
  }
}
