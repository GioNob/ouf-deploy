package it.comune.trieste.ouf.udp;

import java.sql.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Isolated release qualification, never executed against the retained installation. */
class LinkedPropertyUpgradeTest {
  @Test void upgradesPopulatedV34WithoutRewritingEvidenceAndRemainsIdempotent() throws Exception {
    String url=System.getenv("OUF_UDP_DB_URL"), user=System.getenv("OUF_UDP_DB_USER"), password=System.getenv("OUF_UDP_DB_PASSWORD");
    try(Connection c=DriverManager.getConnection(url,user,password); Statement s=c.createStatement()) {
      assertEquals("false",one(s,"select (rolsuper or rolcreaterole or rolcreatedb)::text from pg_roles where rolname=current_user"));
    }
    var old=Flyway.configure().dataSource(url,user,password).schemas("ouf_udp").defaultSchema("ouf_udp").target("34").load();
    assertEquals(34,old.migrate().migrationsExecuted);
    // Historical V1 creates the schema. V35 is qualified after removing that
    // bootstrap privilege; the application keeps only schema/table ownership.
    try(Connection admin=DriverManager.getConnection(url,"ci_admin",System.getenv("OUF_UPGRADE_ADMIN_PASSWORD")); Statement s=admin.createStatement()) {
      s.execute("revoke create on database ouf_upgrade from ouf_udp");
    }
    try(Connection c=DriverManager.getConnection(url,user,password); Statement s=c.createStatement()) {
      assertEquals("false",one(s,"select has_database_privilege(current_user,current_database(),'CREATE')::text"));
      s.execute("insert into ouf_udp.handoff_intake(handoff_id,ingestion_run_id,ingestion_id,source_id,type_code,source_object_id,content_hash,payload_json,receipt_ref) values('upgrade-h','upgrade-run','upgrade-in','api-source','asset','record-1','hash','{}','receipt-upgrade')");
      s.execute("insert into ouf_udp.urban_object(urban_object_id,canonical_type) values('00000000-0000-0000-0000-000000000001','urn:asset')");
      s.execute("insert into ouf_udp.object_revision(revision_id,urban_object_id,revision_no,canonical_hash,authority_hash,authority_state,canonical_payload,access_labels,source_handoff_id,bundle_ref,semantic_publication_ref) values('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001',1,'canonical','authority','{}','{\"name\":\"Retained\"}','[\"OPEN\"]','upgrade-h','bundle:1','semantic:1')");
      s.execute("insert into ouf_udp.property_contribution(contribution_id,urban_object_id,handoff_id,property_iri,value_json,value_hash,access_label,source_id,authority_rank,provenance_json) values('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000001','upgrade-h','urn:name','\"Retained\"','value-hash','OPEN','api-source',0,'{\"original\":true}')");
      s.execute("insert into ouf_udp.property_value(property_value_id,revision_id,property_iri,value_json,datatype,access_label,contribution_id) values('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000002','urn:name','\"Retained\"','string','OPEN','00000000-0000-0000-0000-000000000003')");
      String value=one(s,"select to_jsonb(v)::text from ouf_udp.property_value v");
      String revision=one(s,"select to_jsonb(v)::text from ouf_udp.object_revision v");
      String contribution=one(s,"select to_jsonb(v)::text from ouf_udp.property_contribution v");
      var current=Flyway.configure().dataSource(url,user,password).schemas("ouf_udp").defaultSchema("ouf_udp").load();
      assertEquals(1,current.migrate().migrationsExecuted);
      assertEquals("35",current.info().current().getVersion().toString());
      assertEquals(value,one(s,"select (to_jsonb(v)-'reconciliation_evidence')::text from ouf_udp.property_value v"));
      assertEquals("true",one(s,"select (reconciliation_evidence is null)::text from ouf_udp.property_value"));
      assertEquals(revision,one(s,"select to_jsonb(v)::text from ouf_udp.object_revision v"));
      assertEquals(contribution,one(s,"select to_jsonb(v)::text from ouf_udp.property_contribution v"));
      assertEquals("0",one(s,"select count(*)::text from ouf_udp.handoff_property_profile"));
      s.execute("insert into ouf_udp.handoff_property_profile values('upgrade-h','urn:asset','bundle:1','{}','profile-hash')");
      assertThrows(SQLException.class,()->s.execute("update ouf_udp.handoff_property_profile set profile_hash='changed'"));
      assertThrows(SQLException.class,()->s.execute("delete from ouf_udp.handoff_property_profile"));
      assertThrows(SQLException.class,()->s.execute("delete from ouf_udp.property_contribution"));
      current.validate();
      assertEquals(0,current.migrate().migrationsExecuted);
    }
  }
  private static String one(Statement s,String sql) throws SQLException {
    try(ResultSet r=s.executeQuery(sql)){assertTrue(r.next());String value=r.getString(1);assertFalse(r.next());return value;}
  }
}
