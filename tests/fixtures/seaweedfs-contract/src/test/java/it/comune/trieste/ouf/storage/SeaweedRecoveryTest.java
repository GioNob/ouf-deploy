package it.comune.trieste.ouf.storage;

import it.comune.trieste.ouf.udp.S3LakeObjectStorageAdapter;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import software.amazon.awssdk.services.s3.model.*;

class SeaweedRecoveryTest {
 @Test void restoresAllBytesMetadataAndNamespaceFromIndependentColdCopy() throws Exception {
  try(var udpClient=SeaweedContractTest.client("lab-udp","lab-udp-secret-not-production");var staging=SeaweedContractTest.client("lab-staging","lab-staging-secret-not-production");var admin=SeaweedContractTest.client("lab-admin","lab-admin-secret-not-production")){
   var udp=new S3LakeObjectStorageAdapter(udpClient,"ouf-udp");
   var inventory=udp.inventory();assertEquals(1004,inventory.size());
   for(var object:inventory){byte[] bytes=udp.read(object.locator());assertEquals(object.contentHash(),SeaweedContractTest.hash(bytes));assertEquals(object.sizeBytes(),bytes.length);}
   var managed=admin.listObjectsV2(ListObjectsV2Request.builder().bucket("ouf-managed-files").build()).contents();assertEquals(2,managed.size());
   byte[] big=new byte[10*1024*1024];new Random(42).nextBytes(big);
   Set<String> expected=new HashSet<>(List.of(SeaweedContractTest.hash(big),SeaweedContractTest.hash("codice,nome\n00001,Farmacia test sintetica\n".getBytes(java.nio.charset.StandardCharsets.UTF_8))));
   for(var object:managed){var response=staging.getObjectAsBytes(GetObjectRequest.builder().bucket("ouf-managed-files").key(object.key()).build());assertEquals("text/csv",response.response().contentType());assertTrue(expected.remove(SeaweedContractTest.hash(response.asByteArray())));}
   assertTrue(expected.isEmpty());assertTrue(udp.head("contract/one").isEmpty());
  }
 }
}
