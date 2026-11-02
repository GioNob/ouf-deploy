package it.comune.trieste.ouf.storage;

import it.comune.trieste.ouf.onboarding.application.MinioManagedFileStagingStore;
import it.comune.trieste.ouf.udp.S3LakeObjectStorageAdapter;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import software.amazon.awssdk.auth.credentials.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.*;
import software.amazon.awssdk.services.s3.model.*;

class SeaweedContractTest {
 static S3Client admin, udpClient, stagingClient;
 static MinioManagedFileStagingStore staging;
 static S3LakeObjectStorageAdapter udp;
 static final String ENDPOINT=System.getenv().getOrDefault("OUF_SW_ENDPOINT","http://127.0.0.1:18333");
 static S3Client client(String key,String secret){return S3Client.builder().endpointOverride(URI.create(ENDPOINT)).region(Region.US_EAST_1).credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(key,secret))).serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build()).build();}
 @BeforeAll static void setup() throws Exception {
  admin=client("lab-admin","lab-admin-secret-not-production");
  for(String bucket:List.of("ouf-managed-files","ouf-udp","ouf-versioned"))admin.createBucket(CreateBucketRequest.builder().bucket(bucket).build());
  String policy="""
   {"Version":"2012-10-17","Statement":[
    {"Sid":"DenyOutsideManagedPrefix","Effect":"Deny","Principal":"*","Action":["s3:GetObject","s3:PutObject"],"NotResource":"arn:aws:s3:::ouf-managed-files/managed-files/*"},
    {"Sid":"DenyStagingDeletion","Effect":"Deny","Principal":"*","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::ouf-managed-files/*"}
   ]}
   """;
  admin.putBucketPolicy(PutBucketPolicyRequest.builder().bucket("ouf-managed-files").policy(policy).build());
  Path d=Files.createTempDirectory("ouf-sw-client-");Path a=d.resolve("access"),s=d.resolve("secret");
  Files.writeString(a,"lab-staging");Files.writeString(s,"lab-staging-secret-not-production");
  staging=new MinioManagedFileStagingStore(ENDPOINT,"ouf-managed-files",a,s);
  stagingClient=client("lab-staging","lab-staging-secret-not-production");
  udpClient=client("lab-udp","lab-udp-secret-not-production");udp=new S3LakeObjectStorageAdapter(udpClient,"ouf-udp");
  Files.delete(a);Files.delete(s);Files.delete(d);
 }
 @AfterAll static void close(){if(admin!=null)admin.close();if(udpClient!=null)udpClient.close();if(stagingClient!=null)stagingClient.close();}
 static String hash(byte[] b)throws Exception{return "sha256:"+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
 @Test void onboardingOriginalAdapterRoundTripAndLimits() throws Exception {
  byte[] bytes="codice,nome\n00001,Farmacia test sintetica\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
  String ref=staging.put(new ByteArrayInputStream(bytes),bytes.length,"text/csv");
  assertTrue(ref.matches("object://managed-files/[a-f0-9-]{36}"));assertArrayEquals(bytes,staging.get(ref));
  assertThrows(IllegalArgumentException.class,()->staging.put(new ByteArrayInputStream(bytes),10*1024*1024+1,"text/csv"));
  assertThrows(IllegalArgumentException.class,()->staging.put(new ByteArrayInputStream(bytes),bytes.length,"application/json"));
 }
 @Test void onboardingTenMiBMultipart() throws Exception {
  byte[] bytes=new byte[10*1024*1024];new Random(42).nextBytes(bytes);
  String ref=staging.put(new ByteArrayInputStream(bytes),bytes.length,"text/csv");assertArrayEquals(bytes,staging.get(ref));
 }
 @Test void udpOriginalAdapterMetadataReadAndExactDelete() throws Exception {
  byte[] b="udp-synthetic-content".getBytes();String h=hash(b);
  var stored=udp.put("contract/one",b,"application/json",h);
  udp.put("contract/one-other",b,"application/json",h);
  assertTrue(stored.durable());assertEquals(h,stored.contentHash());assertEquals(b.length,stored.sizeBytes());
  assertArrayEquals(b,udp.read("contract/one"));assertEquals(h,hash(udp.read("contract/one")));
  udp.delete("contract/one");assertTrue(udp.head("contract/one").isEmpty());assertTrue(udp.head("contract/one-other").isPresent());
 }
 @Test void udpInventoryPaginatesBeyondThousand() throws Exception {
  byte[] b="x".getBytes();String h=hash(b);
  for(int i=0;i<1003;i++)udp.put("pages/"+i,b,"application/octet-stream",h);
  Set<String> keys=new HashSet<>();for(var o:udp.inventory())assertTrue(keys.add(o.locator()),"duplicate key");
  for(int i=0;i<1003;i++)assertTrue(keys.contains("pages/"+i));
 }
 @Test void crossBucketAndUnknownCredentialDenied() {
  S3Exception denied=assertThrows(S3Exception.class,()->stagingClient.headObject(HeadObjectRequest.builder().bucket("ouf-udp").key("contract/one-other").build()));assertEquals(403,denied.statusCode());
  try(S3Client unknown=client("unknown","invalid")){assertThrows(S3Exception.class,()->unknown.listBuckets());}
 }
 @Test void versionHistoryAndDeleteMarker() {
  admin.putBucketVersioning(PutBucketVersioningRequest.builder().bucket("ouf-versioned").versioningConfiguration(VersioningConfiguration.builder().status(BucketVersioningStatus.ENABLED).build()).build());
  for(String text:List.of("first-version","second-version"))admin.putObject(PutObjectRequest.builder().bucket("ouf-versioned").key("history/file").build(),software.amazon.awssdk.core.sync.RequestBody.fromString(text));
  admin.deleteObject(DeleteObjectRequest.builder().bucket("ouf-versioned").key("history/file").build());
  var history=admin.listObjectVersions(ListObjectVersionsRequest.builder().bucket("ouf-versioned").build());
  assertEquals(2,history.versions().size());assertEquals(1,history.deleteMarkers().size());
 }

 @Test void tlsRejectsAnUntrustedCertificate() throws Exception {
  assertTrue(ENDPOINT.startsWith("https://"));
  var empty=java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());empty.load(null,null);
  var factory=javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());factory.init(empty);
  var context=javax.net.ssl.SSLContext.getInstance("TLS");context.init(null,factory.getTrustManagers(),new java.security.SecureRandom());
  var connection=(javax.net.ssl.HttpsURLConnection)URI.create(ENDPOINT).toURL().openConnection();connection.setSSLSocketFactory(context.getSocketFactory());connection.setConnectTimeout(5000);connection.setReadTimeout(5000);
  assertThrows(javax.net.ssl.SSLException.class,()->connection.getInputStream());connection.disconnect();
 }

 @Test void prefixPolicyAndDeleteDenials() {
  var forbidden=PutObjectRequest.builder().bucket("ouf-managed-files").key("forbidden/file").build();
  assertEquals(403,assertThrows(S3Exception.class,()->stagingClient.putObject(forbidden,software.amazon.awssdk.core.sync.RequestBody.fromString("probe"))).statusCode());
  assertEquals(403,assertThrows(S3Exception.class,()->stagingClient.deleteObject(DeleteObjectRequest.builder().bucket("ouf-managed-files").key("managed-files/probe").build())).statusCode());
 }
 @Test void postFormCannotBypassPrefixPolicy() throws Exception {
  var client=io.minio.MinioClient.builder().endpoint(ENDPOINT).credentials("lab-staging","lab-staging-secret-not-production").build();
  var policy=new io.minio.PostPolicy("ouf-managed-files",java.time.ZonedDateTime.now().plusMinutes(5));policy.addEqualsCondition("key","forbidden/post-file");
  var fields=new LinkedHashMap<>(client.getPresignedPostFormData(policy));fields.put("key","forbidden/post-file");
  String boundary="ouf-lab-multipart-policy-boundary";var body=new java.io.ByteArrayOutputStream();
  for(var field:fields.entrySet())body.write(("--"+boundary+"\r\nContent-Disposition: form-data; name=\""+field.getKey()+"\"\r\n\r\n"+field.getValue()+"\r\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
  body.write(("--"+boundary+"\r\nContent-Disposition: form-data; name=\"file\"; filename=\"probe.csv\"\r\nContent-Type: text/csv\r\n\r\nprobe\r\n--"+boundary+"--\r\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
  var request=java.net.http.HttpRequest.newBuilder(URI.create(ENDPOINT+"/ouf-managed-files")).timeout(java.time.Duration.ofSeconds(15)).header("Content-Type","multipart/form-data; boundary="+boundary).POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(body.toByteArray())).build();
  var response=java.net.http.HttpClient.newHttpClient().send(request,java.net.http.HttpResponse.BodyHandlers.ofString());assertEquals(403,response.statusCode());
 }

 @Test void unicodeAndReservedKeyCharactersPreserveBytesAndMetadata() throws Exception {
  byte[] bytes="contenuto UTF-8: città λ".getBytes(java.nio.charset.StandardCharsets.UTF_8);String key="unicode/caffè λ/file ?#%.csv";
  udp.put(key,bytes,"text/csv",hash(bytes));assertArrayEquals(bytes,udp.read(key));assertEquals(hash(bytes),udp.head(key).orElseThrow().contentHash());
 }

}
