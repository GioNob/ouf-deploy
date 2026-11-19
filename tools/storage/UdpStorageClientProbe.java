import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;

/** Calls the installed UDP factory and adapter without starting Spring. */
public final class UdpStorageClientProbe {
  private static final String CONFIG = "it.comune.trieste.ouf.udp.S3LakeConfiguration";
  private static final String ADAPTER = "it.comune.trieste.ouf.udp.S3LakeObjectStorageAdapter";
  private static String quote(String value) {
    return value != null && value.matches("[A-Za-z0-9_.$:/ -]{1,160}") ? "\"" + value + "\"" : "null";
  }
  private static String hash(byte[] bytes) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }
  private static String classHash(Class<?> type) throws Exception {
    try (InputStream stream = type.getResourceAsStream(type.getSimpleName() + ".class")) {
      if (stream == null) throw new IllegalStateException("CLASS_RESOURCE_MISSING");
      return hash(stream.readAllBytes());
    }
  }
  private static void emit(String result) { System.out.println("OUF_UDP_PROBE " + result); }
  public static void main(String[] args) {
    String phase = "PREFLIGHT";
    boolean putAcknowledged = false;
    Object client = null;
    try {
      if (args.length != 3 || !List.of("check", "run").contains(args[0])
          || !args[1].equals("ouf-udp")
          || !args[2].matches("diagnostics/seaweedfs-client/[a-f0-9-]{36}")) throw new IllegalArgumentException();
      byte[] payload = Files.readAllBytes(Path.of("/probe/input.csv"));
      if (payload.length < 1 || payload.length > 4096) throw new IllegalArgumentException();
      ClassLoader loader = UdpStorageClientProbe.class.getClassLoader();
      Class<?> config = Class.forName(CONFIG, false, loader);
      Class<?> adapter = Class.forName(ADAPTER, false, loader);
      String configHash = classHash(config), adapterHash = classHash(adapter);
      if (!configHash.equals("5036160bbd46809ee87adb285e489547fc0a713e97a85327d6097be59b1530e6")
          || !adapterHash.equals("5a6bd871ce01e2235ab98f74e6307016ebec9996e62e42fccc11ca951eaa7bf8"))
        throw new IllegalStateException("INSTALLED_CLASS_CHANGED");
      var factory = config.getDeclaredMethod("lakeS3Client", String.class, String.class, boolean.class);
      factory.setAccessible(true);
      client = factory.invoke(config.getConstructor().newInstance(), "us-east-1", "https://ouf-seaweedfs-stage:9002", true);
      Class<?> s3 = Class.forName("software.amazon.awssdk.services.s3.S3Client");
      Object store = adapter.getConstructor(s3, String.class).newInstance(client, args[1]);
      if (args[0].equals("check")) {
        Properties version = new Properties();
        try (InputStream stream = loader.getResourceAsStream("META-INF/maven/software.amazon.awssdk/s3/pom.properties")) {
          if (stream != null) version.load(stream);
        }
        emit("{\"status\":\"JAVA_CLIENT_READY\",\"configurationClassSha256\":" + quote(configHash)
            + ",\"adapterClassSha256\":" + quote(adapterHash)
            + ",\"javaVersion\":" + quote(System.getProperty("java.version"))
            + ",\"sdkVersion\":" + quote(version.getProperty("version")) + "}");
        return;
      }
      String expectedHash = "sha256:" + hash(payload);
      phase = "CHECK_KEY_ABSENT";
      Object existing = adapter.getMethod("head", String.class).invoke(store, args[2]);
      if (((java.util.Optional<?>)existing).isPresent()) throw new IllegalStateException("DIAGNOSTIC_KEY_EXISTS");
      phase = "PUT_AND_HEAD";
      Object stored = adapter.getMethod("put", String.class, byte[].class, String.class, String.class)
          .invoke(store, args[2], payload, "text/csv", expectedHash);
      putAcknowledged = true;
      Class<?> result = Class.forName("it.comune.trieste.ouf.udp.LakeObjectStoragePort$StoredObject");
      boolean metadataMatches = args[2].equals(result.getMethod("locator").invoke(stored))
          && expectedHash.equals(result.getMethod("contentHash").invoke(stored))
          && ((Long)result.getMethod("sizeBytes").invoke(stored)) == payload.length
          && ((Boolean)result.getMethod("durable").invoke(stored));
      phase = "GET";
      byte[] body = (byte[])adapter.getMethod("read", String.class).invoke(store, args[2]);
      boolean bodyMatches = java.util.Arrays.equals(payload, body);
      boolean passed = metadataMatches && bodyMatches;
      emit("{\"status\":" + quote(passed ? "PUT_HEAD_GET_MATCH" : "CONTENT_OR_METADATA_MISMATCH")
          + ",\"putAcknowledged\":true,\"metadataMatches\":" + metadataMatches
          + ",\"bodyMatches\":" + bodyMatches + ",\"bodyBytes\":" + body.length
          + ",\"bodySha256\":" + quote(hash(body)) + "}");
      if (!passed) System.exit(2);
    } catch (Throwable error) {
      List<String> classes = new ArrayList<>();
      String code = null;
      Integer http = null;
      for (Throwable cause = error; cause != null && classes.size() < 12; cause = cause.getCause()) {
        if (!(cause instanceof InvocationTargetException)) classes.add(quote(cause.getClass().getName()));
        try {
          http = (Integer)cause.getClass().getMethod("statusCode").invoke(cause);
          Object detail = cause.getClass().getMethod("awsErrorDetails").invoke(cause);
          if (detail != null) code = (String)detail.getClass().getMethod("errorCode").invoke(detail);
        } catch (ReflectiveOperationException ignored) { }
      }
      emit("{\"status\":\"JAVA_CLIENT_FAILED\",\"phase\":" + quote(phase)
          + ",\"putAcknowledged\":" + putAcknowledged + ",\"exceptionClasses\":[" + String.join(",", classes)
          + "],\"providerCode\":" + quote(code) + ",\"providerHttpStatus\":"
          + (http != null && http >= 100 && http <= 599 ? http : "null") + "}");
      System.exit(2);
    } finally {
      if (client != null) {
        try { Class.forName("software.amazon.awssdk.services.s3.S3Client").getMethod("close").invoke(client); }
        catch (ReflectiveOperationException ignored) { }
      }
    }
  }
}
