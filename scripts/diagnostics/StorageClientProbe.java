import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/** Uses the installed adapter's MinIO client, without starting Spring or a database. */
public final class StorageClientProbe {
  private static String quote(String s) {
    if (s == null || !s.matches("[A-Za-z0-9_.$:/ -]{1,160}")) s = "UNAVAILABLE";
    return "\"" + s + "\"";
  }
  private static String hash(byte[] data) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
  }
  private static Object args(String type, String bucket, String key, byte[] data) throws Exception {
    Object b = Class.forName(type).getMethod("builder").invoke(null);
    b.getClass().getMethod("bucket", String.class).invoke(b, bucket);
    b.getClass().getMethod("object", String.class).invoke(b, key);
    if (data != null) {
      b.getClass().getMethod("stream", InputStream.class, long.class, long.class)
          .invoke(b, new ByteArrayInputStream(data), (long)data.length, -1L);
      b.getClass().getMethod("contentType", String.class).invoke(b, "text/csv");
    }
    return b.getClass().getMethod("build").invoke(b);
  }
  private static void emit(String json) { System.out.println("OUF_PROBE " + json); }
  public static void main(String[] argv) {
    String phase = "PREFLIGHT";
    boolean putAcknowledged = false;
    try {
      if (argv.length != 3 || !List.of("check", "run").contains(argv[0])
          || !argv[1].matches("[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
          || !argv[2].matches("managed-files/[0-9a-f-]{36}")) throw new IllegalArgumentException();
      byte[] data = Files.readAllBytes(Path.of("/probe/input.csv"));
      if (data.length < 1 || data.length > 4096) throw new IllegalArgumentException();
      Class<?> adapterClass = Class.forName("it.comune.trieste.ouf.onboarding.application.MinioManagedFileStagingStore");
      Object adapter = adapterClass.getConstructor(String.class, String.class, Path.class, Path.class)
          .newInstance("https://ouf-seaweedfs-stage:9002", argv[1], Path.of("/probe/access-key"), Path.of("/probe/secret-key"));
      var field = adapterClass.getDeclaredField("minio");
      field.setAccessible(true);
      Object client = field.get(adapter);
      Class<?> putType = Class.forName("io.minio.PutObjectArgs"), getType = Class.forName("io.minio.GetObjectArgs");
      var put = client.getClass().getMethod("putObject", putType);
      var get = client.getClass().getMethod("getObject", getType);
      Object putArgs = args(putType.getName(), argv[1], argv[2], data);
      Object getArgs = args(getType.getName(), argv[1], argv[2], null);
      if (argv[0].equals("check")) {
        try (var bytes = adapterClass.getResourceAsStream("MinioManagedFileStagingStore.class")) {
          emit("{\"status\":\"JAVA_CLIENT_READY\",\"adapterClassSha256\":" + quote(hash(bytes.readAllBytes()))
              + ",\"javaVersion\":" + quote(System.getProperty("java.version"))
              + ",\"minioVersion\":" + quote(client.getClass().getPackage().getImplementationVersion()) + "}");
        }
        return;
      }
      phase = "PUT";
      put.invoke(client, putArgs);
      putAcknowledged = true;
      phase = "GET";
      byte[] body;
      try (InputStream response = (InputStream)get.invoke(client, getArgs)) { body = response.readNBytes(data.length + 1); }
      boolean matches = java.util.Arrays.equals(data, body);
      emit("{\"status\":" + quote(matches ? "PUT_GET_MATCH" : "BODY_MISMATCH")
          + ",\"putAcknowledged\":true,\"bodyMatches\":" + matches + ",\"bodySha256\":" + quote(hash(body)) + "}");
      if (!matches) System.exit(2);
    } catch (Throwable error) {
      List<String> classes = new ArrayList<>();
      String providerCode = null;
      Integer http = null;
      for (Throwable e = error; e != null && classes.size() < 12; e = e.getCause()) {
        if (!(e instanceof InvocationTargetException)) classes.add(quote(e.getClass().getName()));
        if (e.getClass().getName().equals("io.minio.errors.ErrorResponseException")) {
          try {
            Object detail = e.getClass().getMethod("errorResponse").invoke(e);
            providerCode = (String)detail.getClass().getMethod("code").invoke(detail);
            Object response = e.getClass().getMethod("response").invoke(e);
            http = (Integer)response.getClass().getMethod("code").invoke(response);
          } catch (ReflectiveOperationException ignored) { }
        }
      }
      emit("{\"status\":\"JAVA_CLIENT_FAILED\",\"phase\":" + quote(phase)
          + ",\"putAcknowledged\":" + putAcknowledged + ",\"exceptionClasses\":[" + String.join(",", classes)
          + "],\"providerCode\":" + (providerCode == null ? "null" : quote(providerCode))
          + ",\"providerHttpStatus\":" + (http != null && http >= 100 && http <= 599 ? http : "null") + "}");
      System.exit(2);
    }
  }
}
