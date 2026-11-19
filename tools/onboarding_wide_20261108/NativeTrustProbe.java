import javax.net.ssl.HttpsURLConnection;
import java.net.URI;
public class NativeTrustProbe {
 public static void main(String[] a) throws Exception {
  var c=(HttpsURLConnection)URI.create(a[0]).toURL().openConnection();
  c.setConnectTimeout(3000);c.setReadTimeout(3000);
  if(c.getResponseCode()!=200)throw new IllegalStateException("TLS_FIXTURE_FAILED");
  try(var s=c.getInputStream()){if(!new String(s.readNBytes(64)).equals("fixture-tls-ok"))throw new IllegalStateException();}
  c.disconnect();System.out.println("JVM_PRIVATE_CA_TLS_OK");
 }
}
