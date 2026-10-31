import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import javax.net.ssl.*;

public class CheckPublicTrust {
    public static void main(String[] args) throws Exception {
        KeyStore store=KeyStore.getInstance("PKCS12");
        try(var input=Files.newInputStream(Path.of(args[0]))) {store.load(input,"changeit".toCharArray());}
        Set<String> expected=new HashSet<>(Arrays.asList(args[1].split(",")));
        Set<String> actual=new HashSet<>();
        for(var entries=store.aliases();entries.hasMoreElements();) {
            String alias=entries.nextElement();
            if(!store.isCertificateEntry(alias)||store.isKeyEntry(alias)) throw new Exception("PUBLIC_CERTIFICATE_ENTRY_REQUIRED");
            X509Certificate cert=(X509Certificate)store.getCertificate(alias);
            if(cert.getBasicConstraints()<0) throw new Exception("CA_CERTIFICATE_REQUIRED");
            actual.add(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())));
        }
        if(!actual.equals(expected)||store.size()!=expected.size()) throw new Exception("EXACT_CA_SET_REQUIRED");
        if(args.length==3) {
            TrustManagerFactory tm=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tm.init(store);SSLContext context=SSLContext.getInstance("TLS");context.init(null,tm.getTrustManagers(),null);
            try(SSLSocket socket=(SSLSocket)context.getSocketFactory().createSocket("localhost",Integer.parseInt(args[2]))) {
                socket.setSoTimeout(5000);SSLParameters p=socket.getSSLParameters();p.setEndpointIdentificationAlgorithm("HTTPS");
                socket.setSSLParameters(p);socket.startHandshake();socket.getOutputStream().write(1);socket.getOutputStream().flush();
            }
        }
        System.out.println("JAVA21_EXACT_PUBLIC_CA_STORE_VERIFIED");
    }
}
