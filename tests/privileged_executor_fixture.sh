#!/usr/bin/env bash
# Build both test images from the hosted runner's JDK and system libraries.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd "$work"
mkdir -p root/{app,bin,opt,tmp}
chmod 1777 root/tmp
cat > Fixture.java <<'JAVA'
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class Fixture {
    public static void main(String[] args) throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 8080), 0);
        server.createContext("/ready", exchange -> {
            byte[] body = "{\"status\":\"UP\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (var out = exchange.getResponseBody()) { out.write(body); }
        });
        server.start();
    }
}
JAVA
javac Fixture.java
jar --create --file root/app/application.jar --main-class Fixture Fixture.class
jlink --add-modules jdk.httpserver --no-header-files --no-man-pages --output root/opt/java
cp /bin/dash /bin/sleep root/bin/
ln -s dash root/bin/sh
for binary in /bin/dash /bin/sleep root/opt/java/bin/java root/opt/java/lib/{libjava,libnet,libnio,libjimage,server/libjvm}.so; do
    while read -r lib; do
        cp --parents -L "$lib" root/
    done < <(ldd "$binary" | awk '{ for (i=1; i<=NF; i++) if ($i ~ "^/(usr/)?lib") print $i }')
done
tar -C root -cf rootfs.tar .
tested=$(printf 'd%.0s' {1..40})
for revision in old "$tested"; do
    docker import --change 'ENV PATH=/opt/java/bin:/bin' \
        --change "LABEL org.opencontainers.image.revision=$revision" \
        --change 'LABEL org.opencontainers.image.source=https://github.com/fixture/module' \
        rootfs.tar "ouf-ci-gate:$revision"
done
