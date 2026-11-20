#!/usr/bin/env bash
# Build the fixture images from binaries already installed on the hosted runner.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
go_fixture="$(dirname "$(realpath "$0")")/module_release_ready_fixture.go"
cd "$work"
mkdir -p root/{app,bin,opt,tmp}
chmod 1777 root/tmp
mkdir -p root/usr/local/bin
CGO_ENABLED=0 GOPROXY=off GOTOOLCHAIN=local go build -trimpath -o root/usr/local/bin/ouf-mcp "$go_fixture"
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

# Reproduce MCP's absolute /bin/sh link with the runner's BusyBox, offline.
busybox=$(command -v busybox || echo /usr/lib/initramfs-tools/bin/busybox)
"$busybox" sh -c 'exit 0'
mkdir -p busyroot/{bin,usr/local/bin}
cp "$busybox" busyroot/bin/busybox
ln -s /bin/busybox busyroot/bin/sh
ln -s busybox busyroot/bin/sleep
cp root/usr/local/bin/ouf-mcp busyroot/usr/local/bin/
while read -r lib; do
    cp --parents -L "$lib" busyroot/
done < <(ldd "$busybox" 2>/dev/null | awk '{ for (i=1; i<=NF; i++) if ($i ~ "^/(usr/)?lib") print $i }')
tar -C busyroot -cf busybox.tar .
for revision in old "$tested"; do
    docker import --change 'ENV PATH=/bin:/usr/local/bin' \
        --change "LABEL org.opencontainers.image.revision=$revision" \
        --change 'LABEL org.opencontainers.image.source=https://github.com/fixture/module' \
        busybox.tar "ouf-ci-busybox:$revision"
done
