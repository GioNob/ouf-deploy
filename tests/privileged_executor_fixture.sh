#!/usr/bin/env bash
# Build disposable images with the hosted toolchain and the fixture's pinned Java dependencies.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
go_fixture="$(dirname "$(realpath "$0")")/module_release_ready_fixture.go"
fixtures="$(dirname "$go_fixture")/fixtures"
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
mkdir -p BOOT-INF/classes/db/migration
echo 'SELECT 1;' > BOOT-INF/classes/db/migration/V1__base.sql
echo 'SELECT 2;' > BOOT-INF/classes/db/migration/V2__added.sql
jar --create --file root/app/application.jar --main-class Fixture Fixture.class BOOT-INF
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

# A2 successor with image defaults absent from the predecessor.
docker import --change 'ENV PATH=/opt/java/bin:/bin' --change 'ENV A2_IMAGE_DEFAULT=yes' \
    --change 'LABEL fixture.a2.successor=yes' --change 'ENTRYPOINT ["/bin/false"]' \
    rootfs.tar ouf-ci-gate:a2-successor

# Actual Flyway/JDBC artifacts for the isolated Java -> PostgreSQL release.
mv root/opt/java "$work/http-jre"
jlink --add-modules java.se,jdk.httpserver,jdk.unsupported,jdk.crypto.ec,jdk.zipfs \
    --no-header-files --no-man-pages --output root/opt/java
mvn -B -q -f "$fixtures/ingestion-db-preflight/pom.xml" dependency:copy-dependencies \
    -DincludeScope=runtime -DoutputDirectory="$work/root/app/lib"
javac -cp '.:root/app/lib/*' -d . "$fixtures/module-release-flyway/FlywayFixture.java"
python3 - <<'PY'
from pathlib import Path
paths = sorted(p.relative_to("root/app").as_posix() for p in Path("root/app/lib").glob("*.jar"))
classpath = "Class-Path: " + " ".join(paths)
Path("flyway.mf").write_text("Manifest-Version: 1.0\nMain-Class: FlywayFixture\n" +
                            "\n ".join(classpath[i:i+68] for i in range(0,len(classpath),68)) + "\n\n")
PY
rm BOOT-INF/classes/db/migration/V2__added.sql
for revision in old "$tested" semantic; do
    resources=BOOT-INF/classes/db/migration
    defaults=()
    echo 'CREATE TABLE release_fixture.base_row(id integer);' > "$resources/V1__base.sql"
    if [[ "$revision" != old ]]; then
        cp "$fixtures/module-release-flyway/V21__add_repeat_key.sql" "$resources/"
        defaults=(--change 'ENV FIXTURE_JAVA_IMAGE=successor' --change 'LABEL fixture.java.successor=yes')
    fi
    if [[ "$revision" == semantic ]]; then
        cat > "$resources/V22__create_probe.sql" <<'SQL'
CREATE FUNCTION release_fixture.probe_key() RETURNS text LANGUAGE plpgsql AS $probe$
BEGIN
    RETURN 'ready';
END;
$probe$;
INSERT INTO release_fixture.base_row VALUES (22, release_fixture.probe_key());
SQL
    fi
    jar --create --file root/app/flyway.jar --manifest flyway.mf Fixture.class FlywayFixture.class BOOT-INF
    tar -C root -cf - . | docker import "${defaults[@]}" --change 'ENV PATH=/opt/java/bin:/bin' \
        --change "LABEL org.opencontainers.image.revision=$revision" \
        --change 'LABEL org.opencontainers.image.source=https://github.com/fixture/module' - "ouf-ci-flyway:$revision"
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
    defaults=()
    if [[ $revision == "$tested" ]]; then
        defaults=(--change 'ENV MODULE_SUCCESSOR=yes' --change 'LABEL fixture.module.successor=yes'
                  --change 'ENTRYPOINT ["/usr/local/bin/ouf-mcp"]')
    fi
    docker import "${defaults[@]}" --change 'ENV PATH=/bin:/usr/local/bin' \
        --change "LABEL org.opencontainers.image.revision=$revision" \
        --change 'LABEL org.opencontainers.image.source=https://github.com/fixture/module' \
        busybox.tar "ouf-ci-busybox:$revision"
done
