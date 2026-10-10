#!/usr/bin/env python3
"""Boot the exact signed candidate on disposable databases, with real JWT verification."""
import base64, hashlib, json, os, shutil, subprocess, tempfile, threading, time, urllib.error, urllib.request, zipfile
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DB = "ouf-discovery-spring-ci"
ISSUER = "http://127.0.0.1:55440"
BASE = "http://127.0.0.1:55441"
CAP = "ouf.semantic.search"

def command(args, data=None, check=True):
    result = subprocess.run(args, input=data, capture_output=True, timeout=60)
    if check and result.returncode:
        raise RuntimeError("FIXTURE_COMMAND_FAILED: " + result.stderr.decode(errors="replace")[:1500])
    return result

def sql(query, database="semantic"):
    return command(["docker", "exec", "-i", DB, "psql", "-X", "-U", "postgres", "-d", database,
                    "-v", "ON_ERROR_STOP=1", "-A", "-t"], query.encode()).stdout.strip()

def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def http(path, token=None, data=None, receipt=None):
    headers = {"Content-Type": "application/json"}
    if token: headers["Authorization"] = "Bearer " + token
    if receipt: headers["X-OUF-Semantic-Discovery-Receipt"] = receipt
    request = urllib.request.Request(BASE + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()

def main():
    results = []
    process = None
    oidc = None
    with tempfile.TemporaryDirectory(prefix="ouf-spring-fixture-") as directory:
        root = Path(directory)
        try:
            # Private key belongs only to this isolated test, never to deployed IAM.
            private = root / "issuer.pem"
            command(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)])
            private.chmod(0o600)
            modulus = command(["openssl", "rsa", "-in", str(private), "-noout", "-modulus"]).stdout.decode().strip().split("=", 1)[1]
            jwks = {"keys": [{"kty": "RSA", "kid": "startup-fixture", "use": "sig", "alg": "RS256", "n": b64(bytes.fromhex(modulus)), "e": "AQAB"}]}
            discovery = {"issuer": ISSUER, "jwks_uri": ISSUER + "/jwks", "authorization_endpoint": ISSUER + "/authorize", "token_endpoint": ISSUER + "/token",
                         "response_types_supported": ["code"], "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"]}
            class Oidc(BaseHTTPRequestHandler):
                def do_GET(self):
                    value = jwks if self.path == "/jwks" else discovery if self.path in ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server") else None
                    self.send_response(200 if value else 404); self.send_header("Content-Type", "application/json"); self.end_headers()
                    self.wfile.write(json.dumps(value or {}).encode())
                def log_message(self, *args): pass
            oidc = ThreadingHTTPServer(("127.0.0.1", 55440), Oidc)
            threading.Thread(target=oidc.serve_forever, daemon=True).start()
            def token(subject="fixture-reader", audience="fixture-semantic", scope=CAP):
                now = int(time.time())
                claims = {"iss": ISSUER, "aud": audience, "sub": subject, "tenant_id": "fixture-tenant", "ouf_actor_type": "HUMAN", "acr": "fixture-auth",
                          "scope": scope, "iat": now, "exp": now + 120, "auth_time": now, "amr": ["pwd"]}
                encoded = b64(json.dumps({"alg": "RS256", "kid": "startup-fixture"}).encode()) + "." + b64(json.dumps(claims).encode())
                signature = command(["openssl", "dgst", "-sha256", "-sign", str(private)], encoded.encode()).stdout
                return encoded + "." + b64(signature)
            now = datetime.now(timezone.utc)
            bundle = {"bundleId": "startup-fixture", "version": 1, "publishedAt": now.isoformat(),
                      "capabilities": [{"capabilityId": CAP, "operation": "EXECUTE", "requiredScope": CAP, "allowedActors": ["HUMAN"]}],
                      "grants": [{"grantId": "fixture-search", "capabilityId": CAP, "tenantId": "fixture-tenant", "subjectId": "fixture-reader",
                                  "validFrom": (now - timedelta(minutes=1)).isoformat(), "validUntil": (now + timedelta(minutes=10)).isoformat()}]}
            policy = root / "policy.json"; policy.write_text(json.dumps(bundle)); policy.chmod(0o600)
            policy_hash = hashlib.sha256(policy.read_bytes()).hexdigest()
            command(["docker", "run", "-d", "--name", DB, "-p", "127.0.0.1:55439:5432", "-e", "POSTGRES_PASSWORD=ci-fixture-only", "-e", "POSTGRES_DB=semantic", "postgres:17"])
            for _ in range(30):
                if command(["docker", "exec", DB, "pg_isready", "-U", "postgres"], check=False).returncode == 0: break
                time.sleep(1)
            else: raise RuntimeError("POSTGRES_NOT_READY")
            receipt = json.loads(Path("evidence/discovery-remediated-application-qualification-20261009.json").read_bytes())["migrationPlan"]["receipt"]
            libs = root / "lib"; libs.mkdir()
            migrations = root / "baseline"; migrations.mkdir()
            with zipfile.ZipFile("package/application.jar") as jar:
                for name, expected in receipt["candidateMigrationDigests"].items():
                    raw = jar.read("BOOT-INF/classes/db/migration/" + name)
                    if hashlib.sha256(raw).hexdigest() != expected: raise RuntimeError("SIGNED_MIGRATION_BYTES_CHANGED")
                    if not name.startswith("V10__"): (migrations / name).write_bytes(raw)
                for name in jar.namelist():
                    if name.startswith("BOOT-INF/lib/") and name.endswith(".jar"): (libs / Path(name).name).write_bytes(jar.read(name))
            if len(list(migrations.iterdir())) != 9: raise RuntimeError("BASELINE_NOT_V1_TO_V9")
            command(["javac", "-cp", str(libs / "*"), "-d", str(root), "tests/fixtures/FlywayFixture.java"])
            command(["java", "-cp", str(root) + ":" + str(libs / "*"), "FlywayFixture", "migrate", "semantic", str(migrations)])
            sql("INSERT INTO ouf_sem.discovery_request(request_id,requested_artifact_type,intent,preferred_languages,state,created_by_subject) VALUES ('00000000-0000-4000-8000-000000000001','CLASS','historical theatre fixture',ARRAY['it','en'],'PENDING','fixture-history');")
            rows = "SELECT jsonb_agg(to_jsonb(t) ORDER BY request_id)::text FROM ouf_sem.discovery_request t;"
            historical = sql(rows)
            def boot(database):
                nonlocal process
                env = os.environ.copy()
                env.update({"OUF_SEM_DB_URL": "jdbc:postgresql://127.0.0.1:55439/" + database, "OUF_SEM_DB_USER": "postgres", "OUF_SEM_DB_PASSWORD": "ci-fixture-only",
                            "PORT": "55441", "OUF_SCHEMA_GOV_ENABLED": "false", "OUF_DISCOVERY_WORKER_ENABLED": "false"})
                log = root / (database + ".log")
                with log.open("wb") as output:
                    process = subprocess.Popen(["java", "-jar", "package/application.jar", "--ouf.iam.enabled=true", "--ouf.iam.issuer=" + ISSUER, "--ouf.iam.audience=fixture-semantic",
                                                "--ouf.authorization.bundle-file=" + str(policy), "--ouf.authorization.bundle-id=startup-fixture", "--ouf.authorization.bundle-version=1",
                                                "--ouf.authorization.bundle-sha256=" + policy_hash], env=env, stdout=output, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError("SPRING_STARTUP_FAILED: " + "\n".join(line for line in log.read_text(errors="replace").splitlines() if "Exception" in line or "ERROR" in line)[-4000:])
                    try:
                        code, body = http("/actuator/health/readiness")
                        if code == 200 and json.loads(body)["status"] == "UP": break
                    except (OSError, ValueError): pass
                    time.sleep(0.5)
                else: raise RuntimeError("SPRING_READINESS_TIMEOUT")
                path = "/api/semantic/v1/search?q=theatre"
                checks = [("anonymous", http(path), 403), ("granted", http(path, token()), 200),
                          ("ungranted_subject", http(path, token(subject="fixture-outsider")), 403),
                          ("missing_scope", http(path, token(scope="unrelated")), 403),
                          ("wrong_audience", http(path, token(audience="other-owner")), 401),
                          ("invalid_signature", http(path, token() + "invalid"), 401),
                          ("missing_discovery_receipt", http("/api/internal/v1/semantic/discovery/request", data=b"{}"), 403),
                          ("forged_discovery_receipt", http("/api/internal/v1/semantic/discovery/request", data=b"{}", receipt="forged.receipt"), 403)]
                for label, (status, body), expected in checks:
                    if status != expected: raise RuntimeError("HTTP_AUTH_BOUNDARY_FAILED " + label + " actual=" + str(status) + " expected=" + str(expected))
                    if label == "granted" and not isinstance(json.loads(body), list): raise RuntimeError("SEARCH_RESPONSE_INVALID")
                process.terminate(); process.wait(timeout=20); process = None
                results.append({"database": database, "readiness": "UP", "iamEnabled": True, "positiveSearch": True, "denialChecks": [label for label, _, _ in checks if label != "granted"]})
            boot("semantic")
            if sql("SELECT string_agg(version,',' ORDER BY installed_rank) FROM ouf_sem.flyway_schema_history WHERE success;") != b"1,2,3,4,5,6,7,8,9,10": raise RuntimeError("FULL_SPRING_MIGRATION_HISTORY_UNPROVEN")
            # V10 introduces new nullable columns; compare historical projections.
            projected = "SELECT jsonb_agg(to_jsonb(t) - 'idempotency_key_hash' - 'request_fingerprint' ORDER BY request_id)::text FROM ouf_sem.discovery_request t;"
            if sql(projected) != historical: raise RuntimeError("SPRING_START_CHANGED_HISTORICAL_CONTENT")
            sql("INSERT INTO ouf_sem.discovery_request(request_id,requested_artifact_type,intent,state,created_by_subject,idempotency_key_hash,request_fingerprint) VALUES ('00000000-0000-4000-8000-000000000002','CLASS','post migration fixture','PENDING','fixture-writer','" + "a"*64 + "','" + "b"*64 + "');")
            current = sql(rows)
            dump = command(["docker", "exec", DB, "pg_dump", "-U", "postgres", "-d", "semantic", "-Fc"]).stdout
            sql("CREATE DATABASE restored_v10;")
            command(["docker", "exec", "-i", DB, "pg_restore", "-U", "postgres", "-d", "restored_v10", "--exit-on-error"], dump)
            boot("restored_v10")
            if sql(rows, "restored_v10") != current or sql(rows) != current: raise RuntimeError("SPRING_RESTORE_CONTENT_DRIFT")
            receipt = {"schema": "ouf.discovery.spring-startup-fixture.v1", "status": "PASS", "candidateRevision": "403531a9df1cbc877078f8126fd1fc4ff18acea9",
                       "candidateImage": "sha256:b1a7956a673f88b5ee65d174c2eda7b9e448153e101348c06fdd53c0640e700b", "applicationJarSha256": hashlib.sha256(Path("package/application.jar").read_bytes()).hexdigest(),
                       "fullSpringStartupQualified": True, "springAppliedV10": True, "historicalRowsPreserved": True, "currentSnapshotRestoredAfterWrites": True,
                       "liveFixtureUnchangedByRestore": True, "starts": results, "providerEnabled": False, "discoveryWorkerEnabled": False, "realProviderHealthProven": False,
                       "oldApplicationRuntimeQualified": False, "targetDatabaseTouched": False, "targetBackupPerformed": False, "notReleaseAcceptance": True}
            Path("spring-startup-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            print("OUF_DISCOVERY_SPRING_STARTUP_CI=" + json.dumps(receipt))
        finally:
            if process and process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
            if oidc: oidc.shutdown(); oidc.server_close()
            command(["docker", "rm", "-f", DB], check=False)

if __name__ == "__main__": main()
