"""Read-only reconciliation of a reviewed Spring/Flyway launch."""
import json
import os
import re
import stat
import subprocess
from urllib.parse import urlsplit
import zipfile
import zlib

from .contract import Held, digest, jar_name, matches, require


SQL = """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='5s';
SET LOCAL search_path=pg_catalog;
SELECT json_build_object('databaseOid',(SELECT oid::text FROM pg_database WHERE datname=current_database()),
'history',(SELECT json_agg(json_build_object('version',version,'script',script,'type',type,
'checksum',checksum,'success',success) ORDER BY installed_rank) FROM :"schema".flyway_schema_history));
ROLLBACK;"""


def flyway_checksum(raw):
    """Flyway ChecksumCalculator: first BOM removed, CR/LF excluded, signed CRC32."""
    text = raw.decode('utf-8')
    if text.startswith('\ufeff'):
        text = text[1:]
    value = 0
    for line in re.split(r'\r\n|\n|\r', text):
        value = zlib.crc32(line.encode('utf-8'), value)
    return value if value < 2**31 else value-2**32


def java_migrations(jar):
    """Read migration bytes from the already verified packaged executable JAR."""
    rows = []
    with zipfile.ZipFile(jar) as archive:
        members = [m for m in archive.infolist() if m.filename.startswith('BOOT-INF/classes/db/migration/') and not m.is_dir()]
        require(1 <= len(members) <= 256 and sum(m.file_size for m in members) <= 8388608,
                'BOUNDED_PACKAGED_MIGRATIONS_REQUIRED')
        for member in members:
            name = member.filename.split('/')[-1]
            match = re.fullmatch(r'V([0-9]+(?:[._][0-9]+)*)__([A-Za-z0-9_-]+)\.sql',name)
            require(match is not None and member.filename == 'BOOT-INF/classes/db/migration/'+name,
                    'REPEATABLE_OR_CUSTOM_MIGRATION_REQUIRES_REVIEW')
            raw = archive.read(member)
            rows.append({'version':match[1].replace('_','.'),'script':name,'type':'SQL',
                         'checksum':flyway_checksum(raw),'success':True})
    rows.sort(key=lambda r:tuple(int(v) for v in r['version'].split('.')))
    require(len({r['version'] for r in rows}) == len(rows), 'DUPLICATE_MIGRATION_VERSION_DENIED')
    return rows


def inventory(doc):
    # Resolve only fixed regular components in PID 1's pinned root. The gate has
    # not yet exec'd Java. A symlink in the image must never select a host file.
    flags = os.O_RDONLY | os.O_DIRECTORY
    root = os.open(f"/proc/{doc['State']['Pid']}/root", flags)
    try:
        app = os.open("app", flags | os.O_NOFOLLOW, dir_fd=root)
        try:
            fd = os.open(jar_name(doc["Config"]["Cmd"]), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=app)
        finally:
            os.close(app)
    finally:
        os.close(root)
    with os.fdopen(fd, "rb") as jar:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 512 << 20, "FLYWAY_JAR_UNPROVEN")
        return java_migrations(jar)


def canonical_property(name):
    return re.sub(r"[._-]", "", name).lower()


def check_application_json(raw, binding):
    """Check Spring's nested and dotted properties without exporting keys or values."""
    denied = "FLYWAY_DATASOURCE_UNPROVEN"

    def unique(pairs):
        obj = dict(pairs)
        require(len(obj) == len(pairs), denied)
        return obj

    def invalid_constant(_):
        raise Held(denied)

    protected = ("springdatasource", "springflyway", "springconfig", "springprofiles",
                 "springapplicationjson", "springmain", "springautoconfigure", "springjndi",
                 canonical_property(binding["urlEnv"]), canonical_property(binding["userEnv"]))

    def walk(obj, prefix):
        for key, value in obj.items():
            require(matches(r"[a-zA-Z0-9_.-]+", key), denied)
            path = prefix + canonical_property(key)
            require(not path.startswith(protected), denied)
            if isinstance(value, dict):
                walk(value, path)

    try:
        obj = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
        require(isinstance(obj, dict), denied)
        walk(obj, "")
    except (ValueError, RecursionError):
        raise Held(denied) from None


def datasource(binding, config, *, predecessor):
    env = [v.split("=", 1) for v in config["Env"] if "=" in v]
    values = dict(env)
    require(len(env) == len(values), "FLYWAY_DATASOURCE_UNPROVEN")
    options = [values.get(k, "") for k in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "JAVA_OPTS")]
    allowed = set()
    args = config["Cmd"]
    if binding.get("effectiveDatasource") == "profile-env":
        allowed.update(("SPRING_CONFIG_ADDITIONAL_LOCATION", "SPRING_APPLICATION_JSON"))
        if "SPRING_APPLICATION_JSON" in values:
            check_application_json(values["SPRING_APPLICATION_JSON"], binding)
        if values.get("SPRING_FLYWAY_ENABLED") in (("true", "false") if predecessor else ("true",)):
            allowed.add("SPRING_FLYWAY_ENABLED")
        if predecessor:
            args = [arg for arg in args if arg != "--spring.flyway.enabled=false"]
        # Reject aliases that Spring could resolve differently from the literal
        # environment keys used for the read-only PostgreSQL connection.
        names = (binding["urlEnv"], binding["userEnv"])
        direct = allowed | set(names) | {"SPRING_DATASOURCE_URL", "SPRING_DATASOURCE_USERNAME",
                                        "SPRING_DATASOURCE_PASSWORD"}
        sensitive = ("springdatasource", "springflyway", "springconfig", "springprofiles", "springapplicationjson",
                     *(canonical_property(k) for k in names))
        require(all(k in direct or not canonical_property(k).startswith(sensitive) for k in values),
                "FLYWAY_DATASOURCE_UNPROVEN")
        require(not any(canonical_property(arg.partition("=")[0].removeprefix("-D")).startswith(sensitive)
                        for arg in args), "FLYWAY_DATASOURCE_UNPROVEN")
        require(not any(prefix in canonical_property(option) for option in options for prefix in sensitive),
                "FLYWAY_DATASOURCE_UNPROVEN")
    selectors = ("SPRING_CONFIG_", "SPRING_PROFILES_", "SPRING_FLYWAY_")
    require(not any(v and k not in allowed and (k.startswith(selectors) or k == "SPRING_APPLICATION_JSON")
                    for k, v in values.items()) and not any("spring." in arg.lower() for arg in [*args, *options]),
            "FLYWAY_DATASOURCE_UNPROVEN")
    require(all(not key.startswith("SPRING_DATASOURCE_") or key in
                ("SPRING_DATASOURCE_URL", "SPRING_DATASOURCE_USERNAME", "SPRING_DATASOURCE_PASSWORD")
                for key in values), "FLYWAY_DATASOURCE_UNPROVEN")
    jdbc = values.get(binding["urlEnv"], "")
    user = values.get(binding["userEnv"], "")
    require(jdbc.startswith("jdbc:postgresql://") and matches(r"[a-z_][a-z0-9_]{0,62}", user)
            and values.get("SPRING_DATASOURCE_URL", jdbc) == jdbc
            and values.get("SPRING_DATASOURCE_USERNAME", user) == user, "FLYWAY_DATASOURCE_UNPROVEN")
    url = urlsplit(jdbc[5:])
    require(url.query in ("", "currentSchema=" + binding["schema"]) and not url.fragment and not url.username
            and not url.password and matches(r"/[a-z_][a-z0-9_]{0,62}", url.path)
            and binding.get("database", url.path[1:]) == url.path[1:], "FLYWAY_DATASOURCE_UNPROVEN")
    return url, user


def observe(rt, candidate):
    binding = rt.p["migration"].get("flyway")
    if binding is None:
        require(rt.p["module"] == "onboarding" and rt.flyway_peer, "FLYWAY_BINDING_UNPROVEN")
        binding = dict(rt.flyway_peer, urlEnv="OUF_ONB_DB_URL", userEnv="OUF_ONB_DB_USER", schema="ouf_onboarding")
    url, user = datasource(binding, candidate["Config"], predecessor=candidate["Image"] == rt.p["oldImage"])
    pg = rt.inspect(binding["postgresCid"])
    nets = {ep["NetworkID"] for ep in candidate["NetworkSettings"]["Networks"].values()}
    require(pg["Id"] == binding["postgresCid"] and pg["State"]["Running"] and any(
        ep["NetworkID"] in nets and url.hostname in
        [pg["Name"].lstrip("/"), ep["IPAddress"], *(ep.get("Aliases") or [])]
        for ep in pg["NetworkSettings"]["Networks"].values()), "FLYWAY_POSTGRES_CHANGED")
    args = ["/usr/bin/docker", "--host", "unix://" + rt.p["dockerSocket"], "exec", "-i", pg["Id"],
            "psql", "-XwqAt", "-v", "ON_ERROR_STOP=1", "-h", binding["socket"], "-p", str(url.port or 5432),
            "-v", "schema=" + binding["schema"], "-U", user, "-d", url.path[1:]]
    result = subprocess.run(args, input=SQL.encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12)
    require(result.returncode == 0 and 0 < len(result.stdout) <= 1 << 20, "FLYWAY_READ_FAILED")
    facts = json.loads(result.stdout)
    rows = facts["history"]
    require(facts["databaseOid"] and isinstance(rows, list) and len(rows) <= 256
            and all(r["success"] is True and r["type"] in ("SCHEMA", "BASELINE", "SQL") for r in rows),
            "FLYWAY_HISTORY_UNPROVEN")
    return {"peer": pg["Id"], "db": facts["databaseOid"], "history": rows}


def baseline(current):
    rows = current["history"]
    return {"peer": current["peer"], "db": current["db"], "count": len(rows), "before": digest(rows)}


def checkpoint(rt, candidate):
    expected = inventory(candidate)
    current = observe(rt, candidate)
    rows = current["history"]
    sql = [r for r in rows if r["type"] == "SQL"]
    require(sql == expected[:len(sql)], "FLYWAY_BASELINE_CHANGED")
    pending = expected[len(sql):]
    proof = {**baseline(current), "after": digest(rows + pending)}
    if "flyway" in rt.p["migration"]:
        proof["pending"] = pending
    return proof


def verify(rt, candidate, proof):
    current = observe(rt, candidate)
    rows = current["history"]
    require(current["peer"] == proof["peer"] and current["db"] == proof["db"] and
            digest(rows[:proof["count"]]) == proof["before"] and digest(rows) == proof["after"],
            "FLYWAY_HISTORY_UNPROVEN")
