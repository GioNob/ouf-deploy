"""R-033 PostgreSQL observations. Only migration metadata enters the release journal."""
import json
import subprocess
from urllib.parse import parse_qsl, unquote, urlsplit

from .contract import SHA, digest, matches, require


SQL = """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='5s';
SET LOCAL timezone='UTC';
SET LOCAL search_path=pg_catalog;
WITH relations AS (
  SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='ouf_mcp'
), shape(item) AS (
  SELECT json_build_array('relation',relname,relkind)::text FROM relations
  UNION ALL
  SELECT json_build_array('column',r.relname,a.attname,a.attnum,format_type(a.atttypid,a.atttypmod),
    a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid))::text
    FROM relations r JOIN pg_attribute a ON a.attrelid=r.oid
    LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(r.oid,a.attnum)
    WHERE a.attnum>0 AND NOT a.attisdropped
  UNION ALL
  SELECT json_build_array('constraint',r.relname,k.conname,pg_get_constraintdef(k.oid))::text
    FROM relations r JOIN pg_constraint k ON k.conrelid=r.oid
  UNION ALL
  SELECT json_build_array('index',r.relname,pg_get_indexdef(i.indexrelid))::text
    FROM relations r JOIN pg_index i ON i.indrelid=r.oid
  UNION ALL
  SELECT json_build_array('view',relname,pg_get_viewdef(oid))::text FROM relations WHERE relkind IN ('v','m')
  UNION ALL
  SELECT json_build_array('trigger',r.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid))::text
    FROM relations r JOIN pg_trigger t ON t.tgrelid=r.oid WHERE NOT t.tgisinternal
  UNION ALL
  SELECT json_build_array('routine',pg_get_functiondef(p.oid))::text
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='ouf_mcp' AND p.prokind IN ('f','p','w')
)
SELECT json_build_object('databaseOid',(SELECT oid::text FROM pg_database WHERE datname=current_database()),
 'tables',to_regclass('ouf_mcp.profile_analysis') IS NOT NULL
     AND to_regclass('ouf_mcp.profile_analysis_task') IS NOT NULL,
 'schema',(SELECT json_agg(item ORDER BY item COLLATE "C") FROM shape),
 'history',(SELECT json_agg(json_build_array(version,checksum,applied_at) ORDER BY version)
              FROM ouf_mcp.schema_migration));
ROLLBACK;"""


def database_snapshot(engine_socket, binding, old, pg):
    require(pg["Id"] == binding["postgresCid"] and pg["State"]["Running"], "POSTGRES_CHANGED")
    values = [v.partition("=")[2] for v in old["Config"]["Env"] if v.partition("=")[0] == binding["urlEnv"]]
    require(len(values) == 1, "DATABASE_BINDING_REQUIRED")
    url = urlsplit(values[0])
    role, name = unquote(url.username or ""), unquote(url.path[1:])
    overrides = {"host", "hostaddr", "port", "user", "password", "dbname", "database", "service", "servicefile"}
    require(url.scheme in ("postgres", "postgresql") and not url.fragment and
            all(matches(r"[a-z_][a-z0-9_]{0,62}", v) for v in (role, name)) and
            all(k.lower() not in overrides
                for k, _ in parse_qsl(url.query, keep_blank_values=True)), "DATABASE_BINDING_CHANGED")
    networks = {ep["NetworkID"] for ep in old["NetworkSettings"]["Networks"].values()}
    require(any(ep["NetworkID"] in networks and url.hostname in
                [pg["Name"].lstrip("/"), ep["IPAddress"], *(ep.get("Aliases") or []), *(ep.get("DNSNames") or [])]
                for ep in pg["NetworkSettings"]["Networks"].values()), "DATABASE_HOST_CHANGED")
    args = ["/usr/bin/docker", "--host", "unix://" + engine_socket, "exec", "-i", pg["Id"], "psql",
            "-XwqAt", "-v", "ON_ERROR_STOP=1", "-h", binding["socket"], "-p", str(url.port or 5432),
            "-U", role, "-d", name]
    result = subprocess.run(args, input=SQL.encode(), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=12)
    require(result.returncode == 0 and len(result.stdout) <= 4 << 20, "DATABASE_READ_FAILED")
    return json.loads(result.stdout)


def observe(rt, old):
    value = rt.database(old)
    rows = value["history"]
    require(value["tables"] is True and value["databaseOid"] and isinstance(rows, list)
            and all(isinstance(row, list) and len(row) == 3 and type(row[0]) is int and row[0] == i
                    and matches(SHA, row[1]) and isinstance(row[2], str) and row[2]
                    for i, row in enumerate(rows, 1)) and isinstance(value["schema"], list) and value["schema"]
            and all(isinstance(item, str) for item in value["schema"]), "DATABASE_CHANGED")
    return {"databaseOid": value["databaseOid"], "history": rows, "schema": sorted(map(digest, value["schema"]))}


def verify(rt, old, baseline, migration, *, migrated=False):
    now = observe(rt, old)
    items = migration["migrations"] if migrated else []
    if not items:
        require(now == baseline, "DATABASE_CHANGED")
        return
    before = baseline["history"]
    added = [{"version": row[0], "checksum": row[1]} for row in now["history"][len(before):]]
    require(now["databaseOid"] == baseline["databaseOid"] and now["history"][:len(before)] == before
            and added == items and set(baseline["schema"]) <= set(now["schema"])
            and digest(now["schema"]) == migration["targetSchemaSha256"], "DATABASE_CHANGED")
