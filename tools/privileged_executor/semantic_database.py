"""Governed Semantic SQL migrations. Only inventory identifiers leave the executor."""
import hashlib
import json
import re
import subprocess

from mandate import Held, digest, need
from module_release import flyway
from module_release.contract import valid_semantic_database
from store import Journal, read, save


def binding(cfg):
    db = cfg.get("semanticDatabase")
    need(valid_semantic_database(db), "SEMANTIC_DATABASE_PROFILE_REQUIRED")
    return db


def route(config):
    flags = [item.partition("=")[2].lower() for item in config["Env"]
             if item.partition("=")[0] == "SPRING_FLYWAY_ENABLED"]
    need(flags in ([], ["true"], ["false"]), "FLYWAY_MODE_UNPROVEN")
    return "governed-sql" if flags == ["false"] else "spring-flyway"


# Quoted function bodies are data at the outer SQL statement level.
TOKENS = re.compile(r"""--[^\r\n]*|/\*|
    (?P<tag>\$(?:[a-zA-Z_]\w*)?\$)[\s\S]*?(?P=tag)|
    [eE]'(?:\\[\s\S]|''|[^'\\])*'|'(?:''|[^'])*'|"(?:""|[^"])*"|
    [a-zA-Z_][\w$]*|\$\d+|\s+|.""", re.X)
COMMENT_BOUNDARY = re.compile(r"/\*|\*/")


def check_script(raw):
    sql = raw.decode("utf-8-sig")
    first = True
    prepared = False
    offset = 0
    while offset < len(sql):
        token = TOKENS.match(sql, offset)
        word = token[0]
        offset = token.end()
        if word == "/*":
            depth = 1
            for delimiter in COMMENT_BOUNDARY.finditer(sql, offset):
                depth += 1 if delimiter[0] == "/*" else -1
                if depth == 0:
                    offset = delimiter.end()
                    break
            need(depth == 0, "UNTERMINATED_MIGRATION_COMMENT")
            continue
        if word.isspace() or word.startswith("--"):
            continue
        upper = word.upper()
        need(word not in ("'", '"', "\\", "\x00", "$") and upper != "CONCURRENTLY"
             and not (first and upper in ("COMMIT", "BEGIN", "END", "ABORT", "ROLLBACK", "START"))
             and not (prepared and upper == "TRANSACTION"),
             "NONTRANSACTIONAL_MIGRATION_DENIED")
        prepared = first and upper == "PREPARE"
        first = word == ";"


def reviewed(doc, manifest):
    scripts = {}
    rows = flyway.inventory(doc, scripts=scripts)
    actual = [{"name": name, "sha256": hashlib.sha256(raw).hexdigest()} for name, raw in scripts.items()]
    need(isinstance(manifest, list) and all(isinstance(r, dict) and isinstance(r.get("name"), str) for r in manifest)
         and sorted(actual, key=lambda r: r["name"]) == sorted(manifest, key=lambda r: r["name"]),
         "SEMANTIC_MIGRATION_INVENTORY_DRIFT")
    return rows, scripts


def prefix(facts, rows, schema):
    history = [] if facts["history"] is None else facts["history"]
    need(isinstance(history, list) and re.fullmatch(r"[0-9]+", facts["databaseOid"]), "FLYWAY_HISTORY_UNPROVEN")
    # Flyway may record schema creation as the first, unversioned marker.
    marker = history[:1] if history and history[0]["type"] == "SCHEMA" else []
    if marker:
        need(marker == [{"version": None, "type": "SCHEMA", "script": f'"{schema}"',
                         "checksum": None, "success": True}] and marker[0]["success"] is True,
             "FLYWAY_HISTORY_UNPROVEN")
    applied = history[len(marker):]
    need(applied == rows[:len(applied)] and all(r["success"] is True and type(r["checksum"]) is int for r in applied),
         "FLYWAY_HISTORY_NOT_EXACT_PREFIX")
    return marker, len(applied)


class Database:
    def __init__(self, cfg):
        self.db = binding(cfg)
        db = self.db
        self.args = ["/usr/bin/docker", "--host", "unix://" + cfg["socket"], "exec", "-i", db["postgresCid"],
                     "psql", "-X", "-wqAt", "-v", "ON_ERROR_STOP=1", "-h", db["socket"], "-U", db["user"],
                     "-d", db["database"], "-v", "schema=" + db["schema"]]

    def psql(self, sql, *, observe=False):
        try:
            result = subprocess.run(self.args, input=sql.encode(), stderr=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE if observe else subprocess.DEVNULL,
                                    timeout=12 if observe else 75)
        except (OSError, subprocess.TimeoutExpired):
            raise Held("SEMANTIC_DATABASE_OUTCOME_UNPROVEN") from None
        need(result.returncode == 0, "SEMANTIC_DATABASE_READ_FAILED" if observe else "SEMANTIC_DATABASE_MIGRATION_HELD")
        if observe:
            need(0 < len(result.stdout) <= 1 << 20, "FLYWAY_HISTORY_UNPROVEN")
            return json.loads(result.stdout)

    def history(self):
        return self.psql(flyway.SQL, observe=True)

    def apply_one(self, before, row, raw):
        # Recheck the complete approved prefix *under the history-table lock*.
        # SPI executes reviewed bytes as SQL and cannot terminate our transaction.
        # The script never becomes psql input (including backslashes and variables).
        schema = self.db["schema"]
        table = f'"{schema}".flyway_schema_history'
        history = flyway.HISTORY_QUERY.replace(':"schema".flyway_schema_history', table)
        expected = json.dumps(before).encode().hex()
        body = raw.decode("utf-8-sig").encode().hex()
        name = row["script"]
        description = name.split("__", 1)[1][:-4].replace("_", " ")
        need(len(description) <= 200 and len(name) <= 1000, "FLYWAY_FILENAME_TOO_LONG")
        self.psql(f"""BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='60s';
SET LOCAL standard_conforming_strings=on;
SET LOCAL search_path=pg_catalog;
LOCK TABLE {table} IN SHARE ROW EXCLUSIVE MODE;
DO $ouf$ DECLARE started timestamptz; BEGIN
 IF ({history})::jsonb IS DISTINCT FROM convert_from(decode('{expected}','hex'),'UTF8')::jsonb THEN
   RAISE EXCEPTION 'history drift';
 END IF;
 PERFORM set_config('search_path','"{schema}"',true);
 started := clock_timestamp();
 EXECUTE pg_catalog.convert_from(pg_catalog.decode('{body}','hex'),'UTF8');
 INSERT INTO {table}(installed_rank,version,description,type,script,checksum,installed_by,execution_time,success)
 SELECT coalesce(max(installed_rank),0)+1,'{row["version"]}','{description}','SQL','{name}',{row["checksum"]},
        current_user,floor(extract(epoch FROM (clock_timestamp()-started))*1000)::int,true FROM {table};
END $ouf$;
COMMIT;""")


def proposal(database, rows, scripts):
    facts = database.history()
    marker, count = prefix(facts, rows, database.db["schema"])
    for row in rows[count:]:
        check_script(scripts[row["script"]])
    return {"binding": digest(database.db), "databaseOid": facts["databaseOid"], "marker": marker,
            "applied": count, "rows": rows, "inventory": digest({n: hashlib.sha256(s).hexdigest() for n, s in scripts.items()})}


def apply(root, run, database, plan, rows, scripts, guard):
    current = proposal(database, rows, scripts)
    need({**current, "applied": plan["applied"]} == plan and current["applied"] >= plan["applied"],
         "SEMANTIC_MIGRATION_PLAN_DRIFT")
    count = current["applied"]
    journal = Journal(root / ("semantic-db-" + digest([database.db, plan["databaseOid"]])))
    for index, row in enumerate(rows):
        # Stable identity across dispatches, including a fresh plan after a lost receipt.
        before = {"databaseOid": plan["databaseOid"], "history": plan["marker"] + rows[:index] or None}
        effect = {"before": digest(before), "migration": row, "sha256": hashlib.sha256(scripts[row["script"]]).hexdigest()}
        name = "sql-" + digest(effect)
        claim, receipt = (journal.path / (name + suffix) for suffix in (".claim", ".receipt"))
        if index < count:
            if claim.exists():
                need(read(claim) == effect, "MIGRATION_CLAIM_DRIFT")
                if not receipt.exists():
                    save(receipt, {"planSha256": digest(effect), "result": row})
                need(read(receipt) == {"planSha256": digest(effect), "result": row}, "MIGRATION_RECEIPT_DRIFT")
            else:
                need(index < plan["applied"] and not receipt.exists(), "UNCLAIMED_MIGRATION")
            continue
        guard()
        need(not receipt.exists(), "MIGRATION_RECEIPT_HISTORY_DRIFT")
        # A fresh approved dispatch may retry an absent row. Its transaction must
        # acquire the same table lock and still observe the exact before-state.
        if claim.exists():
            need(read(claim) == effect, "MIGRATION_CLAIM_DRIFT")
        else:
            save(claim, effect)
        attempt = journal.path / (name + "-" + run + ".attempt")
        need(not attempt.exists(), "MIGRATION_ATTEMPT_REQUIRES_FRESH_REVIEW")
        save(attempt, {"claim": digest(effect), "plan": digest(plan), "run": run})
        try:
            database.apply_one(before, row, scripts[row["script"]])
            now = database.history()
            need(now == {"databaseOid": plan["databaseOid"], "history": plan["marker"] + rows[:index+1]},
                 "MIGRATION_EFFECT_UNPROVEN")
        except Held as error:
            save(attempt.with_suffix(".failure"), {"status": "HELD", "claim": digest(effect), "reason": str(error)})
            raise
        save(receipt, {"planSha256": digest(effect), "result": row})
    verify(database, plan)
    guard()


def verify(database, plan):
    need(database.history() == {"databaseOid": plan["databaseOid"], "history": plan["marker"] + plan["rows"]},
         "SEMANTIC_MIGRATION_INCOMPLETE")
