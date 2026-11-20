"""PostgreSQL readback. The private subject directory maps every pending row to its tenant."""
import json
from pathlib import Path
import subprocess
import time

from mandate import digest, need

# Exact registry PR 48 projection (Git blob e8efb79269e4a9435e2b708edece0d4e097e4e36).
QUERY = Path(__file__).with_name("discovery-queue.sql").read_text(encoding="ascii").strip().removesuffix(";")
COLUMNS = ("owner_scope", "request_id", "state", "recovery_state", "attempt_count", "worker_generation",
           "lease_until", "next_attempt_at", "budget_started_at", "budget_deadline")
FIELDS = ("requestId", "state", "recoveryState", "attempts", "claimGeneration",
          "leaseUntil", "nextAttemptAt", "budgetStartedAt", "budgetDeadline")


def inventory(rows, tenants):
    result = []
    for subject, *values in rows:
        need(subject in tenants and len(values) == len(FIELDS), "QUEUE_SCOPE_UNPROVEN")
        result.append(dict(tenant=tenants[subject], **dict(zip(FIELDS, values))))
    return result


def review_rows(rows):
    return [{"ref": digest([row["tenant"], row["requestId"]]), **{k: row[k] for k in FIELDS if k != "requestId"}}
            for row in rows]


def permit(rows, policy, approved):
    need(rows == approved and (policy == "inventory" or not rows), "QUEUE_APPROVAL_DRIFT")
    need(all(row["state"] != "RUNNING" for row in rows), "CLAIM_IN_FLIGHT")


class Queue:
    def __init__(self, profile, docker_socket):
        self.cfg = profile
        self.socket = docker_socket

    def query(self, statement, *, deadline=None):
        c = self.cfg
        args = ["/usr/bin/docker", "exec", "-i", "-e", "PGOPTIONS=-cdefault_transaction_read_only=on",
                c["container"], "psql", "-X", "-w", "-q", "-P", "pager=off", "-v", "ON_ERROR_STOP=1",
                "-h", c["socket"], "-U", c["role"], "-d", c["database"], "-A", "-t"]
        timeout = 15 if deadline is None else min(15, deadline - time.monotonic())
        need(timeout > 0, "INGRESS_WINDOW_EXPIRED")
        sql = ("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\nSET LOCAL row_security=off;\n"
               "SET LOCAL statement_timeout='5s';\nSET LOCAL timezone='UTC';\n" + statement + ";\nCOMMIT;\n")
        run = subprocess.run(args, input=sql.encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env={"PATH": "/usr/bin:/bin", "DOCKER_HOST": "unix://" + self.socket},
                             timeout=timeout, check=True)
        return [json.loads(line) for line in run.stdout.splitlines()]

    def snapshot(self, *, deadline=None):
        sql = (f"SELECT row_to_json(q) FROM ({QUERY}) AS q WHERE state IN ('PENDING','RUNNING') "
               "ORDER BY owner_scope, request_id")
        rows = self.query(sql, deadline=deadline)
        need(all(isinstance(r, dict) and set(r) == set(COLUMNS) for r in rows), "QUEUE_PROJECTION_DRIFT")
        return inventory(([r[k] for k in COLUMNS] for r in rows), self.cfg["subjectTenants"])

    def worker(self, since):
        need("proof" in self.cfg, "WORKER_PROOF_PROFILE_REQUIRED")
        spec = self.cfg["proof"]
        # Only hex enters SQL text. The private proof stays on stdin, including for Docker exec events.
        binding = json.dumps(dict(spec, since=since), allow_nan=False).encode().hex()
        sql = f"""
        WITH input AS (SELECT convert_from(decode('{binding}', 'hex'), 'UTF8')::jsonb AS proof)
        SELECT to_json(r.request_id) FROM ouf_sem.discovery_request r CROSS JOIN input
        WHERE r.created_by_subject=(proof->>'subject') AND r.idempotency_key_hash=(proof->>'keyHash')
          AND r.request_fingerprint=(proof->>'fingerprint')
          AND r.created_at >= to_timestamp((proof->>'since')::numeric / 1000000)
          AND r.state='SUCCEEDED' AND r.worker_generation>0
          AND EXISTS (SELECT 1 FROM ouf_sem.discovery_candidate c WHERE c.request_id=r.request_id
              AND c.provider_id=(proof->>'provider') AND c.canonical_uri=(proof->>'uri')
              AND octet_length(c.content_bytes)>0)
        """
        end = time.monotonic() + self.cfg["proofWaitSeconds"]
        while time.monotonic() < end:
            ids = self.query(sql)
            if len(ids) == 1:
                return {"requestId": ids[0], "state": "SUCCEEDED"}
            time.sleep(2)
        need(False, "MCP_WORKER_PROOF_PENDING")
