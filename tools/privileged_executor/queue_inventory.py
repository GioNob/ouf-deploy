"""PostgreSQL readback. The private subject directory maps every pending row to its tenant."""
from contextlib import contextmanager
from datetime import datetime, timezone
import os
import time

from mandate import digest, need
from store import bound

QUERY = """
SELECT created_by_subject, request_id, state, recovery_state, attempt_count, worker_generation,
       lease_until, next_attempt_at, budget_deadline
FROM ouf_sem.discovery_request
WHERE state IN ('PENDING','RUNNING') ORDER BY request_id
"""

FIELDS = ("requestId", "state", "recoveryState", "attempts", "claimGeneration",
          "leaseUntil", "nextAttemptAt", "budgetDeadline")


def inventory(rows, tenants):
    result = []
    for subject, *values in rows:
        need(subject in tenants and len(values) == len(FIELDS), "QUEUE_SCOPE_UNPROVEN")
        def scalar(v):
            if isinstance(v, datetime):
                return v.astimezone(timezone.utc).isoformat()
            return v if isinstance(v, int) or v is None else str(v)
        result.append(dict(tenant=tenants[subject], **dict(zip(FIELDS, map(scalar, values)))))
    return result


def review_rows(rows):
    return [{"ref": digest([row["tenant"], row["requestId"]]), **{k: row[k] for k in FIELDS if k != "requestId"}}
            for row in rows]


def permit(rows, policy, approved):
    need(rows == approved and (policy == "inventory" or not rows), "QUEUE_APPROVAL_DRIFT")
    need(all(row["state"] != "RUNNING" for row in rows), "CLAIM_IN_FLIGHT")


class Queue:
    def __init__(self, profile):
        self.cfg = profile
        self.fenced = None

    def connect(self):
        import psycopg
        os.environ["PGSERVICEFILE"] = str(bound(self.cfg["serviceFile"]))
        conn = psycopg.connect(service=self.cfg["service"], connect_timeout=5,
                               options="-c row_security=off -c statement_timeout=5000 -c lock_timeout=1000")
        try:
            need(conn.info.dbname == self.cfg["database"], "QUEUE_DATABASE_DRIFT")
            return conn
        except BaseException:
            conn.close()
            raise

    @contextmanager
    def snapshot(self, fence=False):
        with self.connect() as conn:
            if fence:
                # Block concurrent enqueue, claim and publication through the decision.
                conn.execute("LOCK TABLE ouf_sem.discovery_request IN SHARE MODE NOWAIT")
            else:
                conn.execute("SET TRANSACTION READ ONLY")
            self.fenced = conn if fence else None
            try:
                yield inventory(conn.execute(QUERY), self.cfg["subjectTenants"])
                if fence:
                    self.assert_fence()
            finally:
                self.fenced = None

    def clock(self):
        self.assert_fence()
        return self.fenced.execute("SELECT extract(epoch FROM clock_timestamp())").fetchone()[0]

    def assert_fence(self):
        need(self.fenced is not None, "QUEUE_FENCE_REQUIRED")
        sql = """SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid()
                 AND relation='ouf_sem.discovery_request'::regclass AND mode='ShareLock' AND granted)"""
        need(self.fenced.execute(sql).fetchone() == (True,), "QUEUE_FENCE_LOST")

    def worker(self, since):
        spec = self.cfg["proof"]
        sql = """
        SELECT r.request_id FROM ouf_sem.discovery_request r
        WHERE r.created_by_subject=%s AND r.idempotency_key_hash=%s AND r.request_fingerprint=%s
          AND r.created_at >= to_timestamp(%s) AND r.state='SUCCEEDED' AND r.worker_generation>0
          AND EXISTS (SELECT 1 FROM ouf_sem.discovery_candidate c WHERE c.request_id=r.request_id
              AND c.provider_id=%s AND c.canonical_uri=%s AND octet_length(c.content_bytes)>0)
        """
        end = time.monotonic() + self.cfg["proofWaitSeconds"]
        while time.monotonic() < end:
            with self.connect() as conn:
                conn.execute("SET TRANSACTION READ ONLY")
                ids = list(conn.execute(sql, (spec["subject"], spec["keyHash"], spec["fingerprint"],
                                               since, spec["provider"], spec["uri"])))
                if len(ids) == 1:
                    return {"requestId": str(ids[0][0]), "state": "SUCCEEDED"}
            time.sleep(2)
        need(False, "MCP_WORKER_PROOF_PENDING")
