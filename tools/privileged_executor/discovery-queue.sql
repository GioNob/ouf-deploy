SELECT created_by_subject AS owner_scope,
       request_id, state, recovery_state, attempt_count, worker_generation,
       lease_until, next_attempt_at, budget_started_at, budget_deadline
FROM ouf_sem.discovery_request
ORDER BY created_by_subject, request_id;
