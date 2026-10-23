# Postboot controller observation boundary

Local qualification, 2026-10-23: `python -B -m unittest discover -s tools/semantic_registry_recovery_execution/tests -p test_controller.py -v` — **13 PASS, 0 skips**. These tests use the actual recovery `Runner`, durable `Store`, controller and Python threads. Native ports, authority/generation witness and the token worker are explicitly simulated. This is not Docker, TLS issuer, JVM or target qualification.

The controller previously stopped on every non-advancing step. A successful Docker SIGUSR1 response can precede the shell's Java `exec`, and Java can precede Spring readiness and policy admission. Stopping the owner during those ordinary intervals prevents the service from obtaining its first usable policy bundle.

The controller now permits additional observations only at these boundaries:

| Checkpoint | Evidence required before waiting | Remaining uncertainty |
| --- | --- | --- |
| 9, release | Durable request-attempt claim and Docker response 204; same current generation | Shell-to-Java transition not observed yet |
| 10, readiness | Release already APPLIED and response 204 retained; same current generation | Application readiness not established |
| 11, final request | Release already APPLIED and response 204 retained; same current generation | Readiness or exact original SERVICE GET still unproven |

An observation returning UNKNOWN is not a successful readiness or authorization decision. In particular, a configured repeated 403 observation does not establish whether policy is merely loading or access is permanently denied. Only the existing final verifier's exact ACTIVE-reference 200 can complete recovery. The controller does not interpret response bodies, select another caller, acquire credentials or weaken that verifier.

The wait has one non-resetting 90-second window for initiating additional observations and at most 12 additional observations across checkpoints 9–11, normally separated by 5 seconds. An observation already in progress retains its existing native transport deadlines; 90 seconds is not a new hard process-termination timeout. These are restrictive local ceilings, not additional authority or durable budgets. Every repeated `Runner.step()` consumes the existing observation counters and invokes the existing signed-authority, owner, route, database and generation checks. The stage claim already exists, so `Runner` takes its observation path and never redispatches the effect. The same recovery journal must remain unchanged while waiting; external progress, generation change, revocation, expiry, clock regression and exhausted original counters stop before the next observation.

The controller releases its shared coordination lock during the wait. The same-process token worker keeps its lifetime invocation lock and runs under its original signed finite budget. Worker termination wakes the controller and prevents a subsequent recovery read. Every failure joins and stops the worker; success reports the verified GET before maintaining the worker for the remainder of its finite window. Neither result establishes perpetual renewal.

ACK ambiguity is distinct from slow startup. An absent response 204, a transport exception, an earlier checkpoint's UNKNOWN or a changed generation receives no automatic wait or dispatch. Existing claims remain consumed for separately authorized reconciliation. Tests prove one SIGUSR1 dispatch for successful delayed transitions, missing ACK and transport failure; 9→10→11 shares one wait counter; original read-budget exhaustion persists; concurrent journal movement is rejected; and the worker runs between observations without overlapping a native step under the shared lock.

Whole Docker/Registry JVM/PostgreSQL/TLS qualification, including actual cold-start and AUTHZ behavior, remains the responsibility of the separate native fixture. No target operation was performed for this qualification.
