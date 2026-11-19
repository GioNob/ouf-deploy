# OUF CLOUD — CSV end-to-end miniproject plan ready

## Checkpoint esecutivo corrente — 2026-10-20T12:54:32.221Z

Mini-PET1.1 invariato. **G0/G1/G2 PASS; tecniche8/8, funzionali4/6**. G2qualificato sui byte24c2d9b8c7b3f4f8a4a61125b86877ffbd635dba:162test componenti,3PG17,3prove native con sequenza completa mediante loader114moduli/issuer/entrypoint isolato. [Dossier G2](../CSV_E2E_G2_NATIVE_EXECUTOR_QUALIFICATION_20261020.md). Nessuna autorità o esecuzione target.

Effort misurato al G2:3.161h, intervallo conservativo3.161–3.731h contro14h cumulative di baseline, comprensivo di WP5 intercalato. Il [registro cronologico](../CSV_E2E_EXECUTION_CHRONOLOGY_20261020.md) conserva gli intervalli non verificati separati e non riscrive la baseline.

WP3 resta bloccato dai gate runtime correnti; ultima finestra HUMAN278/288 scaduta, nessun reset/login/rinnovo automatico. I26tool esposti sono stati ricontrollati come definizioni, con routingouf-admin disponibile; nessuna chiamata protetta è stata usata come probe di autenticazione e manca un executor target qualificato. Contesti/claim/Owner7/proiezione7 invariati.

WP5 in corso: PRIngestion45(bcc1354,197testPASS/2skip), Onboarding48(17a68ae,273PASS/0skip), UDP47(df1f4c3,267PASS/2skip). Conversioni decimale/data e datatype sono implementati e qualificati nei moduli; prova composta, vocabolari e relazione restano aperti. La coorte runtime storica0fe e il packet trattenuto non vengono sostituiti da queste branch. G3–G7 e M1/M2 restano aperti. Quanto segue conserva il piano/handoff iniziale e non supera questo checkpoint.


20 October 2026. Planning/documentation only. Technical8/8,functional4/6 unchanged.

Start from [Mini-PET v1.1](../OUF_CSV_E2E_COMPLETION_MINIPET_v1_1_20261020.md),
[structured plan](../../releases/csv-e2e-completion-plan-20261020.json),
[repository audit](../CSV_REPOSITORY_REAUDIT_AND_EFFORT_20261020.md).
User requested this precise roadmap as the basis for the next session; no implementation or target action was started after that request.

Update20October10:58Europe/Rome request: version1.1 adds a cumulative effort schedule,
30activity allocations, all gate/milestone forecasts, HUMAN participation and passive
wait/actual-effort tracking. Central sequence reaches G1 at3h,G2 at14h,G3 at19h,
F5 at22h,F6/G4/M1 at24h,G5 at35h,G6 at46h,G7/M2 at55h.
Ranges stay18–30h forM1 and40–70h total; HUMAN3–6h is separate. Runtime authority
and finite budgets are unchanged. No implementation started by this document update.

Next action: WP0/WP1. Pin current heads and diagnose the three observed CI findings:
Ingestion39380500855 (RunControl schedules/fixture isolation hypothesis),
MCP39232083000 (p95performance gate; same-head push passed),
Deploy39392193693 (historical human_session.py capsule/package pin mismatch).
Do not claim the full candidate cohort is green from component checks.
Then WP2 completes native Ports, current HUMAN/Owner/DB guards, new Gateway HTTP
transport, scope issuer, immutable closure and entrypoint using existing components.

Two milestones remain distinct: M1 closes retained F5/F6 (18–30active assisted hours);
M2 proves general repeatable CSV on new inputs/two clients (40–70hours total).
Vocabulary-value mapping and declared types/relationship composition are real deltas:
current managed proposal and canonical pipeline support only IDENTITY/string and no
vocabulary mappings in that path. Reuse source revision, identity/property and recovery
implementations; do not reimplement them.

Current ouf-admin is account routing, not an exact tool/plugin name.26OUF definitions
are exposed, but no protected capability/authentication probe or target executor was
used. No new login, refresh, renewal, reset, target Engine/DB/Gateway effect, subagent,
scheduled automation or replay. Last HUMAN278/288 with10left is expired and is not
current authority. Source/runtime states remain distinct.

Preserve retained context qfcpqd9f and predecessor contexts kkj_njiz,0wd4wyuf;
packet hash ad1bdb240483f85785b989f28cd895a72394ea964baabd85ad3062b10180fe5c;
verified inputs c556d7ea44bc7f7e1f337358e166e2cde11c90e6459a76cc703c178218bd9907.
Owner7/projection7 and completed installation/readback/preparation/DB/MAC steps remain
consumed. STOP means retain and reconcile without replay. New native profile publication,
current DB admission and full runtime executor qualification are not yet proven.

All Ente-specific values, including MAC/IP/network/path/UID/domain bindings, belong in
validated versioned profiles. Canonical APIs, capabilities and owner semantics remain
fixed by PET. The mini-PET records original baseline sections,24requirements,24local
acceptance tests and canonical E2E mapping without inventing new canonical identifiers.

The document is a plan, not runtime authority. Do not resume at WP3 until G1/G2 and the
fresh explicit runtime gates are actually satisfied. Full current source inventory and
CI observations are in evidence/csv-repository-effort-reaudit-20261020.json.
