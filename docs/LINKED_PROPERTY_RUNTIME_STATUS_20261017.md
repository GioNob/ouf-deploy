# Linked-property reconciliation: deployment evidence, 17 October 2026

The generic implementation is in UDP `4660b08fdf982f7f7ecc35a378fd8fcad30aa273` and Onboarding `cc7766e6348f9ed2e66ec04018ebb63a904d202d`. It operates on canonical handoffs from files, APIs, scheduler deltas and spatial sources. Geometry retains its dedicated spatial policy. The CSV source used below is a retained installation test fixture, not a product restriction.

## Reported deployment

The operator returned `OUF_LINKED_PROPERTY_UPDATE_RESULT` for `/etc/ouf/deploy-snapshots/linked-property-execution-cjecd1en`: `complete=true`, `applicationReady=true`, `udpMigrationVersion=35`, journal version 55. No identity decisions, job retries, Gateway writes or policy worker were performed. `nativeProfilePublished=false`.

This is the executor result supplied by the operator. The bounded post-rollout reader independently checks current generations, persisted migration history, the V35 schema objects and metadata of the selected source publication. It uses two read-only SQL transactions, opens no token or credential file and performs no publication or scheduler action. Its artifact links are checked locally; it does not re-verify review signatures or claim end-to-end acceptance.

## Activation still required

The approved specification remains the normative comparison policy. Each affected property needs a versioned native `reconciliation` rule in the published source configuration. Existing cardinality, normalization, source authority, temporal/revision and deletion contracts must be considered explicitly; they must not be inferred from a CSV name or from matching sample values.

Creating a new active source publication may be observed by the Ingestion scheduler, including `triggerOnce` sources. Profile deployment must therefore be distinguished from activation, reacquisition and historical reprocessing. The post-rollout reader exposes the currently published property rules and scheduling metadata to prepare an exact review before any such effect.

Status remains technical phases **8/8**, functional milestones **2/6**. Installed code and schema do not prove that a native profile has been published or consumed.

## Activation preparation and XSD compatibility

The reported post-rollout read confirms all20 reconciliation entries are null and V35 checksum is -376865285. Preparation found that the installed validators reject the unchanged XML Schema string datatype when reconciliation is added. UDP PR44 and Onboarding PR45 add exact string-IRI compatibility; both are qualified in CI but not installed.

A concrete20-property proposal preserves datatype, labels, authority and the outer materialization policy. It uses the approved conservative SINGLE default, EXACT_TYPED v1, existing source intervals only, no revision/deletion contract. Native semantic constraint read returned403 SEM_READ_RECEIPT_OR_POLICY_DENIED; no login or grant was opened. Full owner configuration and temporal/semantic constraints remain activation gates.

Ingestion derives one-shot behavior from MANAGED, independently of top-level triggerOnce. A new publication may re-arm acquisition. No publication, job retry, source disable or identity decision was performed. See [the preparation, PET traceability and native publication path](LINKED_PROPERTY_ACTIVATION_PREPARATION_20261017.md). Technical8/8; functional2/6 unchanged.

