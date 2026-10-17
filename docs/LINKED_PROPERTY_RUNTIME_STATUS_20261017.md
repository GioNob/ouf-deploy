# Linked-property reconciliation: deployment evidence, 17 October 2026

The generic implementation is in UDP `4660b08fdf982f7f7ecc35a378fd8fcad30aa273` and Onboarding `cc7766e6348f9ed2e66ec04018ebb63a904d202d`. It operates on canonical handoffs from files, APIs, scheduler deltas and spatial sources. Geometry retains its dedicated spatial policy. The CSV source used below is a retained installation test fixture, not a product restriction.

## Reported deployment

The operator returned `OUF_LINKED_PROPERTY_UPDATE_RESULT` for `/etc/ouf/deploy-snapshots/linked-property-execution-cjecd1en`: `complete=true`, `applicationReady=true`, `udpMigrationVersion=35`, journal version 55. No identity decisions, job retries, Gateway writes or policy worker were performed. `nativeProfilePublished=false`.

This is the executor result supplied by the operator. The bounded post-rollout reader independently checks current generations, persisted migration history, the V35 schema objects and metadata of the selected source publication. It uses two read-only SQL transactions, opens no token or credential file and performs no publication or scheduler action. Its artifact links are checked locally; it does not re-verify review signatures or claim end-to-end acceptance.

## Activation still required

The approved specification remains the normative comparison policy. Each affected property needs a versioned native `reconciliation` rule in the published source configuration. Existing cardinality, normalization, source authority, temporal/revision and deletion contracts must be considered explicitly; they must not be inferred from a CSV name or from matching sample values.

Creating a new active source publication may be observed by the Ingestion scheduler, including `triggerOnce` sources. Profile deployment must therefore be distinguished from activation, reacquisition and historical reprocessing. The post-rollout reader exposes the currently published property rules and scheduling metadata to prepare an exact review before any such effect.

Status remains technical phases **8/8**, functional milestones **2/6**. Installed code and schema do not prove that a native profile has been published or consumed.
