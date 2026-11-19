## Tappa funzionale3 completata sul target — 18 ottobre 2026

**Stato corrente: tecniche8/8; funzionali3/6;13/13 righe committate;13 oggetti distinti; zero quarantene residue per la sorgente di collaudo.** Questo esito supera i precedenti checkpoint2/6 e12/13, conservati sotto come storia.

Il log fornito dall'utente `/home/oufadmin/ouf-csv-last-row-recovery.sHJ0mSn1/run.log` riporta `OUF_LAST_ROW_RECOVERY_RESULT.complete=true`, `singleJobCommitted=true`, `functionalStage3Proven=true` e `upstreamHandoffsAndLineageMatch=true`. Sono confermati il commit di tutte13 le righe, gli11 oggetti CREATE_NEW precedentemente verificati e la conservazione dell'oggetto originario; nessuna riga non provata. [Evidenza target redatta](csv-functional-stage3-target-proof-20261018.json). È evidenza del log target ricevuto, non una nuova interrogazione live dell'agente.

Il job residuo `c5692362-8a22-4656-97b6-46b5ba8ce17f` ha ricevuto **una sola ripresa nativa accettata** ed è arrivato al commit senza ripetere la decisione d'identità. Un grant aggiunto tramite owner ha pubblicato `ouf-lab-authorization:42`, hash `75834f0c64d929cc40401867aa65542b4ba15bb3e4bc32a6fd4ca719bab79fb1`, conservando grant preesistenti e capabilities. Nessuna nuova pubblicazione della fonte o reset di budget. La sessione del credential owner ha effettuato un tentativo/una pubblicazione oltre i318 conservati, entro il tetto444.

Lo stato finale `CANCELLED_BY_OWNER` del worker è la terminazione prevista del recupero finito dopo il successo; non annulla il commit. Il campo `applicationReady=false` del reporter del token owner non è una valutazione della disponibilità complessiva OUF né una prova di accettazione end-to-end. `continuousCredentialLifecycleProven=false` resta esplicito.

La verifica funzionale successiva è la **tappa4: ritrovare i dati con una nuova ricerca dal chatbot**; seguono la5 (seconda importazione dello stesso CSV senza duplicazioni) e la6 (verifica di entrambe le acquisizioni e conservazione degli8 Cinema preesistenti). Prima della ripetizione, valutare gli effetti di pubblicazione/scheduler e le policy effettive senza inventare cardinalità o priorità. Il successo della tappa3 non dimostra l'attivazione di un profilo nativo di riconciliazione, il caso merge/collegamento a oggetto esistente, il rinnovo continuativo o il percorso interamente da chat. Restano criteri di accettazione anche resilienza di rete, ripresa durevole e nessun comando VPS per l'utente.

# Linked-property reconciliation: deployment evidence, 17 October 2026

The generic implementation is in UDP `4660b08fdf982f7f7ecc35a378fd8fcad30aa273` and Onboarding `cc7766e6348f9ed2e66ec04018ebb63a904d202d`. It operates on canonical handoffs from files, APIs, scheduler deltas and spatial sources. Geometry retains its dedicated spatial policy. The CSV source used below is a retained installation test fixture, not a product restriction.

## Reported deployment

The operator returned `OUF_LINKED_PROPERTY_UPDATE_RESULT` for `/etc/ouf/deploy-snapshots/linked-property-execution-cjecd1en`: `complete=true`, `applicationReady=true`, `udpMigrationVersion=35`, journal version 55. No identity decisions, job retries, Gateway writes or policy worker were performed. `nativeProfilePublished=false`.

This is the executor result supplied by the operator. The bounded post-rollout reader independently checks current generations, persisted migration history, the V35 schema objects and metadata of the selected source publication. It uses two read-only SQL transactions, opens no token or credential file and performs no publication or scheduler action. Its artifact links are checked locally; it does not re-verify review signatures or claim end-to-end acceptance.

## Activation still required

The approved specification remains the normative comparison policy. Each affected property needs a versioned native `reconciliation` rule in the published source configuration. Existing cardinality, normalization, source authority, temporal/revision and deletion contracts must be considered explicitly; they must not be inferred from a CSV name or from matching sample values.

Creating a new active source publication may be observed by the Ingestion scheduler, including `triggerOnce` sources. Profile deployment must therefore be distinguished from activation, reacquisition and historical reprocessing. The post-rollout reader exposes the currently published property rules and scheduling metadata to prepare an exact review before any such effect.

Status remains technical phases **8/8**, functional milestones **2/6**. Installed code and schema do not prove that a native profile has been published or consumed.
