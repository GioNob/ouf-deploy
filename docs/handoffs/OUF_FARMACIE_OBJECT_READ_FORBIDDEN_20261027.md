# Farmacie — fallimento di lettura oggetto localizzato, causa autorizzativa da verificare

27 ottobre2026, Europe/Rome. [Prova MCP owner](../../evidence/farmacie-object-read-forbidden-observed-20261027.json). [Checkpoint precedente](OUF_FARMACIE_DIAGNOSTIC_INSTALLED_NEXT_READ_20261027.md).

Proposta f8bc6357-136b-40fc-8a40-8d22816df0b0 r1 PUBLISHED, finalPolicyRef ouf-lab-authorization:55, verificata prima della sola preview. Account ouf-admin; stesso asset9c502da5-b5d8-405e-b3f5-60eb31ecb513/job677480c8-3d10-44fd-9dad-f72ddeed20a4. Risposta FAILED, resultRefnull, ONB_FILE_PROFILE_FAILED, diagnosticCategory OBJECT_READ_FORBIDDEN. La READ applicativa prevista è stata eseguita UNA volta ed è consumata. Nessun contenuto file scaricato o nuovo tentativo di profiling.

## Risultato causale e limite

Il codice installato a5ed8b05c264a8221783a6e323ba00117aed891d esegue GatewayManagedFileObjectStore.read prima di completeProfile/parser. Un non2xx produce l'esatto messaggio allowlisted "Gateway object read failed with status 403" prima della lettura body. È quindi provato il confine del fallimento conservato: object read negata. Non è una nuova prova HTTP contro Gateway oggi; la preview legge il FAILED storico. Non prova regola specifica, token corrente, hash server o validità del CSV sul parser Java.

Catalogo sorgente `catalogue/r4a-managed-file-read-grants.json`: grant-managed-file-read-onboarding, capability ouf.object-storage.content.read, servicePrincipalId ouf-onboarding, tenantouf-lab, validUntil2026-10-25T00:00:00Z, constraintsnull. È un indizio preciso da confrontare con policy attiva, non autorità o prova del grant sul server. Il grant Ingestion distinto presente nel medesimo catalogo non va modificato implicitamente.

Percorso dichiarato Gateway: GET/internal/object-storage/v1/content→Onboarding/api/internal/v1/onboarding/managed-files/content; identità M2M/SERVICE e scope ouf.internal.object-storage.read. Owner richiede ouf.object-storage.content.read. Config/route sorgente c22fbf7f... è un contratto riusabile, non una cattura della rotta attiva.

## Lettura successiva

MCP permissions.read installato ammette subjectId oppure externalRoleRef. AuthorizationReviewService.projectGrants confronta subjectId con grant.subjectId, NON servicePrincipalId: non usare ouf-onboarding come subject fingendo di avere verificato i grant SERVICE. Nessuna chiamata senza selettore o fuori schema tentata.

Serve lettura governata della policy owner attiva, minimizzata ai grant SERVICE pertinenti e con nessuna modifica. I precedenti lettori descriptor/read e il lifecycle SERVICE già esistenti forniscono Device Flow HUMAN e API GET policy attiva: riusarli in un nuovo scope soltanto READ, senza rigiocare plan/draft/publish storici. Nessun token, client secret, chiave, SQL, rawlog, contenuto file o nuovo job deve essere stampato/creato. Prima di qualsiasi fix distinguere expiry del grant da token/scope/route/owner; nessun rinnovo alla cieca.

D4 ha anche un delta concreto confermato: il worker attuale riprova ogni Exception fino5 volte, incluso questo403. La policy finita di errore/recovery va qualificata preservando FAILED e tentativi già consumati; questo checkpoint non autorizza reset o rilancio.

Diagnostica minima installata sul VPS, tutti i comandi APPLY e preparazioni precedenti consumati. M1/G4 acquisito; typed/ASSETS/LATEST/recovery/UDP esistenti da riusare; M2/G5/G6/G7 aperti. No subagenti/automazioni/Registry restart/reinstall/merge/release acceptance; Supervisor dopo E2E.
