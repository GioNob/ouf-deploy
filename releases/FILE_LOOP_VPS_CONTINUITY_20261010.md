# Continuità del giro VPS — riconciliazione 10 ottobre 2026

La precedente risposta «resta da completare il giro sul VPS» era troppo generica. Il percorso già consegnato non viene riaperto. La ricerca dei soli main non ricostruiva la baseline live: le prove operative decisive sono conservate anche su branch di coordinamento.

## Risultati da riusare

Fonte immutabile: [handoff 1 ottobre](https://github.com/GioNob/ouf-semantic-registry/blob/e7bc5190f9e6afbbc4cf3c90d5d4970afbfad14b/docs/handoffs/OUF_HANDOFF_2026-10-01_FILE_TO_UDP_NEXT_SPRINT.md), sezioni risultati e gate ereditati.

| Passaggio | Prova conservata | Disposizione |
| --- | --- | --- |
| Cinema approvato/ACTIVE | managed-cinema-8ec8ae90, run 86809c17-3354-45ca-a7e6-57e903944b24 SUCCEEDED; trigger_once consumato | Non riapprovare, riattivare o riacquisire |
| Delivery e materializzazione Cinema | 8 ACKED, 8 intake PROCESSED, 8 job SUCCEEDED, 8 NEW_OBJECT e 8 oggetti attivi; lineage/evidenze coerenti | Gate storico superato; nessun retry/replay |
| Recupero quarantene | Retry HUMAN governati riusciti, cronologia conservata; legacy smoke fermato e custodito | Non ripetere il recovery |
| Teatri tramite MCP | Asset 6609b245-86ed-4315-8ce0-73f2a8555bf3, profile 7984c39c-7396-4248-ab0a-f2efc390b49c v1, profiling SUCCEEDED | Riutilizzare asset/profile, non ricaricare |
| IAM/Onboarding distribuiti | [Accettazione 18 settembre](https://github.com/GioNob/ouf-semantic-registry/blob/e7bc5190f9e6afbbc4cf3c90d5d4970afbfad14b/evidence/history/OUF_R2F_IAM_PRODUCTION_ACCEPTANCE_2026-09-18.md) | Prova rappresentativa circoscritta già consegnata |
| Dichiarazione runtime corrente | [Ricevuta operatore](../evidence/replacement-runtime-declaration-target-20261010.json), exit 0 | Preparazione completata; nessuna nuova richiesta sudo per ripeterla |

Search Cinema via Gateway/MCP non era verificato nell'handoff del 1 ottobre. Restavano aperti minimizzazione, pagine/cursor/partial, byte/hash storage indipendenti, secondo file sovrapposto e clean-install. La ricerca odierna non ha trovato una prova successiva che chiuda questi criteri. Ciò non significa che la materializzazione sia da rifare, né certifica lo stato live corrente senza osservazione.

## Baseline live e main non sono intercambiabili

UDP installato secondo l'handoff: source 83249a897eb4add4289b5181b3299f48ea4c0f99, image sha256:5e048a859716d6674355e72238f03f899abd705a943ceadbdc5c8863d28f4e9f, schema Flyway34. Contiene il motore class-neutral governato, coverage/subset, review package, IAM e recovery. Non restaurare weighted legacy come default perché il nome di una migrazione storica contiene weighted. La regola di natura/tenant è un vincolo aggiuntivo, non un sostituto del motore concordato.

Confronto GitHub main c786dbae32ce77a6c4a858e3f85181e45020c480 → baseline live: diverged, 267 commit avanti e 10 indietro. Main manca V22–V34 e componenti governati. Le nuove 14 regressioni e dipendenze qualificate su main non certificano automaticamente il live avanzato e non autorizzano un downgrade.

Ingestion main 98a845b453362ec35a55fbebf9156204cc804e10 → branch R4a 163c167d09b8371ff7a62ce7068e9d485b6969b7: diverged, 22 avanti e 4 indietro; include ulteriori correzioni IAM, configurazione congelata e retry. Questo secondo pin è una baseline sorgente di riconciliazione, non una nuova attestazione del container corrente.

## Controllo eseguibile di continuità

[Inventario pinning delle migrazioni e dei componenti](file-loop-retained-source-baseline-20261010.json) e [checker](../scripts/check-source-continuity.py). Il checker usa inventari Git completi: conserva i blob delle migrazioni, richiede i componenti ereditati, rifiuta symlink/duplicati/versioni Flyway duplicate. I digest sono identità blob Git, non hash del JAR o firma di un artefatto.

Sette test verificano regressione di schema, migrazione riscritta, componente rimosso, inventario incompleto, symlink e versioni duplicate, oltre al caso additivo. Prova sull'inventario reale: baseline UDP PASS strutturale; main BLOCKED con 13 migrazioni e 6 componenti mancanti. Un PASS è solo continuità strutturale: codice presente può avere comportamento diverso; rimangono test di contratto, IAM, migrazione N/N+1, recovery, supply chain e accettazione.

Il controllo è un componente preparatorio dell'installer, non ancora cablato come autorità di apply. Non produce deploymentReady, autorizzazioni, grant o firma; non contatta il VPS.

## Prossima sequenza corretta

1. Costruire candidati dai branch che contengono i risultati live, trasferendo selettivamente le nuove correzioni di sicurezza e natura/tenant; testare il motore governato e la compatibilità Flyway34. Nessun wholesale merge o deploy di main.
2. Completare la confezione Semantic/MCP aggiornata e le closure di installazione, senza ereditare hash/attestazioni/trust del precedente candidato.
3. Integrare i collegamenti mancanti riusando Teatri e le decisioni THS; verificare la ricerca sui risultati già materializzati e poi sul nuovo percorso.
4. Automatizzare install/upgrade/resume/recovery e dimostrare host pulito; soltanto dopo consolidamento file passare alle API native PULL v2.3.

Le prove storiche non diventano liveness attuale o piena conformità PET. I claim R9 e le preparazioni consumate non vengono riarmati. Non si richiede all'operatore di ripetere i gate superati senza un cambiamento o drift concreto.
