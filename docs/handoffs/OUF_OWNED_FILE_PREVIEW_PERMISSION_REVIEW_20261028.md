# OUF — Anteprima dei file propri: review HUMAN pronta

28 ottobre2026, Europe/Rome. [Intent autorizzato](../../evidence/owned-managed-file-preview-permission-authorized-intent-20261028.json), [receipt e verifica](../../evidence/owned-managed-file-preview-permission-proposal-20261028.json).

## Proposta corrente

- ID `ad738511-24cd-418a-b5b2-0cfc46be59fe`, revision0, stato **PENDING**, finalPolicyRef null.
- [Review THS esclusivamente utente](https://api.ouf-lab.it/trusted-human/authorization/?proposal=ad738511-24cd-418a-b5b2-0cfc46be59fe).
- Scadenza **28ottobre2026,23:49:49 Europe/Rome** (`2026-10-28T22:49:49.117724Z`).
- Una sola creazione; una lettura indipendente della stessa proposta caller-owned restituisce la stessa receipt. Nessuna pubblicazione effettuata dall'agent.

L'utente ha risposto “Autorizzo” alla domanda esplicita sul mandato stabile di sola anteprima dei file propri per ouf-admin, fino15settembre2036 e con separata reviewTHS. Questo nuovo input risolve la mancanza di autorizzazione esplicita del precedente rifiuto automatico, che resta documentato nello storico. Non è consenso alla pubblicazione da parte dell'agent.

## Effetto concreto

Un nuovo ruolo `owned-managed-file-preview-v1` con la sola capability `ouf.managed-source.preview`, resourceType capability, e una nuova assegnazione nominale `owned-managed-file-preview-v1-ouf-admin` al subject `b93d8cf6-cd14-4ee6-91d7-84cd76c4f500`. validFrom `2026-10-28T22:34:26Z`, validUntil `2036-09-15T07:13:50.968730Z`, entro la scadenza dell'attuale assegnazione admin.

Lettura di metadati/anteprime dei file di cui il caller è proprietario; controlli tenant+subject e redazione restano nell'owner. Nessuna nuova capacità upload, profiling, budget, resume, onboarding, acquisizione o attivazione. Nessuna classificazioneCSV modificata. Tutti gli8ruoli e le12assegnazioni preesistenti sono preservati esattamente; proposta9ruoli/13assegnazioni. Base osservata policy58/hashsha256:e8c3401e1d3209f60af55c36bae25d8a1089d822dc129afbef6ae3a13cce6bfe.

ROLES fresca è stata letta e l'input ricostruito da quel catalogo, non da un vecchio snapshot. [Intent salvato prima dispatch](https://github.com/GioNob/ouf-deploy/commit/5aea3da27812e135ff29878bfb2e4978fb13fd75).

## Dopo la decisione utente

1. L'utente apre la review, esamina scope/durata/preservazione e decide nella propria sessioneTHS. L'agent non apre la review.
2. Con accountouf-admin esplicito rileggere soltanto questo proposalId. PUBLISHED e finalPolicyRef devono arrivare dall'owner; non assumere il numero della nuova policy.
3. Se PENDING,scaduta,rifiutata o esito ambiguo, conservare e riconciliare lo stessoID. Nessun duplicato o rinnovo automatico.
4. Dopo PUBLISHED leggere via source.file.preview il profilo già esistente `f3061699-4fde-4085-89c8-bc8703f65686` dell'asset `9c502da5-b5d8-405e-b3f5-60eb31ecb513`; non avviare nuovo profiling o recupero.
5. Verificare tutti i campi effettivamente esposti, conteggio61righe/10colonne, dialetto e integrità nei limiti delle evidenzeowner; poi proporre mapping/identità/tipi/label/semantica fissata secondo miniPET M2v1.2, senza nuova acquisizione implicita.

## Stato conservato

Profiling Farmacie acquisito: stesso job `677480c8-3d10-44fd-9dad-f72ddeed20a4` SUCCEEDED da letturaMCP, errorCode null; THS osservata6tentativi cumulativi,1su3 e sessioneCOMPLETED. [Handoff del successo](OUF_FARMACIE_PROFILE_SUCCEEDED_20261028.md). Il campoUNCLASSIFIED dopo successo deriva da fallback della proiezione ed è un difettoUX da correggere, non prova di un nuovo errore.

Anteprima dei contenuti ancora non letta; nessuna prova di61righe materializzateUDP. M1/G4 restano acquisiti;M2/G5/G6/G7 e accettazione finale aperti. Tutti i controller/authority consumati restano non riutilizzabili. Nessun nuovo budget/resume/upload/job,terzaacquisizioneTeatri,Registryrestart/reinstall,merge,releaseacceptance,subagenti o automazioni.
