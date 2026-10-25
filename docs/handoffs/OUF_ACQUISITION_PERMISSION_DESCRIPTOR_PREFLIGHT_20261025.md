# Acquisition READ: descriptor preflight required — 25 ottobre 2026

## Stato corrente e risultati effettivi

Questo documento aggiorna [l'handoff di installazione](OUF_ACQUISITION_INSTALLED_NEXT_GOVERNED_READS_20261025.md), da leggere integralmente per prove VPS, source/publication, due run, limiti, contatori e scope consumati. Installazione target riuscita rimane ACQUISITION_READ_PATH_INSTALLED_E2E_NOT_ACCEPTED; nessun APPLY/recupero/vecchio scope va ripetuto.

I tool ouf.ingestion.acquisition.read e urban.acquisition.read sono ORA disponibili anche in questa chat. Il precedente blocco di esposizione client è superato. Account esclusivo ouf-admin/link_6aafef96b4148191b767e9af7b756a07.

La REPLACE_ROLES completa con due ruoli temporanei, sei READ per ciascuna delle due run, originali conservati, è stata inviata UNA volta. Risposta400 ONB_BAD_REQUEST/AUTH_ROLE_CAPABILITY_INVALID; nessuna receipt/proposalId/approvalPath. NON esiste una review corrente da approvare. Non reinviare lo stesso payload o allargare admin per tentativi.

Una prima lettura Ingestion bounded(limit100) sulla runbb2e2af4-9c0a-49ea-8ad9-a947987c1472 è stata invocata: authorization denied/retryable=false. Nessun risultato di acquisizione; NON ripetuta. Nessuna lettura UDP o altra run ancora invocata. Vedi [evidenza minimizzata](../../evidence/acquisition-governed-read-admission-20261025.json).

## Causa dimostrata e limite

OufRoleCatalogue.compile controlla che OGNI permission del catalogo completo abbia un descrittore nel bundle ACTIVE e allowedActors contenga HUMAN. Il codice genera AUTH_ROLE_CAPABILITY_INVALID se almeno una permission non passa. L'errore non identifica quale: non inventare un sottoinsieme mancante dai soli grant. Le82 entry GRANTS precedenti sono configurazione, non catalogo né ALLOW effettivo.

Onboarding PermissionProposalApi supporta già viewCAPABILITIES nella stessa READ governata, senza filtri, con HUMAN-compatible ordinary descriptors. Il manifest MCP installato bd60ccd ha invece enumGRANTS/ROLES. Non inviare valori fuori schema come workaround. PRMCP#47 aveva già implementato il supporto a3547550: la ricostruzione l'ha perso. Ripristino su PRdraft#78/commit165696a9bb59ca60f752defe0b7851232f0dde9c, con rami union completi, filtri esclusi, SDK roundtrip e scope negato prima del Gateway. RunPR40220299700/job121250229342:3testPASS/0skip/log diretto letto. Sorgente/CI, NON nuova installazione o E2E; nessun comando di replacement MCP/Registry consegnato.

## Lettura amministrativa diagnostica, alternativa alla sostituzione MCP

Nuovo script scripts/read-acquisition-permission-descriptors-20261025.py usa SOLO API amministrative HUMAN ESISTENTI:
- normale device login del client esistente ouf-human-admin, scopeopenid+authorization.policy.admin, identitàouf-admin esatta;
- un GET ACTIVE, catalogo registrazioni paginato(limit200,max50pagine), secondo GET ACTIVE esatto;
- stampa soltanto6descrittori target e relativo owner/compatibilitàHUMAN, policyRef/hash, conteggi. Nessun grant o proprietà raw;
- token/device-secret/refresh restano in memoria; nessun filecredenziale, IAMadmin, scope edit, firma, Engine, SQL, registrazione o pubblicazione;
- una sola finestra600s, metadataIAM1GET, device+pollmax121POST(protocolli pending/slow_down), ownermax52GET,2MB/risposta e16MB cumulativi. Nessun retry GET automatico: profilo diagnostico one-pass finito per evitare loop di discovery/admission; errori permanenti/ignoti STOP;
- nuova claim diagnostica FISSA /home/oufadmin/ouf-acquisition-permission-descriptor-read-20261025, distinta da TUTTI i vecchi scope. mkdir esclusivo0700, progressoconteggi riservato/fsync PRIMA di ogni dispatch, state.json0600 atomico, token mai su disco. STOP/crash consuma claim; non rimuoverla/azzerarla/nuovodir per rilanciare.

14 test locali fixtureSINTETICHE PASS: policy drift, separazione registered/ACTIVE, descrittore mancante vsSERVICE, preservazione/occultamento grant e token, dinieghi senza retry, allowlist GET/endpoint, scadenza/conteggi riservati, OAuthpending/slowdown/denied, identitàerrata, TTY, claimconsumata e no replay. CI prima della consegna target ancora da acquisire. Questo NON è riapertura della sessione/budget storico, nuovo grant fonte o authorityruntime; solo login ordinario HUMAN per leggere metadati amministrativi. La conferma device è nel browser dell'owner, mai simulata dall'agente.

**Nessun comando target consegnato a questo checkpoint.** Dopo CI qualificata si prepara consegna pinned/checksum/copia codice root protetta/log trattenuti; non usare il file appena sviluppato sul VPS prima di quella consegna. Non avviare device login dal cloud o usare token dal connettore come bearer amministrativo.

## Dopo il risultato diagnostico

1. Distinguere descrittori registrati da descrittori nel bundle ACTIVE e attori/scopes. Se manca o confligge un descrittore: piano amministrativo ADDITIVO concreto con baseline/hashes; registrazione e pubblicazione ACTIVE governate HUMAN, preservando tutti i grant/ruoli/assegnazioni e semantiche. Non è REPLACE_ROLES e non è nuovo budget fonte. Nessuna pubblicazione automatica dall'agente.
2. Solo dopo preflight positivo, nuove ROLES/GRANTS e una proposta temporanea per le sole due run del vecchio handoff. Risolvere NUOVA finestra concreta, non riciclare18:05–20:05 della proposta rifiutata. Un solo link THS corrente, decisione HUMAN e proposal.read PUBLISHED verificata.
3. Solo dopo autorità effettiva osservata si può riprendere la lettura precedentemente negata come continuazione governata a policy cambiata, senza trattarla come retry automatico. Quattro READ bounded/source/run e cursori owner; nessuna terza acquisizione. Correlare snapshot/publication/CSV/ACK/watermark,13ID e provenance/criterio20proprietà.11–19valori visibili perTeatro resta da spiegare, unione20 non basta da sola.
4. E2E/G4/F5/F6 OPEN, tecnico8/8 funzionale4/6; Supervisor dopo E2E. Nessun merge/release acceptance. No replay/reset/reinstall/restart Registry/nuove attivazioni.

Fonti primarie: Onboarding main tree84828f74ac586bae09a78f0fb197b75b1a3d98d1, OufRoleCatalogue/PermissionProposalService/PermissionProposalApi/AuthorizationAdminApi/AuthorizationAdminService; MCPbd60ccd manifest e PR47. Le letture viaAPI amministrativa richiedono direttamente HUMAN; i token non vengono passati viaMCP.
