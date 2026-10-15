# Prossimo passo — preparazione completa senza avvio, 15 ottobre 2026

## Risultati acquisiti

L'output VPS del15 ottobre identifica il difetto: Aliases della rete è null nel
frame storico/CLI e lista nell'API1.44; gli altri campi e la generazione coincidono.
Le cinque storie DB sono leggibili. La storia semantic coincide col prefisso
dei sorgenti candidati, marker SCHEMA incluso, con sola migrazione V10 pendente.
Una ricerca MCP fresca con l'account proprietario restituisce gli stessi8 Cinema
ACTIVE/revisione1 della baseline. Teatri non è dimostrato end-to-end.

La correzione è nella [PR31](https://github.com/GioNob/ouf-deploy/pull/31), distinta
dalla baseline PR29. Preserva la comparazione storica CLI completa, i binding API
completi per gli intenti e il marker semantic nella storia/readiness. Non modifica
i sei sorgenti applicativi o il pacchetto qualificato.

## Qualificazione esatta

- Sorgente eseguibile: `d8f23a433effbcb0ffb3581f658ce80f2963b595`.
- [CI](https://github.com/GioNob/ouf-deploy/actions/runs/38667398767),
  job116202361077: **193 test,25 suite,PASS,nessun test saltato**.
- Socket/CLI/API reali e storia semantic PostgreSQL reale; righe, storia,
  conteggio ruoli e ruolo applicativo non-superuser preservati nelle fixture.
- Test espliciti del flag nel root entry isolato e dell'uscita a review completa
  senza chiamare approvazione, emissione di autorità o avvio del processo.
- Verificatore HUMAN: run38667398803,PASS.
- [Evidenza strutturata](../evidence/retained-inspection-fix-qualification-20261015.json).
- Capsula: `ba1e4723e8797cb30f1461caf90af6e26eae9f2a617484e076e7a7617d0ca680`.
- Launcher Python: `52dfb7becbec183392633b581636740d07ecbddf3f1ed2564817efd0d218e207`.
- [Comando operatore](chatbot-file-cohort-prepare-vps-20261015.sh), SHA256
  `3167a62da12eb48e439b7e3f899ec6ac71a8745640949e9ca99bb6a8094dd046`.

La prima prova nativa falliva prima dell'esecuzione perché la fixture importava
un installer owner non necessario; la fixture è stata corretta e la prova reale
ha poi passato. Non è un errore scoperto eseguendo il nuovo preparatore sul VPS.

## Operazione richiesta

Il comando usa obbligatoriamente `--prepare-only`. Verifica e riusa l'archivio
esistente esatto; scarica i sorgenti della nuova capsula, effettua le normali
autenticazioni e compila tutti gli input privati e la review. Può richiedere sudo,
password amministrativa Keycloak nel relativo prompt e login browser con device
code. Le password non vanno inserite in chat e il programma non le registra.

Si ferma con `COMPLETE_PRIVATE_REVIEW_READY_NOT_STARTED`: riporta reviewPath e
reviewHash, runtimeAuthorityIssued=false e targetApplyAuthorized=false. Non chiede
di approvare il runtime e non avvia l'installazione. Sono attesi file privati di
staging/audit e sessioni di autenticazione; nessuna mutazione di servizio, DB o
risorsa IAM deriva da questa modalità. Non azzera budget o claim consumati.

La nuova capsula mantiene gli stage precedenti. Il percorso ZIP è quello già
usato nel launcher qualificato precedente; se assente, si ferma prima di sudo.
Il launcher non riscarica1,7GB quando l'archivio esplicito è presente e valido.

Questo è il tentativo di qualificare la preparazione completa con le vere
configurazioni del VPS, ancora non dimostrata dalla CI. Non è un rollout né una
promessa che ogni condizione del target sia già verificata. Un errore deve essere
riconciliato con l'inventario e con il punto di esecuzione; non ricominciare a
modificare microservizi senza una causa dimostrata.

## Stato dopo questa tranche

B02: diagnosi target chiusa. B01: correzione qualificata in CI, ancora da osservare
nella preparazione completa target. B03: review completa target attesa. B04: reale
upgrade/IAM/Gateway/THS non applicato. B05/B06: CSV Teatri e seconda sorgente ancora
da dimostrare. Il riferimento Cinema è fresco e preservato alla lettura del15.
Catalogo amministrativo IAM e ledger corrente non diventano verificati dal solo
successo della ricerca MCP; autorità e contabilità valide restano prerequisiti
della futura applicazione. La review prepare-only è un riferimento privato della
preparazione, non un'approvazione riutilizzabile oltre scadenze/cambiamenti: una
futura esecuzione richiederà sessione e verifiche correnti.
