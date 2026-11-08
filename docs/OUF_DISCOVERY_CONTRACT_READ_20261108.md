# Discovery e budget dinamico: dipendenze da verificare prima del rilascio

8 novembre 2026, Europe/Rome. [Ricevuta operatore delle 09:11:33 CET](../evidence/analysis-discovery-runtime-operator-20261108.json). Nessun rilascio applicativo o nuova discovery è stato eseguito.

## Risultato acquisito

| Componente | Evidenza corrente | Conseguenza |
| --- | --- | --- |
| Onboarding e UDP | Immagini attese, rete e dichiarazioni endpoint/bucket SeaweedFS conservate; Config, HostConfig, mount e NetworkSettings uguali alla cattura dei sostituti. Vecchi writer spenti in entrambe le letture. | Conservare i sostituti e il profilo Teatri; nessuna nuova prova isolata S3 o nuovo upload necessario per questa diagnosi. |
| Registry | Immagine trattenuta `b61bc39c…`, sorgente associato `c2dae77b…` già comprensivo della discovery. `OUF_SCHEMA_GOV_ENABLED=false` e `OUF_DISCOVERY_WORKER_ENABLED=false` nell'ambiente; autenticazione del provider dichiarata true. | È un blocco di configurazione dichiarata, non la prova di un difetto SeaweedFS. Non sostituire Registry col vecchio candidato PR41. Non accendere il worker prima di conoscere eventuale backlog e dipendenze. |
| MCP | Vecchia immagine `a5218012…`, configurazione trattenuta. | Il candidato PR83 con analisi dinamica e discovery resta da installare; schema DB e attivazione/grant vanno verificati. |
| MAC | Nei sostituti Onboarding/UDP nessun delta attuale. Negli altri cinque servizi Config.MacAddress passa da ABSENT nella cattura a STRING corrente, unicast nonzero e coincidente con un endpoint. | Non applicare la regola opposta del vecchio container dopo detach; nessuna normalizzazione o riscrittura delle impronte. Il lettore successivo usa i frame correnti della nuova ricevuta. |

La ricevuta non misura readiness, non legge route/permessi e non prova la configurazione Spring effettiva. L'associazione immagine/sorgente deriva dalle fonti trattenute; l'inventario conferma l'immagine corrente, non ricostruisce nuovamente l'artefatto.

## Passo operatore corrente

L'inventario generale è acquisito e non va ripetuto. Il comando seguente legge soltanto le dipendenze specifiche mancanti:

1. Un GET Admin delle route APISIX, usando la credenziale della configurazione montata. Mostra presenza esatta o per prefisso delle route discovery/provider e i limiti delle route preview/profile/create/review-prepare richieste dal percorso a 1024 colonne; non confonde presenza con autorizzazione effettiva.
2. Metadati della credenziale provider nel filesystem visto da Semantic: mount, presenza, proprietario, gruppo e modalità. Non ne legge il contenuto e non chiede token.
3. Due sessioni PostgreSQL con i ruoli applicativi dichiarati e transazioni `READ ONLY`: storia delle migrazioni MCP e Semantic; conteggi discovery per stato/recovery_state. Nessun identificativo o intento delle richieste viene selezionato. Nessuna migrazione, grant o chiamata a funzioni di claim. `PENDING` include anche richieste in pausa/esaurite: il conteggio non prova l'eseguibilità.

Il database MCP viene confrontato con i checksum esatti delle migrazioni 1–14 del candidato `907ace32100d44a0fcf1fcbda5d713ee7bd8fd94`; eventuali versioni mancanti sono riportate, mai applicate. Il lettore rifiuta DSN diretti verso un host diverso dal PostgreSQL trattenuto e override di identità nella query URL. Non inoltra password del DSN al processo psql; usa il canale locale già disponibile nel container PostgreSQL, senza modificare l'autenticazione.

```bash
(
  set -eu
  ouf_contract=$(mktemp -d /tmp/ouf-discovery-contract.XXXXXX)
  trap 'rm -rf -- "$ouf_contract"' EXIT
  ouf_source='https://raw.githubusercontent.com/GioNob/ouf-deploy/870b5e0cab438de2ed33936c97da28a6930da263/scripts'
  for ouf_file in read-analysis-discovery-runtime-20261107.py read-discovery-contract-20261108.py; do
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
      --connect-timeout 10 --max-time 30 \
      "$ouf_source/$ouf_file" -o "$ouf_contract/$ouf_file"
  done
  (
    cd "$ouf_contract"
    sha256sum -c - <<'SHA256'
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
SHA256
  )
  sudo python3 -I -B "$ouf_contract/read-discovery-contract-20261108.py"
)
```

Restituire soltanto il JSON pubblico. Route complete ed errori PostgreSQL grezzi restano in una nuova directory privata root 0700/file 0600; possono contenere dati sensibili e non vanno incollati. Nessun avvio/stop, modifica di route/configurazione/permessi, richiesta business, token, provider o S3. Il vecchio lettore viene importato soltanto per le funzioni già qualificate; non viene rieseguito il suo inventario generale.

Un cambiamento nei frame correnti di MCP/Semantic/APISIX interrompe prima delle letture credenziale/DB. Una lettura incompleta di un componente non cancella i risultati degli altri: `READ_PARTIAL` resta da interpretare, senza retry automatico. Il confronto finale controlla che i runtime osservati non siano cambiati. La lettura non costituisce autorizzazione automatica a distribuire o riattivare backlog.

## Decisioni dopo il JSON

- Route assenti o ancora incompatibili: comporre il delta Gateway necessario sullo stato letto, mantenendo l'owner operativo. Nessuna sostituzione integrale del ramo divergente.
- Credenziale dichiarata ma non montata o non coincidente: correggere il binding sul Registry corrente; nessuna nuova credenziale dedotta o generata da questo lettore.
- Migrazioni MCP esatte fino alla 12/13: preparare il percorso di migrazione pertinente per PR83, preservando il confine della primitiva privilegiata 12→13 e applicando separatamente la 14. Un checksum diverso richiede riconciliazione, non sovrascrittura della storia.
- Discovery preesistenti pendenti/in pausa: conservarle e determinarne il trattamento prima di avviare il worker; non azzerare contatori o rilanciare comandi.

I grant correnti e la configurazione effettiva JVM restano non provati da questo lettore. Dopo rilascio coerente e attivazione governata: prima discovery di proprietà sul profilo Teatri conservato, mapping motivato, review THS, Ingestion→UDP→grafo e ripetizione E2E. F1 resta acquisito, F2–F6 aperti.

## Prove

Nove prove locali riuscite; la prova PostgreSQL è eseguita in CI. [Run 42463068093](https://github.com/GioNob/ouf-deploy/actions/runs/42463068093), job `128676349535`: dieci prove riuscite, zero skip, log letti. PostgreSQL 17 reale isolato con utenti fixture non amministrativi; verificati checksum/conteggi e rifiuto di una scrittura in transazione READ ONLY. Route e vista del mount sono fixture: non sono prove del VPS, del provider o del lifecycle di sostituzione. Il risultato target di questo secondo lettore è ancora atteso.
