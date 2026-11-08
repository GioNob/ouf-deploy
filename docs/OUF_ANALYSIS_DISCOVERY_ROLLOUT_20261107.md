# Analisi dinamica e discovery: preparazione del rilascio

**Stato dell'8 novembre, 19:59 CET:** Gateway applicato; candidato originale Semantic c2dae77b installato con V11/V12 migrate e validate, chiave corretta e readiness riuscita. [Ricevuta](../evidence/semantic-discovery-key-repaired-operator-20261108.json). Provider/worker restano disabilitati. MCP PR83: preflight delle20:09 CET positivo, [installazione qualificata](OUF_MCP_ANALYSIS_UPGRADE_20261108.md) ancora da eseguire. Non ripetere migratore, correzione Semantic o delta Gateway.

7 novembre 2026, Europe/Rome. Il codice del candidato MCP PR83 è qualificato; non è installato e i sei nuovi strumenti sono INACTIVE. Nessuna nuova discovery o associazione OntoPiA è stata eseguita. F1 rimane acquisito, F2–F6 aperti.

## Correzione della sequenza di rilascio

Il source-lock identifica un candidato, non l'applicazione installata. La lettura del pacchetto ha chiarito che serve la sostituzione; viene scelto c2dae77b, che include anche la successiva correzione delle credenziali.

| Componente | Evidenza sorgente verificata | Conseguenza operativa |
| --- | --- | --- |
| Registry | Il source-lock conserva `c2dae77b42f1811b704465f6ab813c91d808ade4`, discendente di tre commit dell'applicazione discovery `4f8fb581916075a539bda4428be7bd8af073a569`. Comprende la correzione di custodia/rotazione delle credenziali del provider. | Installazione c2dae77b e V11/V12 completata; readiness acquisita. Worker/provider restano disabilitati fino a binding/delega/trasporto/grant verificati. |
| Gateway | Il source-lock conserva `81fdf7a5f9f3ef02ed930a1db911d34cab1a9415`; PR86 è `560fbf6e769c7639a0bc0ddb09380811a4e324e4`. Le storie divergono: candidato avanti 71, indietro 33 commit; base comune `dbdc24b5481dc9473b21b360ab1142c9aef0194b`. Il ramo trattenuto comprende l'owner Java di monitoraggio e i suoi collector. | Non sostituire tutto il Gateway con il ramo candidato. Riconciliare i soli contratti, plugin, route e limiti necessari, conservando l'owner operativo corrente. Le otto modifiche sono applicate e verificate l'8 novembre; owner invariato. |
| MCP | PR83 `907ace32100d44a0fcf1fcbda5d713ee7bd8fd94`: discovery e `source.analysis.plan/read/step` composti; 23 workflow riusciti. | Preparare aggiornamento dell'immagine e migrazione 014 sullo schema effettivamente presente. Non usare il vecchio helper privilegiato 12→13 come migratore generico e non distribuire PR82 da solo. |
| Onboarding / UDP | Le ricevute di switch indicano sostituti SeaweedFS, distinta configurazione TLS e vecchi writer MinIO spenti. | Il punto di partenza è il sostituto corrente, non il container originario del piano. Conservare endpoint, reti, truststore, credenziali e asset/profilo Teatri. |

Fonti: [source-lock corrente](../releases/m2-current-core-source-lock-20261101.json), [delta Registry](https://github.com/GioNob/ouf-semantic-registry/compare/4f8fb581916075a539bda4428be7bd8af073a569...c2dae77b42f1811b704465f6ab813c91d808ade4), [delta Gateway](https://github.com/GioNob/ouf-api-gateway/compare/81fdf7a5f9f3ef02ed930a1db911d34cab1a9415...560fbf6e769c7639a0bc0ddb09380811a4e324e4). Un source-lock non prova da solo la configurazione attuale del processo.

## Inventario acquisito — comando storico, non ripetere

Eseguito l'8 novembre alle 09:11 CET: [ricevuta](../evidence/analysis-discovery-runtime-operator-20261108.json). Il nuovo passo è la [lettura mirata delle dipendenze](OUF_DISCOVERY_CONTRACT_READ_20261108.md). Il blocco seguente resta soltanto come provenienza. L'assistente non dispone qui di una sessione sul VPS. Il comando scarica una revisione immutabile, verifica SHA256 ed esegue il lettore in modalità Python isolata.

```bash
(
  set -eu
  ouf_read=$(mktemp /tmp/ouf-discovery-read.XXXXXX)
  trap 'rm -f "$ouf_read"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/7bdf0e107b534e9db90aabe5e0388c627b7150b8/scripts/read-analysis-discovery-runtime-20261107.py' \
    -o "$ouf_read"
  printf '%s  %s\n' \
    'ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4' \
    "$ouf_read" | sha256sum -c -
  sudo python3 -I -B "$ouf_read"
)
```

Il lettore verifica piano e ricevute già conservate, poi legge due volte le identità correnti di MCP, Onboarding, Semantic, Gateway owner, APISIX, Ingestion e UDP, oltre allo stato dei due vecchi writer. Usa soltanto GET al socket Docker. Nessun avvio/stop, exec nel container, query SQL, chiamata S3, richiesta token, richiesta business o chiamata al provider. Termina entro il proprio limite di 55 secondi oppure restituisce READ_INCOMPLETE.

Conserva le inspect complete, potenzialmente contenenti segreti nell'ambiente, soltanto in una nuova directory root 0700 con file 0600. Questi file privati non vanno incollati. Il JSON pubblico mostra confronti, dichiarazioni selezionate e forma MAC, senza valori di credenziali, argomenti grezzi o ambiente completo. Non modifica il piano, le ricevute, le impronte o i servizi.

Le dichiarazioni ENV/JSON/argomenti sono riportate con la propria origine, senza inventare la precedenza o applicare default del sorgente. Non equivalgono alla configurazione Spring effettiva. `READ_COMPLETE` significa inventario completato: non certifica readiness, route, permessi, TLS o autorizzazione a distribuire. Un vecchio writer trovato acceso è segnalato esplicitamente; il lettore non lo ferma.

## Come l'esito decide il passo successivo

1. Immagine Registry coincidente e dichiarazioni provider/worker presenti: mantenere la versione; verificare il percorso governato dopo composizione/attivazione delle capacità. Se dichiarazioni assenti, false o discordanti, preparare la correzione circoscritta sulla configurazione attuale, senza presumere che il provider sia attivo.
2. Onboarding/UDP ancora sui binding attesi: usare i sostituti come base del futuro aggiornamento. Una differenza MAC resta visibile con presenza/tipo e corrispondenza agli endpoint. Non diventa una deroga al guard; la qualificazione del lifecycle del futuro controller resta distinta da questo lettore.
3. Immagini o configurazioni diverse dalle fonti trattenute: riconciliare il componente specifico prima di sostituirlo. Una variazione durante la lettura produce READ_INCOMPLETE.
4. Preparare il delta Gateway e il rilascio MCP/Onboarding sul quadro corrente, verificando schema DB, route e grant pertinenti. Sono verifiche ancora mancanti, non risultati prodotti dal lettore.
5. Prima discovery reale PROPERTY/RELATIONSHIP sul profilo Teatri conservato; verificare i candidati, motivare il mapping e gli irrisolti, poi review THS e Ingestion→UDP→grafo. Ingestion/UDP a 1024 colonne restano candidati da distribuire coerentemente prima del caso ampio.

## Ricerca dei nomi delle colonne

Il `SchemaGovProvider` del sorgente trattenuto costruisce una ricerca lessicale `CONTAINS` su label/URI. Non interpreta liberamente una frase in italiano come ricerca semantica. Usare intenti lessicali mirati; il contesto dell'oggetto serve all'analista per scegliere e verificare proprietà, definizione, dominio e range. Una risposta vuota non dimostra l'assenza del concetto. Nessun URI è inventato o adottato automaticamente. [Sorgente verificato](https://github.com/GioNob/ouf-semantic-registry/blob/c2dae77b42f1811b704465f6ab813c91d808ade4/src/main/java/it/comune/trieste/ouf/semantic/adapters/discovery/SchemaGovProvider.java).

## Qualificazione e limiti

Dieci prove locali del lettore riuscite: ricevute e impronte, sostituti SeaweedFS, tutte le forme MAC, conflitti nelle dichiarazioni, redazione dei segreti, writer originario acceso, riavvio durante lettura, hash errato, custodia dei file privati e errori senza contenuto sensibile. Usano fixture e Docker inspect simulato: non sono una prova del VPS o del ciclo nativo di sostituzione container. Le stesse dieci prove sono riuscite nella [CI 42422417213](https://github.com/GioNob/ouf-deploy/actions/runs/42422417213), job 128553489638; log letti. Il risultato di questo inventario target è acquisito nella ricevuta dell'8 novembre.
