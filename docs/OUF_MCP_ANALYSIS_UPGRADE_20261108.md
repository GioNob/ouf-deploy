# MCP: candidato analisi persistente e migrazione14

8 novembre 2026. **Installazione qualificata, esecuzione VPS attesa.** Il preflight target è riuscito; Semantic V12 è già pronto. Questo intervento aggiorna soltanto MCP.

## Base concreta e risultato richiesto

La [ricevuta delle20:09 CET](../evidence/mcp-analysis-preflight-operator-20261108.json) identifica il MCP corrente e il suo binario, database OID21560 con checksum1–13 coincidenti, ruolo applicativo non superuser con permessi ordinari14, cinque file montati nel processo e coerenti con il file host. I metadata del permesso storico risultano scaduti. Non rinnovare quel permesso e non azzerare budget.

Il [pacchetto originale](../evidence/mcp-analysis-candidate-package-20261108.json) è artifact13593930449 del run42420569963, source candidato907ace32 e publisher CI e2a474ea con albero identico. ZIP e tutti i payload sono verificati, nessuna nuova build. Il binario candidato ha SHA256 `11f9bb088b6f86d2f82c945728cb904c46d8c43a866b4df4cec2a6531e10605a`.

## Operazione

1. Rileggere l'esatto frame corrente e i file pubblici di reprocessing, confrontare il binario osservato e verificare readiness, storia DB e permessi. Verificare ZIP/immagine prima di importare.
2. Fermare MCP; staccare e conservare il vecchio container con il suffisso `-before-analysis-20261108`, usando la transizione MAC qualificata. Creare il nuovo MCP con ENV e mount esistenti, stesso IP/MAC/alias e nuova immagine. Avvio iniziale dietro il gate; l'applicazione non parte ancora.
3. Verificare binario e file montati. Eseguire il comando ordinario `/usr/local/bin/ouf-mcp migrate` come UID10005 con la configurazione già presente nel container. Richiedere esattamente la14 aggiunta, storia1–13 e relativi timestamp invariati, tabelle analisi vuote. Non usare il migratore privilegiato12→13.
4. Avviare il server con lo stesso picker, credenziali e permesso storico. Il normale avvio può richiedere token, leggere la policy e registrare il nuovo manifest nel DB. Verificare HTTP204, processo MCP, mount/endpoint, file pubblici invariati e storia DB finale. Vecchio MCP fermo, nessun rollback automatico.

La sostituzione interrompe temporaneamente MCP. Non modifica Onboarding, UDP, SeaweedFS, Semantic o route Gateway. Il nuovo pacchetto mantiene i sei strumenti analisi/discovery INACTIVE: l'installazione non prova né attiva la discovery. Nessun budget o permesso storico viene rinnovato.

## Comando corrente

Scarica anche l'archivio originale pubblico verificato, senza richiedere `gh`.

```bash
(
  set -eu
  ouf_install=$(mktemp /tmp/ouf-mcp-install.XXXXXX)
  trap 'rm -f -- "$ouf_install"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/e330ea6805a07f6df4f7eec7eb3ca28b5389faf4/scripts/install-mcp-analysis-20261108.sh' \
    -o "$ouf_install"
  printf '%s  %s\n' \
    '04ee70a8e46167f2dba1cf2fe3e7c51995370aa8351ee22986a8be85fa2a6ae2' \
    "$ouf_install" | sha256sum -c -
  bash "$ouf_install"
)
```

Esito atteso: `MCP_ANALYSIS_V14_READY`. Restituire soltanto il JSON finale. In caso HELD non rilanciare: journal `/var/lib/ouf-storage-migration/mcp-analysis-upgrade-20261108` conservato, eventuale migrazione già inviata e stato dei container da riconciliare. Il controller raccoglie nello stesso risultato le categorie pubblicabili dell'eventuale errore di avvio; log grezzi e configurazioni restano privati.

## Prove e limiti

[CI42514478247](https://github.com/GioNob/ouf-deploy/actions/runs/42514478247), classic job128834381676 e containerd job128834381576, log letti: ogni backend passa quattro test mirati, sei negativi MAC, due prove native e una fixture crittograficamente firmata/scaduta; zero skip. Docker29.8.1 esatto, PostgreSQL17, archivio MCP originale UID10005. Preservati storia migrazioni inclusi timestamp e una sessione sintetica; file reprocessing invariati; client credentials e policy su TLS con CA fixture, readiness204. MAC legacy presente inizialmente su entrambi i profili, assente dopo STOP/DETACH, endpoint conservato sul sostituto.

Il predecessore CI è il medesimo candidato avviato sullo schema13: non è il vecchio binario VPS. Il target viene vincolato al digest realmente osservato; la qualifica riguarda le primitive di sostituzione, migrazione e avvio del candidato. Identità, dati, firme e servizi IAM sono sintetici. Non attesta grant reali, discovery provider, analisi Teatri o E2E. Il primo run42514286601 ha rilevato un path picker errato nella fixture, corretto al percorso contrattuale senza cambiare l'applicazione o il controller. [Qualifica strutturata](../evidence/mcp-analysis-upgrade-qualification-20261108.json).

Dopo successo: completare gli altri candidati1024 preservando i binding SeaweedFS; configurare provider/delega/grant e attivare gli strumenti; usare il profilo Teatri conservato per le proprietà delle colonne, poi THS→Ingestion→UDP e ripetizione.
