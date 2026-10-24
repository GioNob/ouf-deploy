# Registry 502: comando mirato per il binding della credenziale

Il reader è qualificato per una sola nuova osservazione dei metadati già identificati. Non avvia il Registry o un token-worker. Il dato mancante è il legame dimostrato fra mount della credenziale Registry, owner storico e suoi predecessori: la discovery precedente non aveva selezionato tale catena.

## Artefatti e verifica

- Sorgente immutabile: `f8afcf2a78f76f3a201162547ad575c8a02896c7`.
- Reader: `scripts/read-registry-bound-owner-lineage-20261023.py`.
- SHA256: `24739440479a105a211986ed8c2a5c936b76779b6d176aa22662c9fe77168fff`.
- CI [39916642392](https://github.com/GioNob/ouf-deploy/actions/runs/39916642392), job 120291527605: **15 PASS, zero skip**, con file reali protetti in una directory root su runner Ubuntu disposable.
- Tutti i sette file pubblicati nel commit sono stati riletti e confrontati esattamente. Test locali: 15 PASS, zero skip. Revisione statica indipendente completata dopo la correzione che rifiuta una catena senza il primo antenato contabilizzato.
- Wrapper `releases/semantic-registry-bound-lineage-20261023.sh`: sintassi Bash verificata e prova negativa dell'hash superata. La parte privilegiata esegue gli stessi byte verificati in memoria; non riapre il file dopo la verifica.
- Receipt: `evidence/semantic-registry-bound-owner-lineage-ci-20261023.json`.

La qualificazione riguarda il reader su fixture e la sua custodia, non i metadati reali del VPS, un owner corrente o l'intero recupero JVM/OCI/IAM/DB. Nessuna esecuzione target è stata effettuata da questa sessione.

## Esecuzione

Usare una sola volta il contenuto del wrapper nel terminale già stabilito `oufadmin@v2202609421511523101`. Il download pubblico è fissato a commit e hash; il reader gira con Python isolato e senza bytecode/site. Il wrapper conserva sorgente e solo output pubblico in una nuova directory privata sotto HOME. Il reader non modifica il target.

I soli accessi del reader sono tre metadati ancorati da hash, quattro metadati per ciascuno dei 18 candidati noti e due letture dell'identità del boot. Limiti: 75 file, 150 letture comprensive del ricontrollo completo, 32 MiB e 15 secondi massimi. Nessuna scansione, credenziale, OAuth, Engine, SQL, lock o processo figlio.

Un esito `HISTORICAL_CREDENTIAL_LINEAGE_RECONCILED` riporta ordinale dell'anchor storico, hash della relazione mount/output e grafo dei predecessori con i rispettivi contatori. Il terminale del grafo non diventa l'owner corrente, non dimostra esclusività e non approva un nuovo budget. L'accounting legacy sconosciuto resta sconosciuto e altri owner fuori dal perimetro restano possibili.

Un esito `STOP_RECONCILE` conserva un motivo chiuso e i contatori di lettura. Conservare il log e valutare quel motivo prima di un nuovo passo; non rilanciare automaticamente, non modificare metadati per far passare i controlli, non scegliere un altro candidato per data o contatore.

## Passo successivo

Usare la receipt per comporre un recupero distinto nel boot corrente: gate nuovo con Java bloccata, owner corrente vincolato ai conti conservati, completa ammissione nativa e policy fresca, poi rilascio della medesima generazione e GET originale Ingestion SERVICE. Nessun vecchio claim, segnale, boot o attestazione deve essere adottato come corrente. Il percorso eseguibile completo deve essere qualificato prima di nuove richieste HUMAN/token/window.

Il 502 resta aperto fino al successo della richiesta originale; Supervisor e test E2E completi della piattaforma restano successivi. Questo comando non concede autorità di riparazione e non cambia patch12/12, fasi tecniche8/8, milestone4/6, G3OPEN o releaseAcceptancefalse.
