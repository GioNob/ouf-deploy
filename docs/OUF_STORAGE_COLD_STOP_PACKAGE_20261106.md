# Fermo e prima cattura dei dati di test OUF

**Profilo: NONPRODUCTION_TEST_STATE_PRESERVATION.** Giovanni accetta indisponibilità senza un orario obbligato di rientro. Conservare lo stato corrente per il successivo recupero; non dichiarare drain o consistenza applicativa prima delle prove. Il backup rimane necessario all'esercitazione e i segreti restano privati.

La cifratura VPS→Windows è conclusa e non va ripetuta. [Ricevuta](../evidence/storage-backup-cross-platform-operator-20261106.json). Stato operativo: **pacchetto da approvare, nessun fermo/cattura target eseguito dall'agente**.

## Perimetro e limiti

| Elemento | Perimetro |
|---|---|
| Piano sorgente | SHA256 1c0bb62ceba85f748e43465d36f016b4c575c586d40390dc92095a1dbc71bd0f |
| Scadenza | 7 novembre 2026,20:53:39 Europe/Rome; nessun rinnovo automatico |
| Oggetto | 14 servizi,34 fonti,5 directory runtime; intero PostgreSQL condiviso,MinIO,configurazioni,immagini e filesystem dei container |
| Policy | 35 cambi a restart=no:13 servizi selezionati e22condividenti già fermi. Originali registrati; altri81condividenti già no e28esterni fermi non modificati |
| Segnali | 14 invii singoli: TERM ai servizi; INT PostgreSQL se configurato nel piano. Nessun SIGKILL container |
| Fermo | Un tentativo,1200s,256comandiCLI,64MiB metadati,120s massimi per gruppo |
| Cattura | Un tentativo,3600s,256comandiCLI,64GiB prodotti incluse copie intermedie; non è una stima della dimensione finale |
| Fine | Servizi restano fermi; nessun avvio dei condividenti,riapertura,deploySeaweedFS,grant o cancellazione |
| Manutenzione esclusiva | L'operatore sospende altri deploy/ricreatori e strumenti amministrativi che possano scrivere o avviare i servizi durante fermo/cattura |

Sono richiesti almeno4800s residui nel piano all'avvio del fermo. Il driver verifica l'inventario corrente e le identità prima delle mutazioni; alla prima discordanza o esito incerto conserva tutto e termina HELD. Non rilanciare comandi,non eliminare aree/claim o cambiare il budget. Un fermo parziale resta inHOLD; non riavviare per ripristinare la disponibilità.

restart=no non blocca amministratori o ricreatori esterni. L'esclusività è dichiarata dall'operatore,non autenticata dal programma. I controlli osservano identità,stato,eventi e integrità dei file,non costituiscono un fence distribuito. decision-reference è provenienza,non tokenHUMAN/THS. Questo pacchetto di manutenzione locale non registra né concede capabilities OUF.

## Ordine del fermo

Dopo tutte le35policy verificate:
1. caddy,apisix,mcp,gateway-owner;
2. onboarding,ingestion,udp,semantic,ingestion-evidence-read,udp-evidence-read;
3. keycloak;
4. postgres,minio;
5. etcd.

Ogni gruppo deve risultare fermo prima del successivo. PostgreSQL,MinIO,etcd richiedono uscita0; gli altri0/143,conPID0,senzaOOM,errori,paused/restarting. Exit143 prova cessazione fisica,non drain. Il lavoro applicativo interrotto rimane nel backup e dovrà essere riconciliato prima di riaprire.

## Correzione v4 e catena delle prove

Docker può restituire i medesimi mount in ordine diverso. Tre tentativi di qualifica iniziali hanno evidenziato falsi drift prima di ogni mutazione; il terzo documenta la sola permutazione degli array,senza cambio di campi oStartedAt. [Ricevuta](../evidence/storage-test-cold-stop-mount-order-failure-20261106.json).

v4 mantiene il programma v3 esatto come dipendenza e ordina soltanto gli oggetti Mounts per il confronto. Ogni campo,duplicato,fonte,flagRW e generazione resta vincolato. Il piano v4 viene derivato dai byte privati già acquisiti: conserva createdEpoch,validUntilEpoch,budget,fonti e prove runtime. Piano/programma v3 rimangono intatti. La derivazione e il fermo hanno nuove aree esclusive; una capture v3 preesistente blocca v4. Nessun tentativo consumato viene resettato.

[Qualifica e fallimenti conservati](../evidence/storage-test-cold-stop-qualified-20261106.json). Il driver di fermo è provato con14PID1 sintetici e2condividenti Docker,non con14applicativi OUF reali. Cattura/restore sono provati con PostgreSQL+MinIO reali in fixture: non è il ripristino del VPS né su un secondo host. Installer revisionato staticamente e hash confrontati,non dichiarato eseguito sul VPS.

## Installazione preparatoria

Programmi disponibili al commit d57e127ddf244f6bd9218abb7f60c67b418a20b4:

| File installato | Byte | SHA256 |
|---|---:|---|
| /var/lib/ouf-storage-cold-backup-v4.py |4095|8786a65a8bcde2706a3dc05a96a60ad04682cab6baa697e286b2dc525b17b3b9|
| /var/lib/ouf-storage-test-cold-stop-20261106.py |15186|b3b28645ed377459fbe577fe4eb5eb8fb351a0e2c0e3f7067d5745f6f83ad2b5|
| /var/lib/ouf-storage-stop-planner-20261106.py |7161|121f998eabb7f09b00d6e2cc22bbeaa49c78cec3b535f02c46e57e6eb9c71e68|

scripts/prepare-storage-test-cold-stop.py installa solo questi tre file root0600,senza Docker o letture applicative. Rifiuta file esistenti differenti; riusa soltanto gli identici verificati. Conserva v3 e piano. Byte3573,SHA329396be9409d78025cabe7d54f817b5fc6182b389f9272565404db437f46cb2. Download sempre da commit esatto del checkpoint che lo pubblica; verificareSHA prima dell'esecuzione. L'installazione non consuma né autorizza lo scope di fermo.

## Comandi operativi da approvare

**Solo sul VPS,Bash, dopo decisione esplicita su questo pacchetto e manutenzione esclusiva.** Riferimento proposto della decisione: GIOVANNI-NONPROD-COLD-20261106-01. Non eseguire per effetto della sola installazione.

Fermo singolo:

```bash
sudo /usr/bin/python3 -I -B -S /var/lib/ouf-storage-test-cold-stop-20261106.py \
  --decision-reference GIOVANNI-NONPROD-COLD-20261106-01 \
  --exclusive-operator-maintenance --nonproduction-test-state
```

Solo dopo status STOPPED_OFFLINE_CAPTURE_PENDING e verifica della ricevuta, cattura singola con SHA del piano derivato riportato dal fermo. Il comando seguente legge soltanto loSHA dal risultato e il produttore verifica nuovamente piano,programma e guardia offline. Non avviare se la manutenzione esclusiva è stata interrotta.

```bash
(
set -e
ouf_capture_plan_sha="$(sudo /usr/bin/python3 -I -B -S - <<'PY'
import json,re
from pathlib import Path
p=Path('/var/lib/ouf-storage-migration/cold-test-stop-20261106-v1/result.json')
r=json.loads(p.read_bytes())
assert r['status']=='STOPPED_OFFLINE_CAPTURE_PENDING'
assert r['policyChanges']==35 and r['selectedRolesStopped']==14
assert re.fullmatch('[0-9a-f]{64}',r['planSha256'])
print(r['planSha256'])
PY
)"
sudo /usr/bin/python3 -I -B -S /var/lib/ouf-storage-cold-backup-v4.py capture \
  --plan-sha256 "$ouf_capture_plan_sha" \
  --recipient-file /var/lib/ouf-storage-cipher-preparation-20261106/recipient.pub \
  --decision-reference GIOVANNI-NONPROD-COLD-20261106-01
)
```

Risultato atteso ENCRYPTED_OFFLINE_RECOVERY_SET_CAPTURED,con dimensione/SHA dell'archivio. Restituire solo il JSON redatto. Archivio atteso /var/lib/ouf-storage-migration/cold-backup-20261106-v4/capture/backup.tar.age; output e plaintext intermedi custoditi root. Niente SCP del piano,delle credenziali o del plaintext. Trasferimento cifrato,decifraturaPC e restore isolato sono il traguardo successivo; non sono già provati dal successo capture.

## Accettazione e approvazione ancora richiesta

L'utente ha risolto il vincolo di disponibilità,non approvato questo comando preciso prima che fosse preparato. Richiedere una sola decisione sul fermo35policy/14servizi e cattura dell'intero cluster,con esclusività di manutenzione e mantenimento offline in caso di errore. Non richiedere altra finestra di rientro. L'approvazione operatore non viene etichettata come autenticazioneHUMAN/THS.

**MiniPET invariato:18,3/46=39,78%,0/8gate,0/21AT,0/120migrati.**120corpi verificati separatamente. Backup freddo iniziale è conservazione di stato test,nonG3/G4 completi; consistenza,recupero indipendente,capacità e accettazione restano da dimostrare.
