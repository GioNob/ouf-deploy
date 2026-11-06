# Continuazione host dopo SLICE_NAME_REQUIRED — 2026-11-06

**Stato: qualificata, decisione sulla singola continuazione pendente.**
Non rilanciare il comando precedente. Questa consegna conserva il tentativo originale e utilizza una nuova area esclusiva, senza azzerare contatori o estendere la scadenza del piano.

## Evidenza acquisita e difetto corretto

[Readback operatore](../evidence/storage-host-slice-readback-operator-20261106.json):19command receipts,0intenti,0reply,0voci inattese. I due servizi istanziati hanno Slice=system-ouf\\x2dpolicy\\x2dtoken.slice; il vecchio validator li rifiutava. Nessuna nuova osservazione live dedotta dal journal.

Tre digest esatti:
- claim.private.json:622a6a5291c8b9e6ef85bae175d92b23b207b99ad3ec9b1b4d954d0c71d7645b.
- command-001.private.json:9ba599f8ea1938ff3c79c13bab7b2ca5b314dfe199ecf4e47df0a4677b0da67f.
- reviewed-draft.private.json:c4d59b3894f59d6679f11d48dbec2a3d7f5cbba6c8aa89bbee78b63e86475d0a.

La continuazione legge tutti21file dell'area originale e riproduce in memoria le19risposte contro il codice originale pinned: pretende esattamente il diniego SLICE_NAME_REQUIRED prima di qualsiasi mutazione. Questa ricostruzione non richiama provider. Qualsiasi intento,voce inattesa,digest alterato o sequenza diversa blocca il passaggio.

## Perimetro già esaminato, invariato

Cinque timer da disabilitare e fermare: ouf-gateway-policy-token.timer,ouf-ingestion-policy-token.timer,ouf-onboarding-identity-token.timer,ouf-policy-token@onboarding.timer,ouf-policy-token@udp.timer.
I rispettivi cinque servizi vengono lasciati completare naturalmente.
Servizio continuo da disabilitare e fermare con SIGTERM: ouf-registry-token-7cb59501000058b5dc5030ad.service.

Sei dropin persistenti root0600,nessun overwrite,allo stesso percorso /etc/systemd/system/UNIT.service.d/zzzz-ouf-storage-offline-20261106.conf:
```ini
[Service]
Restart=no
SendSIGKILL=no
RuntimeDirectoryPreserve=yes
TimeoutStopSec=120s
```
Eventuali directory mancanti root0755.6disable+1daemon-reload+5stop timer+1stop registry=13comandi mutanti,oltre6dropin. Nessun SIGKILL ai servizi,riavvio automatico,rollback o ripristino automatico dei timer. Coppia semantic masked invariata.
Nessun Docker/PG/S3/IAM,backup o riapertura traffico in questo passo.

## Contabilità e limiti

- Tentativo originale /var/lib/ouf-storage-host-containment-20261106-v1 resta consumato e immutabile.
- Area nuova /var/lib/ouf-storage-host-continuation-20261106-v1,una sola esecuzione; claim prima di chiamate provider.
-19letture originali e byte dei19stdout/stderr restano addebitati. Il massimo cumulativo resta256CLI/32MiB: quindi al massimo237nuoveCLI e32MiB meno byte già consumati.
- Vecchia allowance600s interamente addebitata prudenzialmente; **nuova allowance separata600s**,massimo cumulativo di allowance attiva1200s. Non è un rinnovo automatico del vecchio budget.
- Scadenza1794081219 invariata; avvio solo con almeno5400s residui. Attesa per questa decisione non estende la scadenza.
- Preflight provider fresco prima delle mutazioni: necessario perché il journal è storico. Il campo oldProviderReadsReissued=false riguarda la ricostruzione locale delle vecchie risposte,non esclude le nuove verifiche di stato.
- Dopo il contenimento rilettura integrale dei21file originali e confronto byte/digest. Qualsiasi HOLD lascia tracce e modifiche parziali; nessun replay.
- Risultato nuovo continuation-result.json. Il result.json interno conserva l'esito del driver core separatamente.

## Qualifica

[Run42308843588](https://github.com/GioNob/ouf-deploy/actions/runs/42308843588),job128204988421 **SUCCESS**,codice7887bf88a20d776745e6bb3e09158ecd6a712ff2.
La fixture riproduce realmente il vecchioHOLD con19letture; nega intento di modifica e digest alterato prima di avviare la continuazione. Cinque completamenti naturali,registryTERM,6override/13CLI mutanti,0killforzati,5fonti stabili,replaynegato,vecchiojournal byteidentico.
35nuoveCLI+19precedenti=54,115497byte cumulativi (10696precedenti) sulla fixture; i numeri target saranno misurati.
[Prova](../evidence/storage-host-continuation-native-20261106.json) e [dossier](../evidence/storage-host-continuation-qualified-20261106.json).
Ubuntu24runner,non esecuzioneVPS; nessuna cattura/restoretarget o accettazione dedotta.

## Decisione concreta richiesta

**GIOVANNI-NONPROD-HOST-CONTINUE-20261106-01**: autorizzare una singola continuazione sullo stesso perimetro sopra,con nuova allowance separata di10minuti e contabilità cumulativa indicata. La precedente autorizzazione resta valida come registrazione del primo tentativo consumato,non concede replay automatico.
La decisione registra provenienza operatore; non è HUMAN/THS autenticato né grant runtime.
OUF nonprod può restare indisponibile; manutenzione esclusiva già scelta,nessuna nuova scadenza di rientro richiesta.

## Comando VPS Bash — solo dopo la decisione di continuazione

```bash
sudo /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, subprocess, sys, urllib.request
url = ("https://raw.githubusercontent.com/GioNob/ouf-deploy/"
       "c2ee858be36a3034920eb0d50e50ee809ddd1ac2/"
       "scripts/install-storage-host-continuation-20261106.py")
with urllib.request.urlopen(url, timeout=30) as response:
    raw = response.read(3592)
if len(raw) != 3591 or hashlib.sha256(raw).hexdigest() != "586f46ea0536157ab2e6e45e741b6d0f1b67d81fca4bf0303b4018b33acda13a":
    raise SystemExit("HELD: download o SHA256 non corrispondente")
print("Download e SHA256: OK — strumenti di continuazione", flush=True)
exec(compile(raw, "verified-installer", "exec"), {"__name__": "__main__"})
result = subprocess.run([
    sys.executable, "-I", "-B", "-S",
    "/var/lib/ouf-storage-host-continuation-20261106.py",
    "--decision-reference", "GIOVANNI-NONPROD-HOST-CONTINUE-20261106-01",
    "--exclusive-operator-maintenance", "--nonproduction-test-state"])
if result.returncode:
    raise SystemExit("HELD: continuazione conservata; non rilanciare.")
PY
```

Installer3591byte/SHA586f46ea0536157ab2e6e45e741b6d0f1b67d81fca4bf0303b4018b33acda13a,solo installazione2file nuovi:
- drivercorretto21751byte/SHA05f4e5166a4818d6d6b5a33651e4d4d39888245b2ebe0a3d1ae07a9c28a148ec in /var/lib/ouf-storage-host-containment-fixed-20261106.py;
- continuazione9124byte/SHA5522fde506a439651a923f929bed5d13fe3029a2be508fcebe0c1ec956e5c2c5 in /var/lib/ouf-storage-host-continuation-20261106.py.
Payload pinned7887bf88,verifica entrambi prima di scrivere,O_EXCL/root0600/fsync,riuso solo se identici. Vecchio driver6d5e e readercaac restano inalterati. Sintassi/duepin verificati localmente; nessuna installazioneVPS già dichiarata.

## Dopo l'esito

Atteso HOST_WRITERS_CONTAINED_NEW_STOP_PLAN_REQUIRED. Restituire soltanto JSONstdout redatto.
Poi nuova composizione Dockerstop/capture legata a questa ricevuta e al vecchio tentativoDocker conservato,archivio→Windows→restoreisolato→SeaweedFS. Nessun vecchio comando da rilanciare.
MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120migrati;120verificati separatamente. Nessun credito per questa qualifica.
