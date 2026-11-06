> **Autorizzata il 7 novembre 2026:** Giovanni ha approvato questa singola operazione. Riferimento GIOVANNI-NONPROD-HOST-BOUND-COLD-20261107-01; [ricevuta](../evidence/storage-host-bound-cold-operator-decision-20261107.json). Esecuzione VPS pendente. Le diciture di decisione pendente sotto conservano il pacchetto esatto approvato.

# Backup freddo collegato al contenimento host — 7 novembre 2026

**Stato: procedura qualificata; decisione sul nuovo fermo/capture pendente.**
Il contenimento host sul VPS è riuscito e non va ripetuto. [Ricevuta operatore](../evidence/storage-host-continuation-success-operator-20261107.json).
Prossimo risultato: primo archivio cifrato reale del VPS; successivamente trasferimento al PC Windows e restore isolato.

## Collegamento alle prove reali

Snapshot cinque fonti runtime:8c16113535d7435f49c2c876c20141374bdeca103fda55d826a2f8736a46ff88.
Risultato host canonico:35057e4fc3d2becfcb599ee3b7b767ea484f95343ee73768d3964da26cc82592.
Il programma verifica questi digest,bozza,preflight,cgroup e ricevute private della continuazione riuscita.

Dal piano v4 originale cambia soltanto identità delle cinque fonti runtime,hash del programma e provenienza. Ruoli,immagini,mount,34fonti,policy e scadenza rimangono quelli originali.
Il nuovo piano cifrato contiene sei documenti host privati,incluse configurazioni originali delle unità e testo degli override offline: non solo digest. Nessuno di questi contenuti viene stampato o pubblicato.
Questo non è un'immagine completa del filesystem host né una prova di restore automatico dei servizi host; eventuale ripristino e riabilitazione restano governati.

Il vecchio tentativo Docker viene letto e verificato:claim/proposal pinned,esattamente3stdout+3stderr vuoti e directoryclient vuota,nessun intento o risultato. Inventario conservato coerente col piano. Le3letture e i byte precedenti restano conteggiati. Originali mai sovrascritti o riutilizzati.

## Operazione concreta

1. Installare un solo nuovo programma root0600,senza sovrascrivere gli strumenti precedenti.
2. Creare una nuova area esclusiva /var/lib/ouf-storage-migration/cold-host-bound-20261107-v1 e registrare claim/piano/collegamenti.
3. Verificare dal vivo host inattivo e disabilitato,sei override,cgroup vuoti e fonti runtime identiche allo snapshot.
4. Portare a restart=no **35container**:13dei14ruoli selezionati e22container già fermi che condividono i dati. I103container già fermi con condivisioni restano fermi.
5. Fermare i **14container selezionati**,per gruppi verificati:
   - ingress:caddy,apisix,mcp,gateway-owner;
   - application:onboarding,ingestion,udp,semantic,ingestion-evidence-read,udp-evidence-read;
   - identity:keycloak;
   - data:postgres,minio;
   - control:etcd.
6. SIGTERM per i servizi; PostgreSQL conserva SIGINT se previsto dalla configurazione ammessa. Nessun SIGKILL ai container,riavvio,retry automatico o rimozione. PostgreSQL/MinIO/etcd devono uscire0; gli applicativi0/143 non provano drain.
7. Verificare di nuovo il contenimento host e catturare **34fonti,mount,immagini e rootfs dei14ruoli**,compreso **l'intero cluster PostgreSQL condiviso**. Verifiche tar/metadati prima e dopo,eventi Docker e sorgenti stabili.
8. Cifrare con il recipient pubblico già verificato su Windows,poi verificare nuovamente host e vecchie ricevute.

La cattura comprende dati/configurazioni private. Plaintext temporaneo resta rootprivate sulVPS; il file destinato alPC è cifrato. Nessuna pulizia automatica degli originali o degli scope.
Il campo providerMutationCommands=0 del risultato descrive soltanto la fase capture; il fermo precedente modifica35policy e invia14segnali.

## Limiti e decisione

Riferimento proposto: **GIOVANNI-NONPROD-HOST-BOUND-COLD-20261107-01**.

Una sola esecuzione,manutenzione esclusiva,stato nonprod/test già dichiarato.
- Nuovo fermo:1200s (20minuti);vecchia allowance1200s addebitata integralmente,massimo cumulativo allowance fermo2400s.
-256CLI/64MiB cumulativi di metadati fermo,inclusi3comandi/byte precedenti.
- Cattura:3600s (60minuti),256comandi,budget64GiB di output prodotti dal runner. Non è una stima della dimensione finale dell'archivio.
- Controlli host in sola lettura prima del fermo,prima e dopo capture,con finestra complessiva4800s e limite perCLI15s. Eventuale superamento produceHOLD.
- Scadenza originaria1794081219 **non estesa**; servono4800s residui all'avvio. Nessuna riapertura automatica.
- Nuova area già esistente o qualsiasi HOLD: conservare tutto e non rilanciare.

Serve una decisione per questo nuovo tentativo stop/capture: il precedente consenso Docker copriva un singolo tentativo consumato; i due consensi host non lo riattivano. Il perimetro Docker resta quello già esaminato.
Decision-reference registra la provenienza operatore,non autentica HUMAN/THS né concede authority runtime.

## Prove

[Run42310506109](https://github.com/GioNob/ouf-deploy/actions/runs/42310506109),job128210457310 **SUCCESS**,codiceac0b5b862e7e1209756f596c5ae293c366c7b49e.
Fixture:systemd reale già inattivo,14handlerPID1BusyBox e2sharers fermi;immagine osservata sha256:b116e155074440ffd9e449559433feb4cd2341eb3554b1da1c638c976e56451d.
Riprodotto vecchioHOLD sulle fonti cambiate; nuovo collegamento modifica solo runtime/program/provenienza e conservaTTL.
Timer riabilitato respinto,fermo14container,15policy nella fixture,archivio cifrato69976964byte,decifratura ed estrazione5file runtime riuscite. Sei documenti host nel piano riletti e confrontati. Vecchiojournal byteidentico,replayrespinto.
Il test ha121comandi Docker fermo cumulativi inclusi3precedenti e26capture;3controllihost.
[Prova](../evidence/storage-host-bound-cold-native-20261107.json) · [Dossier](../evidence/storage-host-bound-cold-qualified-20261107.json).

Prima esecuzione42310274347 fallita nella sola costruzione della fixture,GetUnit di slice inattiva; corretta usando i percorsi canonici già legati nella ricevuta simulata. Core host qualificato non modificato.
Le precedenti prove PostgreSQL/MinIO reali con restore e cifratura Windows sono riusate senza ripeterle. Questa nuova fixture qualifica la composizione,non il workload target o un restore dei14servizi applicativi.

## Comando VPS Bash — soltanto dopo la decisione sopra

```bash
sudo /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, subprocess, sys, urllib.request
url = ("https://raw.githubusercontent.com/GioNob/ouf-deploy/"
       "da46be2c9ce47322ac6b65dd615401968beb8534/"
       "scripts/install-storage-host-bound-cold-20261107.py")
with urllib.request.urlopen(url, timeout=30) as response:
    raw = response.read(3558)
if len(raw) != 3557 or hashlib.sha256(raw).hexdigest() != "a0a6eec3c93c6cea3aac941b12ea315f9d264e8b7fab6a4e75ec8b37ca1199c2":
    raise SystemExit("HELD: download o SHA256 non corrispondente")
print("Download e SHA256: OK — programma backup collegato", flush=True)
exec(compile(raw, "verified-installer", "exec"), {"__name__": "__main__"})
result = subprocess.run([
    sys.executable, "-I", "-B", "-S",
    "/var/lib/ouf-storage-host-bound-cold-backup-20261107.py",
    "--decision-reference", "GIOVANNI-NONPROD-HOST-BOUND-COLD-20261107-01",
    "--exclusive-operator-maintenance", "--nonproduction-test-state"])
if result.returncode:
    raise SystemExit("HELD: operazione conservata; non rilanciare.")
PY
```

Installer3557byte/SHAa0a6eec3c93c6cea3aac941b12ea315f9d264e8b7fab6a4e75ec8b37ca1199c2.
Programma14686byte/SHAef76ef3efbbad2caebbfbabbb5c6d40a00fd5cbe09e486cb6ed94e43903af53d,dalcommitac0b5b86.
Installer controlla dipendenze pinnedv3/stop/hostcore,scarica/hash prima di scrivere,O_EXCL/root0600/fsync,riuso soloesatto. Sintassi/pin verificati localmente,nessuna installazione target già attestata.

## Esito

Atteso ENCRYPTED_OFFLINE_RECOVERY_SET_CAPTURED,conpercorso/dimensione/SHA256 reali.
Percorso previsto se riuscito:/var/lib/ouf-storage-migration/cold-host-bound-20261107-v1/capture/backup.tar.age.
Non assume che il file esista già. Restituire soltanto JSONredatto,nonfileprivati.
Poi consegnaSCPWindows e verifica/restoreisolato. Nessuna riaccensione automatica dopo backup.
MiniPET39,78%,0/8gate,0/21AT,0/120migrati;120corpi verificati separatamente. Il contenimento host riuscito e questa qualifica non chiudonoG3.
