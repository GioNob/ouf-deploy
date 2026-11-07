## 7 novembre — claim di cattura già presente

L'operatore ha riportato il riuso esatto dei due strumenti e `HELD/CAPTURE_CONTINUATION_ALREADY_CLAIMED`. Il tentativo osservato si è fermato prima di iniziare una nuova cattura. Il precedente esito sul VPS è da riconciliare con [la ricevuta](../evidence/storage-capture-claim-held-operator-20261107.json) e [il lettore locale](../scripts/read-storage-capture-claim-20261107.py). Usare il comando di lettura ancorato a commit e SHA-256 consegnato all'operatore. Lo scope resta conservato. Nessun replay, reset o uso di un parziale per Windows.

Il lettore restituisce `CAPTURE_RESULT_RETAINED` solo se claim, ricevuta interna, ricevuta finale e dimensione dell'archivio concordano. La copia Windows verifica il digest del file ricevuto. `CAPTURE_OUTCOME_UNSEALED` espone soltanto la presenza dei passaggi e non attesta che il processo sia attivo, concluso o fallito. Nove casi di fixture locali PASS. MiniPET **18,3/46 (39,78%)**, credito aggiunto 0. Il comando di cattura nella sezione storica qui sotto non va rilanciato.

# Cattura dopo fermo HELD — pacchetto concreto del 7 novembre 2026

**Stato: singola continuazione autorizzata da Giovanni il 7 novembre 2026; esecuzione VPS pendente.** Decisione GIOVANNI-NONPROD-CAPTURE-ONLY-20261107-01, [ricevuta](../evidence/storage-capture-only-operator-decision-20261107.json). Le motivazioni di consenso sotto conservano il contesto del pacchetto approvato; non richiedere nuovamente l'autorizzazione.

## Fatti acquisiti dal VPS

[Readback fornito da Giovanni](../evidence/storage-cold-event-target-operator-20261107.json):504file legati,49intenti/reply,35postcondizioni policy,cinque gruppi fermati. L'ultimo inventario conservato registra0running su145container;14ruoli selezionati usciti secondo contratto,PostgreSQL/MinIO/etcd0,applicativi0/143;restart=no. Non è prova live né drain applicativo. Directory capture vuota.

72eventi:35update,14kill,14die e9eventi aggiuntivi di etcd,tre sequenze exec_create/exec_start/exec_die con exit0. I comandi non coincidono colhealthcheck configurato. Non attribuiti a un attore o healthcheck,non dimostrati autorizzati. Non viene dichiarato che fossero innocui. Lo stato di test e questa incertezza vengono conservati nel backup; nessun traffico viene riaperto.

Reportcanonico917b75fa209a4d85aadd92a42913d45eb8f53869c9e2cf1e878f3a1c4b51ddd1;planSHAf4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d;journalSHA5f3416a62555adf1d6b4dc00370bd72cf33c0844bb7d671aaae05c08f4bc741f. Il programma rifiuta report,registro o piano diversi. Il filtro eventi e il produttore backup originali non cambiano.

## Operazione proposta

Decisione esatta: **GIOVANNI-NONPROD-CAPTURE-ONLY-20261107-01**.

1. Installare due nuovi programmi pinned root0600:lettore del journal e wrapper di sola cattura. Nessun file precedente sovrascritto.
2. Rileggere le ricevute già raccolte per verificarne l'integrità;non inviare nuovamente comandi di fermo. Verificare l'unico precedente showhost e conservarne consumo.
3. Creare una sola nuova area esclusiva /var/lib/ouf-storage-migration/capture-after-held-stop-20261107-v1. Le aree precedenti restano immutabili,compresa capture vuota;nessuna adozione dello scope consumato.
4. Controllare dal vivo host disabilitato/inattivo,override/cgroup e cinque fonti runtime. Prima della copia,il produttore verifica di nuovo inventario Docker,uscite,generazioni,policy e condivisioni offline.
5. Catturare le stesse34fonti,immagini e rootfs dei14ruoli,compreso interoPostgreSQLcondiviso;tar/manifest,verifica fonti prima/dopo,controllo nuovi eventi durante cattura,cifratura age con ilrecipient già provato suWindows.
6. Conservare **dentro l'archivio cifrato** il report,la mappa dei504digest,ultimo inventario/eventi privati e ricevute delleazioni;la provenienza e configurazione host è già nel piano originale. Il nuovo piano cambia soltanto programhash e aggiunta di questo contesto;ruoli,fonti,snapshot e scadenza invariati.
7. Verificare nuovamente host,fontiruntime e vecchiojournal dopo la cattura. Pubblicare risultato solo se tutti i controlli riescono.

**Zero segnali ai container,zero modifiche restartpolicy,zero mutazioni host,zero riavvii.** Le classi runner negano esplicitamente mutazioniDocker e host. La cattura usa export/inspect/read locali; scrive nuovi file backup e ricevute,mai dati applicativi originali.

Non si riscrive il vecchioHELD come successo. Non si attribuiscono retroattivamente gli exec né si ammette un nuovo stato operativo. L'eventuale lavoro applicativo ambiguo resta da riconciliare. Lo scopo è conservare lo statoNONPROD/test già accettato daGiovanni,non chiudereG3/G5.

## Budget e autorizzazione

- Una sola continuazione;nuovoscope già presente ⇒HOLD.
- Nessun nuovo budget di fermo:2400s cumulativi già addebitati e184CLI conservati;nessuno di questi comandi viene ripetuto.
- Cattura precedentemente mai avviata:stesso limite3600s e256comandi,64GiB di output prodotto dalrunner (non una stima della dimensione finale).
- Showhost precedente1chiamata/byte addebitato al relativo budget cumulativo256CLI/32MiB;due nuove verifiche host in sola lettura.
- Scadenza originale1794081219 (7novembre2026,20:53:39Europe/Rome) invariata,almeno3600sresidui prima dell'avvio. Nessun reset o estensione.
- EventualeHOLD conserva tutti i parziali;nessunretry automatico o pulizia degli originali.
- Plaintext temporaneo resta privato sulVPS; il file perWindows è cifrato. Nessun corpo privato va caricato inGitHub/chat.

Il consenso precedente copriva un solo tentativo stop/capture,ora consumato. Questa continuazione distinta richiede la decisione sul pacchetto concreto e sulla conservazione dello stato con i treexecnonattribuiti. Non si richiede di nuovo consenso per sviluppo,fermo già effettuato o downtimeNONPROD. La decision-reference è provenienza operatore,non un tokenHUMAN autenticato o ungrant runtime.

## Qualifica

Cinque test di confine localiPASS:mutazioniDocker respinte,decisione esatta,scopeconsumato,scadenza non rinnovata e digestreport diverso. La nuova prova nativa riproduce il caso concreto con145containerfixture,treexecetcd reali provocati,fermo49azioni eHOLD finale; poi sola cattura,decifratura e verifica delleprove archiviate. Non è il workload applicativo target né un restoreindipendente delVPS. Le provePG/MinIO eWindows precedenti non sono state rilanciate.

[Run42313748655](https://github.com/GioNob/ouf-deploy/actions/runs/42313748655),job128221206861 **SUCCESS** alcommit0e1c3bdb587b3d6e8a360f8f9a7af4dd3a4b97ac;log riletto.5testPASS più prova nativa:145container,103sharer,treexecetcd reali provocati,72eventi/9respinti eHOLD riprodotto. Cattura successiva con0segnali/0policy/0mutazionihost,26CLIbackup,3hostreadcumulativi incluso1precedente. Archivio cifrato70.366.180byte/20membri,decifratura ed estrazione5corpi runtime e prove integrali riuscite. Vecchiojournal byteidentico,alterazioneintent respinta prima delclaim,replayrespinto,TTLpreservato.

La fixture ha1fonte e498filejournal/181comandi precedenti,contro34fonti e504file/184comandi deltarget; la differenza nei comandi dipende dai poll del fermo. Percorsi,ID e digest della fixture sono sostituiti soltanto nel test;il programma operativo conserva i pin esattiVPS. Il restore applicativo reale e l'attribuzione dei treexec sulVPS restano non provati. [Dossier](../evidence/storage-capture-after-held-stop-qualified-20261107.json) · [Risultato nativo](../evidence/storage-capture-after-held-stop-native-20261107.json).

## Comando VPS Bash — soltanto dopo la decisione registrata

```bash
sudo /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, subprocess, sys, urllib.request
url = ("https://raw.githubusercontent.com/GioNob/ouf-deploy/"
       "f9a8a5a6967bad69e74e23563f8460968068089f/"
       "scripts/install-storage-capture-after-held-stop-20261107.py")
with urllib.request.urlopen(url, timeout=30) as response:
    raw = response.read(3914)
if len(raw) != 3913 or hashlib.sha256(raw).hexdigest() != "45d65577bad7c135bc292575214a1121092f178121548b10cfff73ef8487d19d":
    raise SystemExit("HELD: download o SHA256 non corrispondente")
print("Download e SHA256: OK — strumenti di sola cattura", flush=True)
exec(compile(raw, "verified-installer", "exec"), {"__name__": "__main__"})
result = subprocess.run([
    sys.executable, "-I", "-B", "-S",
    "/var/lib/ouf-storage-capture-after-held-stop-20261107.py",
    "--decision-reference", "GIOVANNI-NONPROD-CAPTURE-ONLY-20261107-01",
    "--exclusive-operator-maintenance",
    "--preserve-held-nonproduction-state-with-unattributed-etcd-execs"])
if result.returncode:
    raise SystemExit("HELD: continuazione conservata; non rilanciare.")
PY
```

Installer f9a8a5a6967bad69e74e23563f8460968068089f,3913byte/SHA45d65577bad7c135bc292575214a1121092f178121548b10cfff73ef8487d19d.
Wrapper 0e1c3bdb587b3d6e8a360f8f9a7af4dd3a4b97ac,11182byte/SHA583a5e26ab18bfdb09d868fb3d7fabd9acf347f64dbf01b8caf0bf8cbec80184.
Lettore15318byte/SHA3d96e397c3331c4ab17c32a517338f56135c7d9c9120e236be2295af30ff794a,giàqualificato.

## Consegna attesa

ENCRYPTED_OFFLINE_RECOVERY_SET_CAPTURED con percorso/dimensione/SHA256 reali. Percorso previsto,se riuscito:/var/lib/ouf-storage-migration/capture-after-held-stop-20261107-v1/capture/backup.tar.age. Non si presume già esistente.

Dopo il JSON reale:trasferimentoSCPWindows,custodia offhost e restore isolato,poi SeaweedFS. MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120migrati;120verificati separatamente,nessun credito aggiunto per questa qualifica.
