# Farmacie — continuazione dopo peer Engine riconciliato

27 ottobre 2026, Europe/Rome. [Handoff precedente e storia completa](OUF_FARMACIE_DIAGNOSTIC_APPLY_NEXT_20261027.md). Capture5909d100, preparazione immagine/inputc2258617, primoAPPLY e reader conservato sono tutti CONSUMATI. Nessuno va rilanciato.

## Punto provato sul VPS

Reader RETAINED_ONBOARDING_TRANSPORT_STOP_OBSERVED_NO_AUTHORITY, complete=true/Exit0/DeliveryExit0:7metadata+22letturecodice/319666byte. Stesso socket path/custodia e profilo nativo. L'unico delta è peerCredentials ASSENTE nel profilo storico e presente come lista nella cattura successiva. Zero Engine/SQL/OAuth/configurazione/credenziali/chiavi, nessun vecchio file scritto; assenza autorità/journal e3metadataread originali riconciliati. Non osserva stato runtime corrente e non autorizza la continuazione.

[Ricevuta esatta](../../evidence/onboarding-transport-stop-reconciled-target-20261027.json). Result privato /etc/ouf/deploy-snapshots/onboarding-diagnostic-transport-stop-read-c2258617-v1/result.json, SHA256 be0123cad1ce85cbe16b508d41d9361fa76843603dceffff4e1f64bac655ee3c. Log /etc/ouf/deploy-snapshots/onboarding-diagnostic-transport-stop-read-c2258617-v1/operator.log; delivery /home/oufadmin/ouf-onboarding-transport-stop-read-delivery.qXNr3gnq/bootstrap.log.

## Correzione e qualifica

Source 0e5be010ee37479a49500afb70bbf13b26b40e8a; delivery fd8313933609b53c98b691c675a7b8454f8e9364; wrapperSHA256 16fa7d0b398a3b5a54f371887855930db5edeeea7373a1a780fef5d79ffb64fc; manifesto21fonti d65d48b2da52ef456b0db3cf1807e907983da87fd2100597cb0185c7714bdbce. [Prova completa](../../evidence/onboarding-peer-continuation-qualified-20261027.json).

Il profilo storico resta byte-equivalente e il suo hash non viene riscritto. Ogni campo storico deve coincidere; solo il campo peerCredentials aggiunto deve corrispondere esattamente al suo hash riconciliato. Ogni connessione Engine verifica SO_PEERCRED contro l'intera tupla catturata e richiede UIDroot; il GID osservato resta esatto, senza inventare GID0. Nessuna esclusione generica o tolleranza di socket/CID/profilo diverso.

Riusato anche il probe Spring /actuator/health/readiness del precedente controller Onboarding qualificato; rimosso il path sintetico di altro framework. Porta sempre dal piano privato frozen. Non viene modificata la configurazione del servizio.

CI40479182671:11protocollo+12compatibilità/contatori+6MACnegativi+9fence;7lifecycle per backendDocker29.8.1 classic/containerd conPG17reale;11TTY per sudo use_pty e !use_pty. Consegna esatta40479720976/job122106687702 PASS:root0400/checksumroot/log0600/TTYreale, treletture cumulative e vecchifile/resultreader invariati, rifiuto hash privato sintetico errato prima di Engine/autorità. Log diretti letti, nessuno skip nei casi citati. Tutti21blob e dipendenzeCI esatti. Workload/schemaoperativo/autorità delle fixture sono sintetici: non sono prova VPS/causa Farmacie/E2E.

## Nuovo perimetro concreto

Childunico: /etc/ouf/deploy-snapshots/onboarding-diagnostic-update-c22586172070809d-v1/retained-peer-credentials-continuation-v1. Prima di Engine verifica di nuovo il report conservato per hash, le quattro claim originali e l'assenza di vecchia authority/journal; aggiunge un solo child al vecchio contesto, lasciando intatti i file. I3metadataread originali sono inclusi nei64massimi invariati. Le7+22letture del reader restano consumate e registrate separatamente. VecchieSQL/Engine/import pari0, nessuna fase runtime da ripetere.

Nuova review privata e APPROVO fresco nel terminale prima di autorità/firme/SQL/lifecycle. Stessa immagine diagnostica minima PR52 reviewedSourcea5ed8b05/tested692277b1/native074bd16e/archivio87585bd8 già preparata; nessun rebuild/relabel/import preliminare o candidatoM2piùampio. Nuova cattura di generazioni/peer e admission prima e dopo la review. Nessuna autorità runtime della continuazione ricevuta finora.

Sola sostituzione Onboarding, con breve indisponibilità: vecchio fermato/scollegato/trattenuto fermo, nuovo con stessi MAC/IP/porte/User/Env/mount e policyMemory0; nessun rollback automatico. UnicoYAMLowner già classificato verificato in memoria, zero altri filecredenziali. QuattroSQLtecniche readonly per identitàPG17/35migrazioni/novehash di stato/jobFarmacieFAILED5/assenza lavoro pendente; nessuna diagnosi o contenuto dominio viaSQL. Originali, Registry, MCP, worker, READ e Gateway intatti. Massimi restanti invariati:EngineGET512/write10/import1/readiness96/configmetadata64/contenutoYAML1/SQL4/quarantena1;900s esecuzione+30sola quarantena del proprio candidato non committed. Tre firme esistenti, massimo15aperturechiave dopo consenso.

## Comando — prima esecuzione della SOLA continuazione

Eseguire come oufadmin dal terminaleVPS (chat senza executorVPS). Checksum utente, copia root0400 e verifica root, log conservati; esecuzione interattiva diretta, nessun consenso passato dal wrapper.

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_peer_bootstrap=$(mktemp -d "$HOME/ouf-onboarding-peer-continuation-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 65536 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/fd8313933609b53c98b691c675a7b8454f8e9364/releases/apply-onboarding-diagnostic-peer-continuation-20261027.sh" \
    -o "$ouf_peer_bootstrap/run.sh"
  printf '%s  %s\n' '16fa7d0b398a3b5a54f371887855930db5edeeea7373a1a780fef5d79ffb64fc' "$ouf_peer_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_peer_bootstrap/run.sh"
  /usr/bin/bash "$ouf_peer_bootstrap/run.sh"
)
```

Leggere la review effettivamente prodotta. Se approvata, inserire ESCLUSIVAMENTE la riga APPROVO con il nuovo hash mostrato dal controller e premere Invio. Nessun hash storico o consenso in chat sostituisce questo atto. Finestra900s, input canonico editabile e correggibile entro la stessa scadenza.

Codice/log: /usr/local/lib/ouf-onboarding-diagnostic-update-d65d48b2da52ef45/operator.log. Bootstrap nella nuova directory HOME/ouf-onboarding-peer-continuation-delivery.*. SeSTOP/ambiguo: conservare tutto, non rilanciare e non riavviare il vecchio owner. Mai resettare contatori o rigenerare acquisizioni/job.

Atteso SOLO dopo prova reale: ONBOARDING_DIAGNOSTIC_UPDATE_INSTALLED_E2E_NOT_ACCEPTED, complete=true/Exit0/DeliveryExit0, stato operativo invariato e readiness dimostrata. Poi registrare JSON/log e proseguire sulla stessa Farmacie asset9c502da5-b5d8-405e-b3f5-60eb31ecb513/job677480c8-3d10-44fd-9dad-f72ddeed20a4 tramite owner/APIgovernata con mandatoREADfinito valido. Policy54 scaduta non rinnovata dalla manutenzione; nessun aggiramento SQL o grantautomatico.

M1/G4 acquisito; M2/G5/G6/G7 e causaFarmacie aperti. Percorso CSVgiàriuscito e codice/prove suGioNob sono baseline da riusare, non nuovo sviluppo da ricominciare. Nessun upload/picker/job nuovo, terzaTeatri, sourceactivation, Registryrestart/reinstall, merge o releaseacceptance. Supervisor dopoE2Ecompleto. Lavorare sequenzialmente senza subagenti/automazioni.
