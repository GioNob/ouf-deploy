# OUF — verifica corrente della custodia discovery: operatore necessario

29 ottobre2026. [PR54](https://github.com/GioNob/ouf-deploy/pull/54). [Qualifica custodia](../../evidence/m2-discovery-custody-capture-qualified-20261029.json), [frame Docker reale](../../evidence/m2-discovery-native-frame-qualified-20261029.json), [owner nodo](../../evidence/m2-discovery-node-owner-source-qualification-20261029.json), [pacchetti](../../evidence/m2-discovery-native-witness-and-packages-20261029.json).

## Esito di questo avanzamento

Il percorso sorgente ora comprende profilo discovery distinto, proposta completa OCI a sette mount, tre capability con un solo scope, witness collegato aPausedNodeObservation, rientro13fasi alle posizioni9/10 e owner del nodo con recipe/phase-intent firmato. Il vecchio profilo file-only e il suo rientro7/8 restano distinti. L'owner rifiuta firma mancante, finestra scaduta, intent diverso anche se firmato, recipe mutata o transizione file-only.

Frame nativo verificato su Docker29.8.1/overlayfs/systemd/containerd, push40845016640/job123350264235 e PR40845022690/job123350284460, entrambiSUCCESS e log letti. La policy deriva dal baseline indipendente, non dall'OCI da controllare. Cinque file readonly e configtree DB osservati realmente; container in pausa e Java mai eseguito. La CLI riordinava Env: il qualifier usa ora l'effettiva API Engine JSON/Unix con peer root, senza modificare il confronto OCI. Immagine/input sono sintetici: token owner, IAM/provider/TLS, firma di accettazione target e E2E restano non provati.

Pacchetti MCP e Gateway prodotti e riletti indipendentemente: MCP imagea013bceb...,artifact12882394596,Go1.26.10/user10005:10005,9checksum/261blob/config/layer/binario verificati; Gateway artifact12882339953,6checksum/378blob/6file materializer verificati. Gate HIGH/CRITICAL/UNKNOWN inclusi unfixed PASS; report filtrati non dimostrano assenzaLOW/MEDIUM. Tutti i digest e limiti nel dossier pacchetti. Nessuna prova publisher trust o ammissioneOCI/rootfs host. Registry conserva il pacchetto qualificato già selezionato.

109PASS/0errori/0skip per esecuzione su push40846711261/job123355871936 e PR40846716178/job123355889523:102regressioni/profilo/owner e7nuovi test della custodia. File POSIX e proprietari/modi reali nel runner root, process/boot fixture esplicita con un test separato sul proprio processo Linux reale. Il runtime locale cloud non supporta chown/proc necessari: nessuna pretesa di qualifica POSIX locale.

## Perché serve ora l'operatore

Il connector non espone accesso manutentivo al filesystem del VPS e non c'è un esecutore SSH collegato. La preparazione necessita della verifica locale dei candidati credenziale/chiave già creati dall'owner: non occorre scegliere nuovi segreti, recuperare budget o fare login IAM. Sono candidati storici, non authority corrente; la nuova lettura confronta impronte e metadata effettivi e ricontrolla i pin dei quattro processi e il boot prima/dopo.

Sono selezionati esattamente due metadata: inputsf759d397 e manifest732a633e del precedente rootsemantic-discovery-runtime-inputs-682nr5ky. Quattro file esatti: una credenziale provider, le due copie della chiave applicativa discovery (Registry/Gateway) e il CA pubblico. Massimo45secondi/4MiB; nessun valore grezzo di credenziale/chiave viene stampato o salvato. Le impronte specifiche restano nel record privato root0600. L'output pubblico riporta solo esito/counter/hash del nuovo record. File e scope preesistenti restano invariati.

ZeroEngineGET/write/SQL/IAM/OAuth/login/chiavi nuove/chiavi di firma deployment/firme/import/lifecycle/grant/budget/upload/job/resume/acquisizione. Il successo dimostra soltanto continuità e custodia di candidati: non validitàIAM, scopeOAuth, providerTLS, ammissioneDB, tutti13peer correnti o authority. Queste verifiche restano nel percorso coordinato successivo.

Il nuovo scope è `/etc/ouf/deploy-snapshots/m2-discovery-custody-f759d397-20261029-v1`, ancora NON eseguito sul target. È diverso dal vecchio scope f759, consumato e non rilanciabile. Riferimenti storici sono input di provenienza, mai un reset o una ripetizione delle vecchie authority.

## Unico comando corrente

Come `oufadmin` in SSH interattivo, UNA volta. Può essere richiesta soltanto la password sudo locale. Nessun APPROVO, token o login IAM. Restituire solo JSON finale e footer; non inviare gli inputs privati, file credenziale/chiave o configurazioni.

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_custody_bootstrap=$(mktemp -d "$HOME/ouf-m2-custody-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 16384 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/a2473d8925eaa54924d76dd630566c848030c80d/releases/read-m2-discovery-custody-20261029.sh' \
    -o "$ouf_custody_bootstrap/run.sh"
  printf '%s  %s\n' '308b8e5b69a52e7ae6f5b8ed7898519a3a78e8d60b25a4597857752c98070226' "$ouf_custody_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_custody_bootstrap/run.sh"
  /usr/bin/bash "$ouf_custody_bootstrap/run.sh"
)
```

Sourcebab8d63a6d8e47cf0ae6ff0dc15841009748b417/SHA834dd9b0b7e9f7b02fc07c7080f6d3e51cc7b7fd541691f26942e136a08c00cf; wrappera2473d8925eaa54924d76dd630566c848030c80d/SHA308b8e5b69a52e7ae6f5b8ed7898519a3a78e8d60b25a4597857752c98070226. Consegna qualificata5782af38ce1f7ed777094dcc56075741e7fa4801, push40847147152/job123357320519 e PR40847156690/job123357352454 SUCCESS, log letti. HTTPS reale,oufadmin/nonroot/sudo,codice root0400/checksum root,nonTTY prima del download/scope e accesso nonroot al codice negato. La consegna usa il source esatto e si ferma per assenza dei metadata target nel runner; la raccolta positiva è provata separatamente dai test POSIX. Lo scope di fallimento resta conservato e il replay è negato prima della riesecuzione protetta.

Se STOP, conservare l'esito e NON rilanciare, cancellare o ricreare lo scope. Il primo risultato f759d397 rimane riuscito: il duplicato1FN41iD7 rifiutato non lo sostituisce.

## Dopo il risultato

Vincolare il record privato candidato alla preparazione completa e agli owner correnti: eventuali proiezioni di file devono rispettare UID/modi effettivi senza cambiare i file storici; validità della credenziale, scope del workload, chiave coerente APISIX/Registry e fiducia TLS richiedono ancora ammissione attuale. Preparare la review coordinata con generazioni correnti, backup/fencing/DBV11–V12, source/pacchetti/OCI/rootfs indipendenti, rinnovo e autoritàHUMAN finite quando richieste. Nessuna semplice accensione di flag o bare restart.

Poi installazione/pubblicazione governata e prova reale chatbot→MCP→Gateway→Registry→OntoPiA, stessa idempotencyKey/requestId e provenienza/snapshot, adozione/pubblicazione e sorgente canonica, fault/reboot/rotazione e due client. Le capability discovery non sono ancora esposte dal connector; tutti8criteri di stabilità edE2E sonoOPEN.

Farmacie invariato: asset9c502da5-b5d8-405e-b3f5-60eb31ecb513/job677480c8-3d10-44fd-9dad-f72ddeed20a4/profilof3061699-4fde-4085-89c8-bc8703f65686 SUCCEEDED,61righe/10colonne,ministerialeSTRING,CAPSTRING e10campiOPEN confermati. Nessun nuovo upload/profiling/budget/resume/acquisizione. M1/G4 acquisiti; M2/G5–G7/D5–D7 aperti. Nessun merge/releaseacceptance/subagente/automazione. Non sostituire OntoPiA con web/Turtle/ontologia locale.
