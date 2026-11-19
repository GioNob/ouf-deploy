# OUF — generazione33: perdita congiunta dei processi storage

Stato: **74 test locali/hosted e cinque scenari nativi PASS**. Run [41819462147](https://github.com/GioNob/ouf-deploy/actions/runs/41819462147), job126538678956, producer `1a8a868fc4361b567127fe898e36c5da2b51d4e2`. Stessa OCI33/coorte e stessa fixture IPv4 del checkpoint `b4cf88b7dec220fb831787313097efdf6708962d`. Nessuna modifica al binario o al target.

## Esito nativo e readback originale

- Quattro SIGKILL137/non-OOM verificati. I timestamp FinishedAt di **tutti** i vecchi servizi precedono Created di **ogni** sostituto. Quattro nuovi container/namespace, distinti tra loro/dall'host/da quelli originali; client con ID/StartedAt/RestartCount conservati. Identità completa nella receipt.
- Stesse radici/IP, config e TLS read-only. Regole di tutti i ruoli e otto listener chiusi prima del rilascio globale. Inventari fermo/gate esattamente identici: **master4 file/1335 byte; filer40 file/5274 byte; volume7 .dat/8389064 byte**. Prefissi .dat ancora identici dopo recupero; nessuna uguaglianza fisica post-apertura imposta agli store master/LevelDB.
- TopologyId `4928781d-af44-4fb7-9f31-f306d40eaeb9` e localizzazioni dei chunk conservati. Nuove registrazioni filer/S3/volume nel log del nuovo master. **Primo probe di topologia PASS** dopo la readiness degli otto listener; non è una misura del tempo di disservizio.
- JSON metadati completo invariato e contatore HTTP del nuovo filer **0→1954 byte**. **Primo GET/HEAD/LIST S3 di recupero PASS**, zero PUT aggiuntivi, corpo8388865 byte/SHA256 `25809f4ef8ae5e9ab82c2688effb8da2ae66bb0b320befd55350dcb2cda9569d`, MIME/TLS coerenti. Contatore HTTP del nuovo volume **0→8397434 byte TCP**. I contatori comprendono overhead, non misurano dimensione esatta del payload né prestazioni/RTO.
- Tutti i cinque scenari mantengono10 link ammessi/37 dinieghi ciascuno, other_denied zero e parità oggetto dopo i probe. **32 container distinti,25 arresti finali puliti,7 SIGKILL intenzionali/non-OOM**, cinque reti rimosse. I casi singoli conservano le rispettive verifiche.
- Artifact13315564297 originale: **323530 byte**, SHA256 `b52402b03b4ba5c1aaecb2a1060034a95f8bd0c271345d5c9ef7c395ef5ad65c`; **307 membri,306 checksum,22 hash sorgenti esatti**. Readback locale di timestamp/stati, mount, gate/namespace, inventari, topology/lookup/registrazioni, metadati, TLS/S3, contatori/dinieghi e cleanup PASS. Nessuna chiave privata. Firma publisher coorte verificata hosted; nessuna verifica crittografica locale aggiuntiva dichiarata.

[Archivio originale](../evidence/artifacts/storage-all-crash33-41819462147.zip) e [receipt di readback](../evidence/storage-all-crash33-readback-20261104.json). Nessuna seconda esecuzione nativa locale o esportazione dei corpi DB/payload.

Prossimo singolo passo: interrompere un PUT mentre il corpo è ancora in trasferimento, prima dell'ACK, nella fixture isolata; verificare l'esito tramite letture reali e impedire oggetti parziali validi o reinvii mutativi automatici. Non dedurre tale proprietà dal crash post-ACK appena concluso.

## Protocollo eseguito

1. Un PUT confermato dell'oggetto8388865 byte, chiave fixture `staging/volume-crash.bin`; nessun GET del corpo prima del guasto. Metadati completi dal filer e TopologyId/localizzazioni chunk direttamente dal master registrati come baseline.
2. Un comando Docker batch invia SIGKILL a master,volume,filer,S3. **Tutti e quattro devono risultare exit137/non-OOM prima di creare qualsiasi sostituto**. Non si assume simultaneità fisica dei segnali. Il client resta vivo; i suoi processi Python di richiesta sono effimeri e il gateway S3 viene sostituito.
3. Inventari bounded di master,LevelDB2 e .dat a processi fermi, senza sync/checkpoint/copia artificiale. Rimozione dei quattro container morti; quattro nuovi container/namespace/gate con stessi IP/radici e configurazione/TLS montata read-only.
4. **Tutti i firewall e gli otto listener chiusi sono verificati prima di rilasciare qualunque gate**. I quattro namespace devono essere distinti tra loro, dall'host e da tutti quelli originari. Inventari identici ancora prima dell'exec. Anche un gate mancante/symlink/preaperto impedisce il rilascio degli altri.
5. Ripartenza, metadati completi e TopologyId/localizzazioni invariati; log del nuovo master con registrazioni filer/S3. Policy discovery già qualificata:10 tentativi/120s, jitter/Retry-After rispettati, solo readiness503 o lookup404/503 dei volumi noti ammessi come attesa. Stato errato/identità/integrità/errore sconosciuto blocca.
6. GET/HEAD/LIST S3 firmati/TLS, corpo/hash/MIME invariati senza alcun PUT di recupero. Contatore HTTP del nuovo volume misura traffico almeno pari al payload, contatore filer prova il GET diretto dei metadati, prefissi .dat originali preservati. Nuova matrice10 link ammessi/37 dinieghi e controllo parità finale. Cinque arresti puliti e rete rimossa dopo le quattro morti intenzionali.

## Verifiche e limiti

Dieci nuovi test su insieme esatto dei processi morti, rifiuto di exit/OOM errati, sostituzione di tutti i servizi con client invariato, namespace nuovi, rilascio dei gate dopo validazione completa, gate mancanti/symlink/preaperti e combinazioni CLI incompatibili, mount persistenti/config read-only. Totale74 con le64 regressioni; YAML e shell validati. La CI esegue cinque laboratori separati: normale,volume,filer,master,congiunto.

La rifattorizzazione della sostituzione usa lo stesso ciclo bounded per1 o4 servizi; gli originali storici restano conservati e i casi singoli sono nuovamente eseguiti. L'evidenza congiunta identifica distintamente le quattro morti, i quattro sostituti e l'unico client mantenuto.

Non è power loss, reboot host, perdita disco/quorum, HA, test durante scrittura in-flight o RPO/RTO. Il PUT è già concluso e la page cache del kernel rimane disponibile. La perdita delle cache dei quattro processi non equivale alla perdita della cache del sistema operativo. Nessuna accettazione target o prova di prestazioni rappresentative viene dedotta. Metodi interni/mTLS/IPv6/host compromesso restano non qualificati. Dati DB/payload non esportati, soltanto inventari/hash e osservazioni hosted; nessuna seconda esecuzione nativa locale dichiarata.

MiniPET invariato18,3/46=39,78%, circa40% ±10;0/8 gate,0/21 AT,0/120 oggetti reali. Nessun VPS/merge/deploy/replay/reset/grant. MinIO, scope17/52 Engine GET, Teatri/M1 e Farmacie preservati.
