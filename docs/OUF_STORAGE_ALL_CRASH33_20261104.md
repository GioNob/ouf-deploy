# OUF — generazione33: perdita congiunta dei processi storage

Stato iniziale: **74 test locali PASS; qualifica nativa PENDING**. Stessa OCI33/coorte e stessa fixture IPv4 del checkpoint `b4cf88b7dec220fb831787313097efdf6708962d`. Nessuna modifica al binario o al target.

## Protocollo

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
