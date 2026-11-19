## Profilo v3 riconciliato — host completo fino a192container

Il readback operatore riporta145directory metadata Docker,13binding presenti,zero altre entry/symlink e scope consumato coerente. Non è nuovo conteggio live. La nuova soglia fissa192 dà47posti di margine, senza eliminare container fermi o esterni dal censimento/ispezione.

Input v1/v2 conservano64container/130GET/52GET storici. Solo il nuovo input `ouf.storage-g0-package-input.v3` richiede rete e `priorAttemptFiles` con quattro ricevute private (result,claim,decision,input), ciascuna path e SHA256. Deve essere il precedente tentativo v2 HELD/HOST_BEFORE/G0_HOST_CONTAINER_LIMIT,un solo GET,53cumulativi,nessun child/S3/DB/write. Claim,decisione e input devono coincidere; installazione,13ruoli,percorsi capacità,prove operatore,storico17 e outputParent rimangono uguali. Quattroconfig e rete possono cambiare esclusivamente operationId in nuove copie. Una decisionRef vecchia è respinta; null consente solo check. Questi riferimenti non autenticano HUMAN.

v3 concede al collector solo i limiti tecnici del profilo: massimo192ispezioni+1elenco per osservazione,386GET nelle due passate,32MiB totali/2MiB per risposta,60s per passata e900s complessivi. Il primo GET consumato non è azzerato: priorEngineGets=53,cumulativo massimo439. S3 e DB conservano i budget originali. Ogni lista salva prima del diniego tipo/numero/soglia in host-list-N.json,senza corpo grezzo. Oltre192: HOLD prima delle ispezioni,nessun troncamento/paginazione/retry.

La qualifica nativa aggiornata riproduce145container reali (13ruoli e132fermi fuori roster): il vecchio profilo si ferma dopo1GET; il nuovo, su ricevuta preservata e decisione distinta solo di fixture, ispeziona tutti145prima/dopo con292GET e345cumulativi, poi completa corpiS3/tre export/join. È una nuova prova della composizione modificata, non ripetizione gratuita del vecchio laboratorio13container. Il test non autorizza il VPS o chiude G0.

# G0 — profilo con namespace MinIO e PostgreSQL separati

## Perché serve

Il 6 novembre Giovanni ha riportato: preparazione privata riuscita con17ricevute, nessun listener host sulle porte9000/5432, nsenter disponibile, nessun Compose trovato nella ricerca limitata. Un controllo locale del binding storico autenticato per digest e del boot/processo mostra MinIO e PostgreSQL ancora nelle generazioni attese, ciascuno in una rete diversa dall'host, con listener IPv4/IPv6 sulle porte previste. È output dell'operatore, non accesso agent o ammissione runtime. Il frammento di terminale prima del JSON non cambia il risultato da attribuire: nessuna connessione ai servizi riportata.

Il bundle e7c46c73 usa la rete host. Questo nuovo bundle aggiunge un profilo esplicito per raggiungere ciascun provider attraverso la sua rete privata, senza pubblicare porte, cambiare servizi, usare Docker exec operativo o modificare il database. Collector Go, SQL exporter, proiezioni, riconciliazione e sette hash qualificati restano invariati. Il vecchio archivio e la preparazione già presente sul VPS vanno conservati.

## Input e vincoli

Il profilo host `ouf.storage-g0-package-input.v1` resta compatibile. Il profilo `v2` richiede anche `networkBindingFile`, un file privato0600 dello stesso utente del collector. Nessun fallback su host se manca il binding. `check` valida file, struttura, digest e loopback; non legge /proc, non entra nei namespace e non apre connessioni. Nessun input o template costituisce approvazione HUMAN.

Schema del file rete: `ouf.storage-g0-network-binding.v1`; operationId e installationRef identici al parent; bootId UUID esatto; targets esattamente `minio` e `postgres`. Ogni target contiene containerId e nativeImage uguali ai binding del parent, e process con pid, startTicks, namespaces.net e namespaces.mnt (coppie device/inode positive). PID distinti; nessun processo trovato automaticamente per nome. I riferimenti storici sono candidati, non configurazione corrente assunta: la raccolta confronta ruolo/ID/immagine/PID/running/paused con l'osservazione Docker e controlla le generazioni nel kernel.

Entrambi i profili richiedono identità/ruoli/capacità,17ricevute, quattro connessioni private, bucket owner dichiarati e input operatore del contratto G0. Nel profilo rete tutti gli endpoint devono essere IPv4 loopback letterale; per SQL host=hostaddr, anche con TLS. S3 mantiene TLS oppure HTTP loopback esplicito; PostgreSQL mantiene TLS verify-full oppure disable su loopback. Nessun allentamento per raggiungere IP bridge in chiaro. Non usare gli indirizzi loopback di un namespace diverso o scegliere automaticamente namespace dopo restart.

## Esecuzione

Solo sotto la decisione operativa separata applicabile, il parent conserva claim, budget e input congelati. Dopo HOST_BEFORE verifica il binding di MinIO/PostgreSQL. Ogni child acquisisce pidfd e FD del namespace, controlla boot/startTicks/net/mnt, liveness e associazione pidfd/PID. I FD fissano la rete senza rileggere un pathname al momento del cambio. Un nuovo processo Python isolato entra solo nella rete tramite `os.setns(..., CLONE_NEWNET)`: S3 nella rete MinIO, tre export DB nella rete PostgreSQL. Filesystem/mount e identità restano quelli host; il coordinatore non cambia mai namespace. Il client psql installato sull'host e i file protetti restano raggiungibili. Il programma nsenter disponibile sul VPS non viene usato dal codice operativo.

I controlli di generazione/liveness continuano durante l'attesa del child; reboot, uscita owner, cambio di namespace o binding negano il risultato e bloccano i passi successivi. Nessun replay o rebind. Ogni child lascia prima delle letture una ricevuta `network-entry-*.json`, legata al digest del binding. La query è ancora READ ONLY REPEATABLE READ con limiti originali; non cambia la connessione owner di un'applicazione né concede autorità recovery.

Budget parent900s e130GET Docker invariati, riferimenti17controlli/52GET storici preservati. S3 child massimo310s; SQL mantiene120s interni e watchdog parent125s. Output del worker limitato a8192byte per stream; sessione/process group dedicata, terminazione su timeout/overflow/owner incerto e chiusura dei FD. Non mantenere alcun fence di policy durante queste attese. Non riutilizzare scope consumati dopo un HOLD.

`collect` continua a richiedere un riferimento di decisione, che è sola provenienza: non autentica HUMAN/THS. Questo lavoro non installa endpoint, bean, grant o un verificatore di approvazione. Conservare i gate applicabili e non eseguire collect soltanto perché check riesce.

## Qualifica richiesta e limiti

13regressioni della composizione modificata e14casi del nuovo trasporto; i controlli pidfd reali richiedono Linux root e vengono eseguiti in CI, non simulati come PASS nel workspace privo di /proc accessibile. Prima prova locale:9errori dovuti a /proc non esposto; separati esplicitamente4casi nativi e fixture pura. Risultato locale10PASS/4SKIP più13PASS della composizione; non qualifica nativa.

La nuova fixture usa MinIO legacy esatta e PostgreSQL/PostGIS esatto del precedente run, in due reti none distinte e senza porte pubblicate. Undici container di ruolo vengono creati e mai avviati; non rappresentano servizi applicativi completi. Applica le95migrazioni originali dei commit già qualificati e seed sintetico, poi esegue il pacchetto completo:2corpi/6byte, tre export e join. Prova FD rete scambiato, owner morto mentre il FD resta aperto, replay dello stesso scope, budget e permanenza del parent sulla rete host. È una nuova qualifica della composizione, motivata dalla differenza di trasporto; non ripete l'intera suite precedente o recovery. Prima del PASS e del readback, il candidato resta non qualificato.

Restano fuori: TLS PostgreSQL remoto, semantiche slice/shadow fuori profilo, full services/IdP/UI, autenticazione del census, common-cut, capacità/finestra/custodia target, licenze/sicurezza servizi e approvazione runtime. Nessun dato reale raccolto o copiato; MiniPET39,78%,0/8gate,0/21AT,0/120oggetti reali. La ricevuta pubblicata dopo la CI riporterà esiti effettivi, fallimenti, digest e scadenza; nessun successo anticipato.

Riferimento API Python: https://docs.python.org/3.12/library/os.html#os.setns . Il file HOST_PROFILE.md conserva il contratto precedente; per il trasporto v2 valgono i vincoli di questo README.
