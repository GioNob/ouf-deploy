# Runtime variabili e scrittori host — 6 novembre 2026

## Risultato acquisito

[Readback operatore](../evidence/storage-cold-runtime-drift-operator-20261106.json):3output comando,0intenti,0reply,0policy verificate,0gruppi fermati e nessuna directorycapture. Registro coerente con HOLD prima delle mutazioni; non è un probe dello stato live né prova contro la cancellazione di ricevute. Non riportare “tutti i servizi fermi”. Il tentativo rimane consumato.

Tutte le5fonti hanno2entry e medesime dimensioni (1501,1630,1438,1434,1435byte; totale7438). Per ciascuna directory cambiano mtime/ctime; per ciascun file cambiano inode/mtime/ctime e **hash del corpo**. Proprietà/mode/link/dimensione/xattr risultano uguali nel confronto. Non è un semplice falso allarme dei timestamp né l'ordine mount già corretto. Confronto corrente,non snapshot dell'istante del precedente HOLD.

Piano originaleSHA1c0bb62c; derivato0f71ecd23a6e929045c08144a4ce0b878c7a25c87ecaf4e4e50ccc85ee486ea1; claim786b60aa,proposta62b2afd0. Nessun rinnovo,reset,replay o nuova capture.

## Causa di progetto individuata e limiti

Il backup ha applicato l'identità immutabile delle fonti anche a directory runtime che possono ospitare credenziali rinnovabili. Il rosterDocker e restart=no non contengono gli eventuali scrittori host. Prima di aggiornare il piano occorre distinguere questi input e completare il contenimento; un semplice rebind dei nuovi hash rischia lo stesso errore al rinnovo successivo.

Precedente già disponibile: [contratto token rinnovabile V11](../releases/RETAINED_V11_RENEWABLE_TOKEN_CONTRACT_REVIEW_20261012.md). Descrive l'errore di modellazione e la sostituzione atomica prevista solo sotto contratto esplicito; non autorizza ad allentare gli invarianti. [Review consumer13ottobre](../evidence/policy-token-consumer-review-target-20261013.json) osservava timerGateway,Ingestion,OnboardingIdentity attivi. Quelle osservazioni NON sono stato corrente.

La sorgente esatta GioNob/ouf-semantic-registry@b87c8291c791a6ab0f75ece6e595b49330ac3681:scripts/r4a_onboarding_token_runtime.py (SHA7cd1969f già documentato) definisce il servizio/timer ouf-onboarding-identity-token,output directory /run/ouf-onboarding-identity e pubblicazione con os.replace. SHA256 di quel percorso coincide con630028add258dae74151a71fc4e08e655c8a022f28b8b17a72e55f670c0f5c45 della fonte corrente. È un collegamento esatto al percorso e a un writer noto,non prova dei byte attualmente installati o del processo che ha scritto gli altri4file. Non attribuire automaticamente tutti5cambi a token validi o a rinnovi leciti.

## Prossima lettura raggruppata

scripts/read-storage-runtime-writers-20261106.py,8871byte,SHA3d1f998c4634a12c9b4fe1bb659df39d7df69f60ae81816e3f2041e55ad1b636. Pinning del driver e delle dipendenze già installate; piano originale esatto. Nessun confronto runtime già riuscito ripetuto e nessuna lettura dei corpi delle credenziali.

Massimo3comandi systemctl di sola lettura: list-unit-files,list-units(all),show; filtro ouf-*token*.service/timer,max32unit,1MiBstdout per comando,10s ciascuno,60s budget lettura. Non interrogare nomi storici assenti; segnalarli senza assumere assenza di altri writer. Report stati/associazioni cardinalità preservata; ExecStart e ReadWritePaths restano interni.

Legge solo candidati script.py/.sh sotto /opt/ouf,/var/lib/ouf- o /var/lib/ouf,con lettore protetto nofollow,max16file*256KiB; nessun codice sorgente eseguito. Se custodia non conforme o fonte assente,riporta indisponibilità,non allenta la guardia. Esporta soltanto corrispondenze letterali ai5percorsi già vincolati,non percorsi,argomenti,environment o sorgenti. Un literal non prova il flusso effettivo di scrittura; nome unità non è censimento completo. Nessun IAM/grant/Docker/start/stop/restart/mask/disable/file scritto oauthority.

Controlli locali puri PASS su parsing unità,percorso esatto vs prefisso simile,conservazione proprietà ripetute e rifiutoIDduplicato. Non qualifica nativa o esecuzione target. Non ripetere i test di stop/capture riusciti.

## Uscita utile per la migrazione

Il risultato deve permettere di preparare un contenimento preciso dei writer host rilevanti,poi una fotografia stabile e una nuova operazione governata collegata al tentativo consumato. Non viene qui aggiunta una mutazione systemd all'autorizzazione precedente35policy/14servizi. Nessun arresto generico di unitàtoken,nessun rinnovo IAM per risolvere il backup. Il token eventualmente salvato resta dato di recupero,mai autorità corrente dopo restore.

Questa è una dipendenza concreta della prima copia G3/G4,non un filone autonomo IAM/DR. MiniPET18,3/46=39,78%,0gate/0AT/0migrati;120corpi verificati. Nessun credito o passaggio operativo nuovo.
