# G0 fermato dal limite host — readback locale

## Evidenza e causa

Il tentativo autorizzato `seaweedfs-g0-20261106-v1` è consumato: HELD, fase HOST_BEFORE, G0_HOST_CONTAINER_LIMIT. Una richiesta Docker di elenco,285226byte,53GET cumulativi; nessun child S3/DB. [Output operatore](../evidence/storage-g0-held-operator-20261106.json). Non è osservazione diretta agent.

La guardia in g0_host.snapshot controlla che la risposta sia una lista non vuota con al massimo64container, includendo quelli fermi. Non controlla soltanto i13ruoli OUF. Il codice di errore non distingue tipo/zero/>64 e il corpo di risposta non viene salvato. Il numero live non è quindi ricavabile dal risultato. Il readback non lo inventa e non ripete la GET.

## Due passi e prossimo dato necessario

1. Registrare scope consumato, contatori ed effetto realmente raggiunto.
2. Leggere e vincolare lo stato conservato, più i soli nomi di directory dei metadati Docker sul filesystem locale.

`scripts/readback-storage-g0-held-20261106.py` usa guard file copiati dal helper capacità qualificato9bfb. Eseguire con sudo /usr/bin/python3 -I -B -S -c sui byte pubblici verificati per SHA256. Nessuna scrittura, directory/scope nuovo, socket, HTTP, SQL o credenziale; il download pubblico del helper avviene separatamente come utente.

Controlla input originale esatto6b5a2ba0, copia con solo decisionRef, decisione e claim collegati, limiti originali, risultato uguale al JSON ricevuto, una sola richiesta /containers/json?all=1 e faseHOST_BEFORE. Richiede l'insieme esatto dei file attesi; confronta quattroconfig e rete congelati, evidenze runtime/capacità e17ricevute. Non apre i file password/accessKey/secretKey referenziati dalle config. Prima del rapporto verifica nuovamente le ricevute. Restituisce soltanto hash e contatori.

Il conteggio in /var/lib/docker/containers è limitato a10000nomi. Non legge config.v2.json o altri contenuti dei container; non segue symlink. Riporta directory con nome64hex, numero di binding OUF presenti, altre entry e completezza. Directory mutata durante la scansione: HOLD. Area assente: ABSENT_NOT_PROOF_OF_DOCKER_ROOT, mai zero inventato. Il rapporto dichiara sempre liveEngineContainerCountProven=false: directory conservate su disco e lista live possono differire e il DockerRootDir effettivo non è dedotto dal solo percorso.

## Vincoli della correzione successiva

Conservare l'inventario completo, inclusi container fuori roster/fermi; non escluderli per aggirare il limite. Dimensionare conteggio, GET,byte e deadline in modo coerente sulla nuova evidenza, senza innalzare indiscriminatamente la soglia. Qualificare il confine e la diagnostica del numero osservato senza riscrivere la storia o alterare il bundle installato.

Il vecchio scope, copie input e claim rimangono intatti. Lo storico17/52 resta storico; il GET consumato porta il cumulativo a53, non autorizza altra lettura. La decisione iniziale era monouso e non include retry. Solo dopo riconciliazione e consegna concreta del profilo corretto si sottopone una nuova operazione distinta al gate applicabile, riportando costi/contatori precedenti. Nessuna authority runtime viene emessa dal readback.

Qualifica locale8test PASS su fixture file/directory, inclusa directory con70ID; zero provider. Inizialmente7PASS, poi aggiunto controllo esplicito dei limiti e relativa regressione,8PASS. Qualifica CI dedicata e SHA256 del comando nella PR54. Non nuovo test di migrazione o credito MiniPET.

L'operatore restituisce solo il JSON redatto. Se HELD, conservare tutto: non modificare i file per far passare il readback. Nessuna correzione operativa consegnata da questo checkpoint; raccolta ancora incompleta, MiniPET39,78%,0/8gate,0/21AT,0/120oggetti migrati.
