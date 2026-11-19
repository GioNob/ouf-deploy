# SeaweedFS — adapter Raft bbolt locale

Stato: sviluppo e prove locali, nuova immagine non qualificata.

La generazione 29 importa `github.com/hashicorp/raft-boltdb/v2@v2.4.2`, che usa
già `go.etcd.io/bbolt@v1.5.0` per gli store attivi. Il solo helper esportato
`MigrateToV2`, mai chiamato da SeaweedFS, importa ancora il progetto archiviato
`github.com/boltdb/bolt@v1.3.1`. La release upstream più recente osservata il
3 novembre 2026 è ancora v2.4.2; non viene inventato un aggiornamento risolutivo.

L'adapter `weed/util/raftstore` deriva dai sorgenti esatti di quella release:
conserva operazioni attive, nomi bucket `logs`/`conf`, chiavi big-endian,
MessagePack, opzioni e default fsync, metriche e interfacce Raft. Sono omessi
solo il vecchio helper di conversione, i suoi import e il suo test. Il server
cambia un import. Nessuna conversione o migrazione del formato DB è eseguita.

`metrics.go`, `util.go` e `LICENSE` sono copie byte per byte; gli header MPL-2.0
e copyright originali sono conservati. `UPSTREAM.md` registra gli hash degli
input. OUF assume la manutenzione e review di questa piccola derivazione:
non la presenta come release upstream e deve conservare il sorgente MPL nel
nuovo pacchetto di consegna/licenze. La review legale resta separata.

Due delta sono consegnati separatamente per consentire l'integrazione ordinata:

- `4.52-raft-bbolt-local-store.patch`: adapter, attribuzione, test e import server.
- `4.52-raft-bbolt-module-closure.patch`: rimozione dei due requirement inutili,
  promozione dei tre moduli già presenti a import diretti e rimozione di sei
  checksum legacy ormai inutilizzati. Nessuna versione mantenuta cambia.

Il grafo produttivo è confrontato con gli stessi Go 1.27.3, linux/amd64 e
CGO=0 della generazione 29: **1.811 → 1.810 pacchetti**. Escono esattamente
`github.com/boltdb/bolt` e `github.com/hashicorp/raft-boltdb/v2`; entra soltanto
`github.com/seaweedfs/seaweedfs/weed/util/raftstore`. Il primo conteggio esplorativo
usava CGO predefinito e non è usato per il confronto o la qualifica.

## Prove

I 12 test upstream delle operazioni ancora esposte passano sull'adapter locale.
I 12 esiti dei test server Raft selezionati (inclusi sottocasi) passano con
CGO=0. La prova server estesa esplorativa registra 969 PASS, due skip e un FAIL:
`TestBuildGuardedRemoteStorageClient` richiede risoluzione DNS Google, negata
dal sandbox. La stessa failure è stata riprodotta sulla baseline 29 immutata;
la suite estesa non viene dichiarata PASS. Sono conservati tutti gli esiti
terminali e il messaggio dell'errore; hash/dimensione identificano anche il log
completo locale, che non è ripubblicato integralmente.
Il comparatore separato esegue tre ulteriori test su file DB reali:

1. Scrive con il vecchio adapter v2, copia il DB, legge e modifica la copia
   con quello locale, tronca/sostituisce un suffisso del log e persiste il
   termine; riapre con il vecchio v2 e confronta. L'originale resta immutato.
2. Scrive con il locale e legge con il vecchio v2; riapertura locale read-only,
   scrittura negata e hash del file invariato.
3. Conferma che nessuno dei due implementa `raft.MonotonicLogStore`: non si
   introduce una promessa più forte rispetto allo store upstream. Ordering
   Raft e decisioni sui termini rimangono responsabilità del protocollo Raft.

Log, term, tipo, dati binari, extensions, timestamp, current term e voto sono
confrontati. Il comparatore importa l'adapter precedente e quindi Bolt legacy
**solo in un modulo temporaneo esterno**: ciò non rientra nel candidato.
`qualify-seaweedfs-raftstore-compat.py` verifica h1 degli oracle, mantiene tutti
i pin del candidato, controlla che go.mod/go.sum sorgenti rimangano immutati,
ha deadline finita e non introduce retry. Non esegue conversioni automatiche.

Le prove riguardano chiusura e riapertura ordinata; non simulano perdita di
alimentazione, crash durante fsync, upgrade di un cluster attivo o dati target.
Servono ancora suite integrata della generazione risultante, tidy completo,
nuovo binario/immagine, SBOM/scansione, provenienza, licenze e laboratori. La
qualifica dell'immagine 29 non viene trasferita al nuovo binario. Non è una
dichiarazione che tutti gli altri moduli siano mantenuti.

Fonti primarie: [release v2.4.2](https://github.com/hashicorp/raft-boltdb/releases/tag/v2.4.2)
e sorgenti verificati nel module cache con h1 già fissato. MiniPET/PET e policy
resilienza restano applicabili. Nessuna operazione target, deploy, merge,
ammissione release o nuova autorità; MinIO, Scope17/52, Teatri/M1 e Farmacie
restano invariati.
