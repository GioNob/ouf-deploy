# SeaweedFS — httpdown senza clock/stats archiviati

L'adapter HTTP locale già presente in SeaweedFS usava soltanto i timer di
`facebookgo/clock` e tre operazioni di `facebookgo/stats`. Entrambi i repository
canonici sono archiviati. Il lotto usa `time.NewTicker`, `time.After` e
`time.NewTimer` della libreria standard e una piccola interfaccia locale
`Stats`: BumpAvg, BumpSum e BumpTime. Un client che soddisfaceva la precedente
interfaccia Stats resta assegnabile alla nuova; non sono ricopiati framework,
prefix client, histogram o clock simulato.

Il campo Go **HTTP.Clock viene rimosso**: è un cambiamento esplicito dell'API
del package locale, non una promessa di compatibilità per una libreria esterna.
La scansione dell'intero repository non trova assegnazioni di quel campo nei
caller; i due usi di `httpdown.HTTP` in volume.go rimangono invariati e i caller
`weed/command` sono compilati nella prova locale. Non cambiano API HTTP, TLS,
porte, listener o configurazioni volume.

## Timer e correzione di una race preesistente

Zero mantiene il default di un minuto per ciascuna fase. I valori espliciti
restano identici, compresi 30 secondi/un minuto per il cluster e cinque minuti
per fase per l'endpoint pubblico. Le durate negative continuano a scadere
immediatamente, senza diventare attese infinite. Il ticker periodico viene
fermato anche quando il manager termina.

Un test nuovo ha esposto una race esistente: su server già drenato e timeout
immediato, il select poteva scegliere il timer dopo che il manager aveva chiuso
il canale kill, causando `send on closed channel`. La stessa panic è stata
riprodotta copiando il file originale generazione 29 e usando le vecchie
dipendenze, senza la modifica stdlib. Entrambe le prove negative sono conservate.

I canali di controllo stop/kill non sono più chiusi dal manager. La pubblicazione
del kill seleziona anche il completamento del drain e il timeout della fase;
quest'ultimo comprende ora anche l'attesa per consegnare il comando al manager.
I callback ConnState, il manager delle connessioni e i percorsi Serve/ServeTLS
sono conservati. Non viene sostituita la logica con un nuovo framework shutdown.

I budget delle fasi non possono interrompere implementazioni arbitrarie che
blocchino in Listener.Close, Conn.Close, Stats o ConnState. Tali callback devono
ritornare prontamente, come richiede l'uso corrente con listener TCP. Al termine
del kill budget l'adapter può rinunciare anche se un Close custom non termina:
non si dichiara da questo un endpoint healthy o una chiusura target completa.

## Prove locali e dipendenze

Con Go 1.27.3 linux/amd64 CGO=0: **13 esiti PASS** (10 test principali e tre
sottocasi), incluso un loop di 100 arresti immediati. Il race detector con
CGO=1 ripete tre volte gli stessi casi: **39 esiti PASS**, nessun DATA RACE.
Sono usati TCP/HTTP reali su loopback e TLS con CA fixture verificata:

- richiesta in corso completata durante il drain e rifiuto di nuovi accept;
- timeout di grace, chiusura TCP forzata e cancellazione del request context;
- connessione idle chiusa, callback ConnState inoltrato e connessione nuova
  senza richiesta chiusa al termine della grace;
- 16 Stop concorrenti e ulteriori Stop idempotenti;
- default/configurazioni/durate negative, pubblicazione kill senza manager
  limitata dal proprio budget e statistiche opzionali senza client esterno;
- percorso TLS GetCertificate utilizzato, risposta letta e arresto ordinato.

`weed/command` compila con `-run '^$'`: è prova di compilazione dei caller,
non esecuzione della suite command. Il grafo produttivo esatto passa da
**1.811 a 1.809 pacchetti**: escono solo facebookgo/clock e facebookgo/stats,
nessun nuovo pacchetto entra. Due requirement e quattro checksum sono rimossi;
nessuna versione mantenuta cambia. Code patch e module patch sono separate
per l'integrazione ordinata con gli altri fronti.

La riapplicazione sul sorgente 29 riproduce byte per byte i cinque file cambiati.
Rimangono necessarie suite integrata, tidy completo, nuovo binario/immagine,
scansione/SBOM/provenienza/licenze e collaudi della generazione combinata. Le
qualifiche hosted 29 non vengono trasferite automaticamente. Nessuna promessa
che tutti gli altri progetti archiviati siano stati rimossi.

Nessuna operazione target, merge o deploy. MinIO resta attivo; Scope17/52,
Teatri/M1 e Farmacie rimangono invariati.
