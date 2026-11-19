# Diagnosi dello start Ingestion ambiguo

Fasi 1–5 completate e conservate; fase 6/8 sospesa, CSV 0/6.
Il runtime f6078a5ac07853b4abc13d310882f5a30086baba ha superato il preflight
ed è stato approvato nella review 62c8837120f9079cbf2dd026105ccce7befbbbfbbd09b1c67fc813e6a468f91e.
L'autorità b6335ae592c469d253a345c29352a6fe2180e1297a29146b98bf1048016b4fe4
ha raggiunto lo start Ingestion; il controllo della risposta Docker 204 ha
fermato il processo con COHORT_START_REQUIRES_RECONCILIATION. Il corpo della
risposta non è conservato: non è provato se l'effetto sia avvenuto.

Il lettore f7252c1a33694b6760bb9c35e94db53e481a8666 è specifico dell'incidente.
Vincola review, autorità, sorgente, processo fermo, bundle privato e container
cbf3067d946cf21a8f4abbb03ed47a217f2f39624ed1a5fb23a642325129ee35.
Richiede journal ordinato con 12 effetti APPLIED e ingestion.start CLAIMED,
ricontrolla ogni intento e hash delle evidenze, e confronta l'identità fisica
con l'evidenza create. Legge l'eventuale State.Error di Docker e pubblica
soltanto categorie fisse e lunghezza, senza messaggio, percorsi o valori.
Un errore vuoto non è una prova di start riuscito; una categoria non dimostra
il codice HTTP storico, che rimane indisponibile.

Legge metadati del nuovo worker, del journal backup/migrazioni e delle quattro
generazioni applicative; verifica due mappe Gateway complete e identiche al
piano. Nessun nuovo dump, accesso DB/IAM/MCP, grant, log applicativo o scrittura
Gateway/container. Custodia, trasporto di lettura e namespace sono gli stessi
del lettore già qualificato, copiati senza modifiche. Domini/bindings provengono
dai piani approvati; le costanti dell'incidente non sono default installativi.

Massimo 180 secondi, due letture Gateway, limiti di byte/timeout per lettura,
nessun retry o reset dei budget. Non riconcilia journal né emette autorità,
non avvia container e non modifica checkpoint. A fine lettura riverifica
record e generazioni; un cambiamento impedisce la conclusione positiva.

Locale: 34 test, 32 PASS e due prove native rinviate alla CI. Otto test nuovi
coprono il percorso completo, il claim specifico, l'identità create, deriva
dei record e redazione dei messaggi. Nessuna prova CI avanza il VPS.

CI 38880646317, job 116906283698: PASS, 34 test senza skip, incluse le due prove native namespace/PostgreSQL del lettore ereditato. Il nuovo main non chiama PostgreSQL. Le nuove otto prove usano file privati reali e osservazioni Engine/Gateway simulate; le funzioni di trasporto e custodia sono confrontate per AST con quelle native già qualificate.

Reader SHA256: 9cbe7efbb94c20dbbdff427d7b0874b1dcbe647a1b49e1f5146f7fcd8528630e.
Launcher SHA256: f444139d49d9a532babb86b3fde1252fa01d4a9ecc38c4ed990df9fc5ae7b9cc.
