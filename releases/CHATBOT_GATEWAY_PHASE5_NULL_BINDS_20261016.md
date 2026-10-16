# Fase 5: correzione della preparazione con Binds null

Sorgente: `5d9c9b6b944e71b25cd006994c511397295b4f4f`.
Questo launcher sostituisce quello pubblicato in `add1a8a53216ce35f1f8ece08b110417f5f8ec66`.

Il VPS si è fermato in preparazione prima della revisione HUMAN, senza nuova
runtime authority, dopo il controllo dello storico con otto grant conservati.
Il difetto era `.append()` su `HostConfig.Binds=null`: il test Docker precedente
usava `-v`, mentre la rappresentazione `--mount` usa `HostConfig.Mounts` e può
lasciare `Binds` nullo. La riproduzione locale fallisce nello stesso punto prima
della correzione. La nuova richiesta materializza una lista vuota soltanto per
aggiungere i due asset; identità storica, campi e montaggi esistenti restano esatti.

## Qualificazione della correzione

- 28 test runtime superati, due verifiche native saltate solo nell'ambiente locale.
- 14 test delivery superati; tutti i 128 membri della capsula verificati.
- CI nativa 38860719163 PASS: Docker reale con Binds nullo, sostituzione APISIX,
  nove effetti conservati, 28 scritture residue e 37 route esatte; storico grant
  conservato e nono grant nella fixture TLS, revoca e ripetizioni bloccate.
- Regressione backup 38860719021 PASS.
- Regressione generale 38860719114 ancora in corso alla pubblicazione. I 473 test
  verdi della precedente release riguardavano il sorgente aeeb625; non sono
  presentati come risultato di questa nuova esecuzione.

[Evidenza strutturata](../evidence/chatbot-gateway-phase5-null-binds-20261016.json).

## Ripresa sul VPS

Usare soltanto `scripts/launch-chatbot-gateway-phase5-null-binds-20261016.sh`, con
commit e SHA256 verificati. Scarica il delivery dal sorgente qualificato sopra;
riutilizza l'archivio originale e prepara una capsula privata nuova. Non ripetere
il launcher precedente; non cancellare lo staging del tentativo fallito.

Rimangono gli stessi vincoli della [procedura di fase 5](CHATBOT_GATEWAY_PHASE5_CONTINUATION_20261016.md):
quattro backup riutilizzati senza dump/restore, migrazioni MCP CLEAN acquisite,
nessun replay Registry o sostituzione UDP/Onboarding. Otto grant cumulativi
conservati, prossimo effettivo nono. Revisione completa prima di APPROVO,
nuova finestra finita 128 tentativi/3600 secondi senza rinnovo automatico.
La sostituzione Gateway comporta una breve interruzione; poi il piano comprende
Ingestion, MCP applicativo e verifica complessiva. Le decisioni HUMAN applicative
restano in THS. Ambiguità, drift e revoca fermano l'esecuzione senza replay.

Domini, endpoint, route e rete restano quelli della configurazione approvata.
I pin di questo recupero sono specifici all'installazione conservata e non sono
default per altri Enti. Non viene dichiarata qualificazione multi-host/multi-rete.

Stato target: fasi 1–4 acquisite; fase 5 ancora da eseguire; fasi 6–8 pendenti;
dimostrazione CSV 0/6. Le prove CI non modificano tale stato.
