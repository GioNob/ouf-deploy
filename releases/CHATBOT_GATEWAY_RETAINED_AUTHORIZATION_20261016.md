# Fase 5: APISIX conservato e verifica autorizzazioni resiliente

Sorgente runtime: `495d46f6ff7320c6d6248438895a52c8dc4c0818`.
Launcher: `scripts/launch-chatbot-gateway-retained-20261016.sh`.

## Stato effettivamente confermato sul VPS

Il readback delle 08:33 CEST conferma APISIX completato: otto passi, container
`733c5bdeca250fba778d431e121120e6653296d84c747552d8f95290ad01e8d9`, zero restart,
due asset numerici in sola lettura. Nessun nuovo worker installato e nessun
nuovo grant: il totale resta otto. Il prossimo effettivo sarà il nono cumulativo.
La chiamata MCP nei log ha status 503, mentre il GET amministrativo ha 200;
il reader non ha inventato né esposto la causa interna del 503.

Le due mappe Gateway sono stabili e corrispondono al prefisso di nove modifiche
conservate; restano 28 modifiche sulle 37 del piano. Le 64 route attualmente
rilette sono l'inventario totale, comprese quelle estranee preservate: non vanno
confuse con le 37 modifiche del piano o con le route della fixture CI.
Fasi tecniche 1–4 acquisite, fase 5 sospesa, 6–8 pendenti; CSV 0/6.

## Cosa fa la prosecuzione

Legge l'intera catena precedente e l'esatto tentativo post-Gateway, compresi
review, decisione, authority, processo spento, stato di pausa, claim già consumato,
autorizzazioni senza effetti e assenza del nuovo worker e di journal applicativi
successivi. La ricevuta di adozione vincola piano, otto effetti e generazione
nativa. L'authority precedente non viene prolungata.

Un nuovo claim distinto è autorizzato soltanto dalla nuova revisione HUMAN.
Il nuovo journal APISIX conserva gli otto effetti, collega la vecchia authority
e porta la nuova authority: apply verifica soltanto la generazione esistente.
Nessun nuovo stop, rename, create, connect o start; nessuna ristadiazione della
configurazione o degli asset. Il vecchio container ritirato resta conservato.
Il duplicato e la revoca bloccano; non si riscrive nessun journal storico.

### Ordine delle dipendenze e prova dei ruoli

MCP è tra le vecchie generazioni quiescenti e viene sostituito nella fase 7.
Il processo iniziale conserva la cache owner dei ruoli osservata prima della
quiescenza; un processo di ripresa ne è privo. Chiamare MCP in questo punto
introduce una dipendenza circolare che il solo retry non risolve.

Il nuovo piano firma `ouf.authorization-retained-role-observation.v1`, vincolato
alla ricevuta owner in before/QUIESCE_PRODUCERS, al suo hash e al roleCatalogueHash
del catalogo già verificato. Un GET fresco della policy owner deve avere identici
policyRef e contentHash; il controllo viene ripetuto durante l'osservazione.
Non si inventa uno snapshot nuovo: OufRoleCatalogueStore.stage pubblica catalogo
e policy nella stessa transazione bloccata di PermissionProposalService.decide,
contratto già usato dalla cache in-process. Fonte owner qualificata:
`GioNob/ouf-source-onboarding@84828f74ac586bae09a78f0fb197b75b1a3d98d1`.
Policy diversa o gara di pubblicazione blocca senza interrogare MCP fermo.
Gli altri controlli di policy, descriptor e OAuth restano letture correnti.
Prima del rilascio dei produttori la cache viene svuotata e una lettura MCP reale
dei ruoli, dopo il suo avvio, è obbligatoria. Nessun ruolo o permesso viene cambiato.

La verifica delle autorizzazioni dopo APISIX e prima del rilascio dei produttori
usa un profilo firmato `ouf.authorization-finite-observation.v1`. Solo le letture
verificate come tali ricevono retry per trasporto e HTTP 408/429/502/503/504:
backoff 5/15/60/300/900, jitter fino al 20%, Retry-After, massimo 128 tentativi e
3600 secondi entro la scadenza HUMAN. Stato e contatori sono persistenti; il lock del journal viene rilasciato
prima dell'attesa di backoff. Il budget include la durata
delle chiamate. Le attese pubblicano motivo sicuro, contatore e prossimo tentativo.
Un crash in ATTEMPTING richiede riconciliazione; rifiuti permanenti, drift, revoca,
cambio di boot, anomalie dell'orologio e budget esaurito non vengono ritentati.
Il numero storico di letture non registrate resta UNKNOWN, senza contatori inventati.

Le scritture non usano questo ciclo: gli esiti ambigui continuano a richiedere
riconciliazione. Le 28 modifiche Gateway richiedono verifica esatta dell'intera
mappa prima e dopo ogni scrittura. Seguono Ingestion, MCP applicativo, verifica
complessiva e rilascio produttori, sempre entro la finestra finita.

Quattro backup COMPLETE riutilizzati con verifica e copia: zero nuovi dump o
restore. Migrazioni MCP COMPLETE/audit CLEAN, UDP e Onboarding restano acquisiti.
Nessun replay delle dieci fasi Registry, nessun primo grant ripetuto. Le decisioni
applicative HUMAN restano nel THS; la procedura non prova il CSV end-to-end.

## Configurazione e ambito

Domini, endpoint, route, issuer, chiavi e reti derivano dalla configurazione e dai
piani già approvati. Il recupero mantiene i pin di questo incidente e l'adattatore
Docker/netns qualificato. Non dichiara qualificazione generale multi-host o
multi-rete e non introduce valori di questo Ente nei default degli installer.

## Verifiche

CI nativa 38865027512 PASS: adozione di otto passi con zero ulteriori operazioni
di ciclo di vita, nove modifiche storiche, 28 scritture residue, mappa completa
esatta nella fixture, claim storico conservato. Revisione completa, otto grant
TLS conservati e nono effettivo, duplicati e revoca bloccati. Comprende anche
sei test di budget e osservazione dei ruoli, tre di custodia/adozione e due di orchestration.
Regressione generale 38865027539 PASS: 484 test in 65 suite, zero errori e zero skip.
Regressione backup 38865028729 PASS. Il launcher è rilasciato con sorgente e SHA256
vincolati; le evidenze CI non modificano lo stato effettivo del VPS.

[Evidenza strutturata](../evidence/chatbot-gateway-retained-authorization-20261016.json).

## Operatore

Usare solo il nuovo launcher, scaricato da un commit preciso e verificato SHA256.
Riutilizza l'archivio già presente e verifica una capsula di 129 membri. Prepara
il documento privato completo prima di APPROVO. Il riepilogo deve dichiarare
APISIX già completato, zero nuovi stop/create/start, fasi 1–4 conservate, otto grant,
28 modifiche residue e una nuova finestra finita. Non ripetere i launcher consumati.
Una sospensione successiva conserva il nuovo stato per riconciliazione.
