# Rotazione credenziali S3 — fixture33, 2026-11-04

## Contratto della prova

Una sola identità applicativa e la stessa policy prefix-scoped, con chiavi sintetiche pubbliche: OLD → OLD+NEW → NEW → riavvio NEW. L'identità bootstrap è invariata e non è il soggetto della rotazione. Si sostituisce solo il gateway S3, fermando/rimuovendo il precedente prima di avviare il successivo; master, volume e filer devono mantenere ID, StartedAt e RestartCount. Certificato e CA TLS restano identici, con verifica hostname e fingerprint su ogni richiesta.

Un solo seed iniziale: creazione bucket e oggetto binario. Prima della rotazione NEW deve essere rifiutata; durante overlap entrambe leggono gli stessi byte con GET/HEAD/LIST completo. Dopo revoca OLD deve ricevere HTTP403 InvalidAccessKeyId su GET, LIST, PUT nuovo, overwrite e DELETE; HEAD richiede HTTP403 e corpo vuoto, senza inventare un codice XML assente. NEW deve scrivere una sola volta un secondo oggetto, rileggerlo e conservare il precedente; DELETE e PUT fuori prefisso restano AccessDenied, secret errato SignatureDoesNotMatch. Dopo ulteriore restart tutti i dinieghi e le letture devono essere identici, senza ripetere seed o scrittura NEW.

Sette container distinti complessivi, massimo quattro simultanei, un solo gateway attivo; tre sostituzioni bounded. Nessun retry mutativo. Il solo materiale credenziale salvato nelle evidenze è pubblico e sintetico; il workflow rifiuta chiavi private TLS.

## Verifica

22 test locali PASS: 12 nuovi e 10 regressioni TLS esistenti. Esito nativo PASS sul workflow dedicato, legato al lock/coorte/OCI33 esatti; archivio originale verificato. Gli altri cinque scenari storage già verificati restano al checkpoint320827d2, senza trasferire il loro risultato a questo nuovo test.

## Esito nativo e rilettura

- Producer `69680f3e2ca42515110ac3d6ee4f6b1b27dd5415`; [run 41811147933](https://github.com/GioNob/ouf-deploy/actions/runs/41811147933), job `126510424981` SUCCESS, artifact `13311548597`. Tutti i 22 test hosted PASS.
- OLD → OLD+NEW → NEW → restart NEW riuscito. Durante overlap entrambe le chiavi leggono lo stesso oggetto; dopo revoca OLD fallisce sui sei percorsi previsti prima e dopo il riavvio. HEAD restituisce solo HTTP403/corpo vuoto; i cinque altri percorsi restituiscono InvalidAccessKeyId. NEW conserva i dinieghi di policy e di secret errato.
- 19 dinieghi complessivi: 11 InvalidAccessKeyId (inclusa NEW non ancora introdotta), due HEAD403 senza codice XML, quattro AccessDenied e due SignatureDoesNotMatch. Due PUT oggetto riusciti in totale (seed OLD e prova NEW) più una creazione bucket; zero retry mutativi e nessun reseed dopo restart.
- Oggetto iniziale di 50 byte conservato; secondo oggetto NEW di 41 byte, totale 91 byte finali con GET/HEAD, MIME e LIST completo. Certificato identico in tutti gli stadi. Sette ID container distinti e sette arresti puliti; master/volume/filer mantengono ID, StartedAt e RestartCount, massimo quattro container simultanei e un solo gateway.
- Quattro configurazioni effettive fixture confrontate con la sorgente: cambiano soltanto le credenziali dell'identità applicativa, owner e policy restano identici. Nessuna chiave privata TLS nell'evidence.
- ZIP originale [storage-credential-rotation33-41811147933.zip](../evidence/artifacts/storage-credential-rotation33-41811147933.zip), 68148 byte, SHA256 `756dc24c3b8d3d88723a56791af3c6b7cb80fcbad6a8615de4ff4ff19fe0349c`; verificati 46 membri, 45 checksum e 15 sorgenti esatte. [Receipt di rilettura](../evidence/storage-credential-rotation33-readback-20261104.json).
- La rilettura locale verifica originali, configurazioni, identità dei processi e report hosted; nessuna seconda esecuzione nativa locale o verifica crittografica locale della firma publisher dichiarata. Il publisher della coorte è verificato hosted con source commit esatto.

## Prossimo singolo passo

Isolamento laterale dei ruoli SeaweedFS nel laboratorio: definire e verificare i soli collegamenti necessari e i dinieghi nativi tra ruoli. La namespace loopback condivisa delle prove attuali non equivale a tale isolamento. Nessun cambiamento target; passo ancora non eseguito.

## Limiti e avanzamento

Non è hot reload, zero downtime, rotazione owner/admin, STS/session token, test di richieste in-flight o custodia segreti produttivi. Le chiavi sono fixture dichiarate pubbliche; nessun segreto target, VPS o servizio reale viene modificato. Non prova revoca su gateway multipli, né ammissione target. MiniPET invariato 18,3/46, circa40% ±10; 0/8 gate, 0/21 AT, 0/120 oggetti reali.
