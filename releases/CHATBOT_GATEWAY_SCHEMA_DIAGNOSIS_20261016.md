# Fase 5/8: schema APISIX, causa riprodotta e verifica mirata

## Stato target confermato

La diagnosi operatore del 16 ottobre 2026, 05:04 Europe/Rome, è completa:
quattro backup COMPLETE, MCP 12 migrazioni/CLEAN, UDP 35 e Onboarding 34
migrazioni attese, entrambe le generazioni running/restart 0. La readiness
corrente non è riprovata. Registry conserva dieci effetti. Otto grant cumulativi,
worker CANCELLED, admission BLOCKED. CSV 0/6, nessuna accettazione permanente.

Gateway: nove modifiche APPLIED su 37, decima CLAIMED. Due GET identiche
alla mappa prima del claim, route assente, zero differenze estranee.
Il suo hash ID corrisponde alla route pubblica `mcp-managed-file-review-prepare`.
[Readback target](../evidence/chatbot-gateway-target-readback-20261016.json).
Assenza osservata non prova la storia di un effetto né autorizza replay della PUT.
L'ACK originario non è conservato; la causa sul VPS resta da legare ai bytes e
all'immagine attuali, senza inventare una risposta HTTP storica.

## Riproduzione nativa e correzione parziale

CI `38844107608`, job `116790586582`, sorgente deploy
`02413079de9eba98119096dc9d327274c073aa94`: APISIX 3.18.0-debian ed etcd reali,
37 route prodotte dai materializzatori del pacchetto originale Gateway
`bf179e96200deb84942ad32507edef52a4284cd0`, input/credenziali esclusivamente sintetici.
Trentasei PUT vengono accettate; la decima, esattamente quella assente sul VPS,
restituisce HTTP 400: il plugin request-validation rifiuta il `$id` URN annidato
`urn:ouf:managed-file-execution-proposal:lexical-csv:v1`.

Il candidato Gateway `f0d11909f8dce34811036800944ed4c6665d1972`, ramo
`fix/phase5-apisix-schema-projection-20261016`, proietta solo quello schema per
APISIX eliminando quel solo metadato quando non esistono riferimenti. Rifiuta
`$ref`, `$dynamicRef`, `$recursiveRef` o un identificatore diverso. Il contratto
canonico non cambia, nessun vincolo di validazione viene rimosso. Quattordici
test mirati passati; CI Gateway `38844320835` e `38844320766` success.

CI nativa candidata `38844842784`, job `116792910278`, deploy
`16adcd7eed08b526c24018536109bfcc18f7b5d0`: tutte le 37 PUT sono accettate, ma
solo 34 hanno GET identica. Le tre route review-prepare, semantic-proposal-review
e semantic-proposal-validate alterano il massimo della versione da
9007199254740991 a 9007199254741000.0. Non è una semplice differenza di tipo.
Il confronto esatto ha correttamente segnalato un vincolo numerico alterato.
**Il candidato non è pronto per apply.** Non abbassare/arrotodare i limiti,
ignorare campi o introdurre tolleranza numerica per aggirare questo gate.
Va preservata la semantica contrattuale e verificato anche il payload applicativo
al bordo del range, prima di pubblicare una nuova intenzione governata.

Immagine CI: `apache/apisix@sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d`,
config image ID `sha256:b6fd21b8c341f3bf274ddabbad2e3c1bbb6a17566f0e41bf618166e63e4641e4`.
I backend della fixture non ricevono traffico: questa è prova di accettazione e
rilettura Admin API, non prova CSV o di autorizzazione applicativa.
La prima prova CI `38844024763` si era fermata prima delle route per la rete
Docker interna senza port publication; `38844107608` ha corretto la fixture.
[Evidenza CI e limiti](../evidence/chatbot-gateway-schema-reproduction-20261016.json).

## Prossima lettura VPS, nessun DB o archivio

Script `scripts/read-chatbot-gateway-schema-20261016.py`, sorgente
`16adcd7eed08b526c24018536109bfcc18f7b5d0`, SHA256
`ca6ae2d3e8691e9ca61082f2e7eb9fa5dfbd8f4ea733802c4971f2d95a1d590d`.
Launcher `scripts/launch-chatbot-gateway-schema-20261016.sh`, SHA256
`e6958d0cfe03eb2fb2023e7423e82a31cc81480aba78d69409c59ae556554ece`.

Vincoli: stesso contesto/review/authority storici, processo delivery fermo,
journal Gateway esatto `9d1c903c6290dca22c28c601ccfda33f440d06f6079ff7e7d104584c99b6a515`,
worker cancellato con otto grant e admission BLOCKED. L'autorità storica è
letta come evidenza, non esercitata. Nessun rinnovo/reset, IAM, grant,
DB/SQL, dump o lettura archivi; nessun create/start/stop o pubblicazione.

Massimo 120 secondi e due GET Gateway; guarda identità/custody prima e dopo,
rilegge i record per rilevare concorrenza. Stampa hash degli schemi, confronto
con l'URN pubblico, presenza di riferimenti, verifica dei limiti pubblici e
image ID. Nessuno schema, URL, nome privato o segreto viene stampato.
Il confronto e la proiezione sono in memoria; non modificano il piano custodito.
Il trasporto resta quello locale qualificato dell'incidente, non un default per
installazioni distribuite. AGENTS.md conserva il requisito di profili/bootstrap
per Ente, route approvate e confini PET; la policy resilienza v3 resta vincolante.

CI reader `38844842741`, job `116792910398`: 16 test senza errori o skip.
Quattro nuovi test coprono flusso completo con record privati, concorrenza,
redazione, assenza di DB/archivi e identità AST dei helper GET/custody rispetto
al reader qualificato. I dodici test precedenti includono namespace GET e
PostgreSQL reali; il nuovo reader non chiama PostgreSQL.

Dopo l'output: legare la riproduzione all'immagine/schema target, risolvere la
precisione numerica senza indebolire il contratto, conservare ACK diagnostico
nelle future mutazioni, qualificare una prosecuzione che mantenga nove effetti
Gateway e dieci effetti container/Registry senza replay. Solo allora preparare
una nuova revisione finita concreta per i passi ancora necessari. Nessun
launcher runtime precedente è riutilizzabile; fase 1 e migrazione MCP non si
ripetono. I backup restano quelli conservati; nessun restore.
