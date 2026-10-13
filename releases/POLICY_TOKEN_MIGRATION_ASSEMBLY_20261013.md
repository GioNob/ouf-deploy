# Migrazione policy-token: osservazione consumer e moduli assemblati

## Evidenza target acquisita alle 20:32 CEST

[Ricevuta operatore](../evidence/policy-token-consumer-review-target-20261013.json): quattro sorgenti e una configurazione letti, nove letture systemctl concluse, una evidenza privata `603a7e11a9e3d5c444accd4f198d30cb721a5f816a4b00d7d200cadde068c325`. Nessun altro nome di unità corrisponde al selector osservato. I quattro timer sono active/waiting/enabled; i servizi erano inactive/dead. Non è quiescenza e non è prova di assenza di consumer fuori dal selector.

| Writer | Osservazione sul client | Revisione del sorgente |
| --- | --- | --- |
| Semantic | Client selezionato presente nel codice/configurazione osservati | Hash identico al file repository revisionato |
| Gateway | Un identificativo statico diverso | La sola osservazione statica non prova il data flow effettivo |
| Ingestion | Un identificativo statico diverso | La sola osservazione statica non prova il data flow effettivo |
| Onboarding | Un identificativo statico diverso | Hash identico al file repository revisionato |

Semantic: `GioNob/ouf-api-gateway`, commit `5bdb36f3980a5b33fbce0a9bfe2c2cb64393e63a`, `ops/policy_token/refresh_policy_token.py`, SHA256 `728b4c44d0e24b3c3bfc31769346c0c05752e870e93c096fac1c2897250e5c79`. La revisione del codice mostra `required("OUF_POLICY_TOKEN_CLIENT_ID") → config()["client_id"] → form["client_id"]`. Il `Subscript` rimasto irrisolto nel parser generico è questo accesso al dizionario, non un secondo client scoperto. Il codice seleziona anche l'endpoint dalla configurazione: `staticIssuerMatchesRetained=false` non dimostra issuer diverso. La configurazione corrente andrà vincolata nel percorso operativo completo; questa revisione non promuove il report a prova runtime.

Onboarding: `GioNob/ouf-semantic-registry`, commit `b87c8291c791a6ab0f75ece6e595b49330ac3681`, `scripts/r4a_onboarding_token_runtime.py`, SHA256 `7cd1969fa0773da3243c4d6aeac033e81e90788658dbaccba0440bccbb4bbbd7`. Il sorgente usa la costante CLIENT nel Basic authentication; la corrispondenza dei byte è distinta dalla prova di esecuzione corrente.

Il report indica ancestry non interamente root-controlled per i tre sorgenti sotto /opt/ouf, mentre configurazione semantic e sorgente onboarding risultano root-controlled nell'osservazione. Non attribuire `observationHasFindings=false` al superamento della custody: il campo riassume i problemi della raccolta, non l'accettazione dei controlli di sicurezza. Non adottare i vecchi sorgenti o la credenziale come se fossero già custoditi.

## Raccolta immutabile dei componenti

È stato assemblato [il capsule dei 29 moduli](policy-token-migration-component-capsule-20261013.json), riusando il loader chiuso esistente. SHA256 `6f97e4b49a9d47b5d277b49be7d3037326fcb40045b664c5e4a17af8e31bbac7`, declaration hash `aa3021e579308a85fdc7970928b6d79ee1598d9c01059493ec03f864868c5bd5`. [Ricevuta di assemblaggio](../evidence/policy-token-migration-component-capsule-assembled-20261013.json).

I byte dei 29 moduli e del loader coincidono con i 30 blob Git del commit `c33d39c6922fbcd87a853c8b9f12e6bbb193e22a`. I componenti a quel commit hanno CI riuscite `38446909989` e `38446909986`. Il capsule effettivamente prodotto è stato caricato da memoria in un processo `-I -B -S`, ottenendo l'entrypoint `first_controlled_grant`; nessun suo metodo operativo è stato invocato.

Questo file è una confezione immutabile dei componenti esistenti, **non un launcher da eseguire sul VPS e non l'installer completo**. Non introduce un servizio o un framework. Non riutilizza l'autorità del precedente apply IAM: quell'azione rimane APPLIED_RECONCILED e consumata.

## Integrazione ancora da chiudere

Il prossimo lavoro è il collegamento di preparazione e consegna governata ai componenti già disponibili. Va completato prima di chiedere approvazioni operative: revisione corrente della configurazione e del perimetro dei consumer, identità dell'output, binding IAM/TLS/host richiesti, e autorità HUMAN di esecuzione riferita a questi byte e agli effetti esatti. Le tre radici sono state create con la consegna descritta sotto: riutilizzare le identità registrate, senza ricrearle e senza usare il vecchio worker con una storia azzerata.

La sequenza già implementata nei componenti è retirement semantic → credenziale → primo grant/introspezione/pubblicazione, con le riserve durevoli esistenti. La creazione delle radici ha un componente separato già qualificato; manca il collegamento completo di questa sequenza alla consegna/signing dell'installer. La storia legacy rimane UNKNOWN/null, il gap OPEN e il primo budget proposto resta uno/300 secondi; nessun rinnovo implicito o replay R12.

Non rieseguire la raccolta consumer: riutilizzare l'evidenza appena acquisita. Gli eventuali controlli correnti necessari a un'azione appartengono al flusso operativo completo, con diagnosi nello stesso comando. Nessun nuovo comando VPS è richiesto dall'assemblaggio di questo capsule.

## Consegna operativa successiva

La creazione governata delle radici è stata eseguita: [ricevuta target dell'operatore](../evidence/policy-token-root-custody-target-20261013.json), stato `ROOTS_CUSTODIED_NOT_RUNTIME_ACCEPTED`, sei directory create, tre radici root:root0700, due firme, nessuna mutazione IAM o dei servizi e nessun grant. Il claim è consumato. [La consegna precedente](POLICY_TOKEN_ROOT_DELIVERY_20261013.md) è storica: non ripeterla. La ricevuta è riferita dall'operatore; non costituisce una rilettura indipendente da questo ambiente.

`migration_root_custody.completed_roots()` riutilizza il ledger completato tramite hash esatto, confronto dei percorsi e delle identità, ancestry e file descriptor aperti. La scadenza del budget della vecchia creazione non cancella la custodia delle directory e non viene rinnovata per leggerle. Ledger parziale, sostituzione di directory o drift dei permessi bloccano il riuso. Nessuna firma, nuova directory, credenziale o sessione viene creata dalla lettura.

`FirstControlledGrant.from_completed_custody()` collega queste identità ai componenti esistenti di retirement, credenziale e primo grant. Il nuovo scope v2 vincola separatamente hash del ledger storico e closure della creazione, mentre la nuova azione continua a richiedere i quattro scope firmati correnti. Non trasforma le firme di creazione in autorità di rotazione o grant. L'output root:gid10001 con mode0750 rimane un input da predisporre esplicitamente; le tre radici0700 non vengono allargate implicitamente.

La qualifica dei componenti non completa l'installer: restano consegna del worker con storia durevole, configurazione e perimetro dei consumer correnti, autorità di esecuzione e cutover applicativo. Il primo budget uno/300 secondi non autorizza rinnovi periodici. Semantica/THS, ingestione, dedup/merge e lettura UDP/MCP dei Teatri restano da dimostrare sull'ambiente reale. Nessun nuovo comando VPS è richiesto per la sola integrazione qui descritta.

## Qualificazione del collegamento alle radici completate

Commit `fc914f9b086b4ac3244b773ffbf2488fcfeaca3f`: [CI 38461510061](https://github.com/GioNob/ouf-deploy/actions/runs/38461510061), job115517570687, SUCCESS, **213 test in29 suite, zero esclusioni**, oltre alla prova del protocollo Keycloak monouso. I10 test del primo grant includono3 nuovi casi: percorso completo dalle radici custodite alla pubblicazione, drift di custodia prima degli effetti e rimozione del binding firmato negata. La prova positiva verifica un retirement, una rigenerazione, un grant, due introspezioni, file token presente, ledger di creazione invariato e nessun replay. Filesystem, firme e TLS sono reali; systemctl e amministrazione credenziali sono simulati e l'issuer TLS è sintetico. La prova Keycloak reale è separata, non una prova del medesimo percorso completo sul VPS. [Evidenza strutturata e limiti](../evidence/policy-token-completed-root-migration-qualified-20261013.json).

Il lettore di custodia ha inoltre superato CI38460617302 sul predecessore926d8b4: 8 test retirement,19 custodia e7 consegna, zero esclusioni. Le prove coprono la scadenza della vecchia finestra di creazione senza rinnovo, hash errato, ledger parziale e sostituzione di directory durante l'uso.

[Raccolta aggiornata dei29 moduli](policy-token-root-bound-migration-capsule-20261013.json), SHA256 `7b01bfb3012d1825e2a7c37ac159ee13c751194ea71cf56f63d57c6b20a153be`, declaration hash `7a3329da199d76217d74f02aae0f7fc1e3d7fd26819de04a282a0fd4a73d4520`. I30 blob, incluso il loader, coincidono con il commitfc914f9; l'entrypoint è stato importato realmente in `-I -B -S` senza invocare metodi operativi. [Verifica dei blob](../evidence/policy-token-root-bound-capsule-assembly-20261013.json). La confezione storica usata dalla creazione resta immutata. Anche quella aggiornata è una raccolta di componenti, non un comando da eseguire sul VPS.

