# M2 — Correzione Gateway acquisita, decisione storage necessaria

1 novembre 2026, Europe/Rome. È completato il lavoro indipendente sulle due
origini residue fino al punto in cui serve una scelta di prodotto dell'owner.
La [proposta concreta sullo storage](../decisions/OUF_M2_OBJECT_STORAGE_DIRECTION_20261101.md)
è pronta: AIStor con licenza adeguata oppure qualifica di un backend S3
mantenuto e open source. Non è richiesto un comando VPS o un consenso runtime.

## Gateway operational owner

L'assenza dell'immagine nei due run originali è confermata. Il nuovo pacchetto
è esplicitamente distinto dal retained `979de5eb`: non si ricostruisce per
dedurre l'uguaglianza. Il sorgente originale81fdf7a5, testato, produceva comunque
un candidato con5HIGH Jackson e2CRITICAL SpringWebMVC; il gate41352768608 lo ha
respinto e la sua evidenza completa resta conservata.

La [PR85](https://github.com/GioNob/ouf-api-gateway/pull/85), sorgente
`17439fed7a45d455baa6945ee72a65fa19c14029`, cambia solo `operational-owner/pom.xml`:
Boot4.0.8, Spring7.0.9, Jackson2.21.7 e bridge Jackson2. Jetty e Micrometer
seguono la BOM corrispondente. Java applicativo, route, ricevute, policy e SQL
non cambiano. È una nuova generazione candidata; il cambiamento di major
richiede comunque la qualifica e review della coorte prima dell'installazione.
Le aggiunte incident-catchup successive sulla base della PR restano distinte:
non vengono eliminate, dichiarate incluse nell'immagine o accettate implicitamente.

[CI sorgente41353173886](https://github.com/GioNob/ouf-api-gateway/actions/runs/41353173886):
tre job PASS, tutti i log finali letti. SDK10 e owner4 nei job Java, APISIX reale
con revoca e catena summary completa; configurazione generica244PASS/3SKIP,
con opt-in live eseguiti separatamente. I tre skip non sono promossi a PASS.

[CI pacchetto41353205013](https://github.com/GioNob/ouf-deploy/actions/runs/41353205013),
job124987637755, publisher48c934d0: PASS. Package3, SDK10, owner4 e integrazione
APISIX→Java1 senza failure/error/skip. Docker29.8.1; baseJRE21 risolta e congelata
nel Dockerfile; identici JAR testato e JAR nel rootfs; native/config/layer e
envelope scanner controllati. Scansione OS+JAR, tutte severità/unfixed:
**zero HIGH/CRITICAL/UNKNOWN,53MEDIUM/4LOW**. Attestazione del checksum subject
verificata con gh2.97.0 per workflow/ref/source/runner hosted/Sigstore.

Artifact13102047484:298.387.448byte,SHA256 `9af9def1…`.
Nuovo native `502ba0e4`,config `8c2b47b5`. L'agente rilegge intero ZIP, tutti i
checksum inclusi i due archivi immagine, configurazioni e tutti i9layer/diffID,
poi230Gitblob/mode contro albero indipendente. Metadati originali completi
conservati in `releases/artifacts/m2-gateway-owner-qualified-metadata-41353205013.zip`.
Il futuro intake deve ancora acquisire l'archivio eseguibile originale e
verificare custodia/freschezza/authority. La lettura offline dei metadati non
asserisce di ripetere la verifica della catena Sigstore o della liveness target.

[Dossier Gateway](../../evidence/m2-gateway-owner-security-qualified-20261101.json).
Il primo tentativo di pacchetto41352559992 si era fermato sul percorso SBOM
storico inesatto; test Java/APISIX erano passati. È corretto nel pacchettizzatore
leggendo l'output CycloneDX effettivo, senza indebolire il requisito SBOM.

## MinIO

[Dossier immagine esatta](../../evidence/m2-minio-exact-copy-security-readback-20261101.json):
indice14cea493/manifestoa1a8bd4a/config69b2ec20 e9layer/diffID recuperati da copia
pubblica esplicita GHCR, tutti SHA confrontati. Nessun tag mutabile, fallback
installativo, esecuzione immagine, credenziale utente o publisher vendor dedotto.
La mancata disponibilità del registry originale rimane preservata.

Scanner OS+Go su questi byte reali:9CRITICAL,127HIGH,8UNKNOWN,171MEDIUM,27LOW.
Run41352708811/job124986151771 fallisce correttamente il gate; intero artifact
13101916659 conservato. Non sono144CVE distinti né una prova di reachability.
Almeno due bypass autenticazione risultano, secondo gli avvisi ufficiali,
ancora presenti nell'ultima release open source. Upstream dichiara il progetto
non mantenuto; aggiornare solo sistema operativo/Go/dipendenze non chiude il gap.

La proposta documenta fonti ufficiali, licenza AIStor richiesta, limiti Free su
cifratura/HA e irreversibilità dichiarata della conversione in-place. Nessuna
licenza viene accettata o migrazione scelta. Non si assume implicitamente un
fork Community manutenuto da OUF. L'owner deve indicare la direzione; la scelta
abilita la qualifica del candidato, non l'installazione sul VPS.

## Continuità e prossima azione

Il riconciliatore pubblico aggiunge il candidato Gateway distinto e la prova
MinIO HELD. Semantic corretto resta nel suo campo candidato; il ruolo installato
resta HELD. Le origini dei runtime conservati e le future sostituzioni sono
distinte: nessuna nuova selezione, source admission o autorità implicita.

Scope12 consumato,12controlli/35GET invariati, tutti235/19/17/21/23sorgenti
congelati preservati. Coorte completa/custody/policy/owner/bearer/proposalGateway,
pacchetto sigillato/review/HUMANdual-role restano gate. M1/Teatri8/8tecnico e
6/6funzionale acquisiti; stessa Farmacie61righe/10OPEN/ministerialeSTRING
preservata. M2/G5–G7/dueclient e61esitiUDP/ripetibilità/fault OPEN. Poi
grafo/search e verticali/API scheduler/delta. Non rilanciare vecchie consegne.
