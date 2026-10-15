# Conversione ambiente storico al profilo CSV — 15 ottobre 2026

## Causa dimostrata

Il lettore sul VPS ha restituito una sola variabile non ammessa: JAVA_TOOL_OPTIONS. È presente nella richiesta storica (31 variabili) e assente dal frame del container corrente (19 variabili). Produce entrambi i failedChecks: retainedEnvironmentNamesAccepted e jvmPropertyOverridesAbsent. Gli altri sette controlli dell'ambiente sono PASS. Nessuna mutazione o autenticazione IAM è stata eseguita dal lettore.

La variabile fu aggiunta da scripts/compose-semantic-replacement-draft.py per il provider discovery privato. Il valore sorgente seleziona /run/ouf-discovery-trust/java-truststore.p12, tipo PKCS12, con il valore pubblico changeit. Il profilo CSV disabilita provider e worker discovery e ha quattro mount: quel truststore non vi compare. Mantenere il vecchio selettore JVM e togliere il relativo mount sarebbe incoerente; consentire opzioni JVM arbitrarie indebolirebbe il controllo degli override.

L'aggiunta era già elencata in evidence/replacement-configuration-composed-target-20261010.json. La precedente analisi avrebbe potuto individuarla prima: l'inventario condiviso con soli conteggi ENV e la fixture con il solo PATH non erano sufficienti a prevedere questo blocco. Questa lacuna non viene attribuita ai microservizi o al lavoro della precedente sessione.

## Modifica limitata

Sorgente eseguibile: 912ec9d90015a2742957e49f72bc3a483e759e10, PR31.

retained_file_environment accetta di escludere dalla NUOVA proposta soltanto l'esatto JAVA_TOOL_OPTIONS introdotto dal compositore storico, a condizione che sia assente dall'ambiente nativo storico. Un'opzione diversa, vuota, estesa con altre proprietà o presente nel container applicato viene respinta. JDK_JAVA_OPTIONS, _JAVA_OPTIONS e override Spring/alias feature restano vietati. FileOnlyProfile conserva il divieto JVM nel risultato finale.

Gli input storici non sono modificati. La verifica della conversione è aggiunta al preflight prima di ensure_admin_session e del device login; è ripetuta durante creation. Il preflight espone retainedEnvironment e historicalDiscoveryJvmTrustOptionRemovedFromProposal, senza valori ENV. Il controllo dell'immagine è separato e conserva la lista chiusa delle variabili runtime.

I sei pin applicativi, il pacchetto1,7GB, le migrazioni applicative e i vincoli HUMAN non cambiano. Nessun servizio VPS è stato modificato durante questa correzione.

## Qualificazione

- CI nativa: run38675974309/job116229545255, PASS: **195 test,25 suite,nessun test saltato**.
- CI immagine reale: run38675969215/job116229529470, PASS: compila il profilo a quattro mount con i31/19 nomi osservati e il config esatto dell'immagine sha256:29e32c1487b5ba29d6d29ec04f7daa3baeb1e30f392a46c838eef01493d60489.
- Lo stesso job carica quell'immagine in CI e verifica HTTPS Java predefinito su https://auth.ouf-lab.it/realms/ouf/.well-known/openid-configuration: PASS, issuer esatto, TLS_AES_128_GCM_SHA256.
- Verificatore HUMAN: run38675974374, PASS.
- La rete/namespaces del VPS e il completamento dell'intera review non sono dimostrati da queste fixture.

La fixture riproduce i nomi osservati sul VPS con valori pubblici ricavati dai sorgenti e valori di test: non rappresenta una copia dei valori privati del target. Verifica la compilazione della proposta a quattro mount con config dell'immagine reale e l'immutabilità degli input, oltre ai casi negativi. La prova Java esegue soltanto GET pubblico alla discovery OIDC e verifica issuer esatto con hostname/certificato controllati dal normale HttpsURLConnection; non usa login, token o trust TLS disabilitato.

## Consegna e limite residuo

Capsula SHA256: 6cdb34162fbdabfb585fdeeb8d7d9d7a7169d956d8ad8d25ed7c50a910738d1f.
Launcher SHA256: 310da13bbbe583e040237221b4d54ff8c5dafa670541cef3a426a88de3acbebb.
Wrapper: releases/chatbot-file-cohort-prepare-env-vps-20261015.sh.
Wrapper SHA256: eb83af756739f71d36a856b980a63a7f5c0e05f76e531e849d77c3444b78cb8c.

Il wrapper seleziona il sorgente eseguibile esatto e --prepare-only, riusa lo ZIP già presente e il client gh portatile esistente. Può richiedere nuove autenticazioni sudo/IAM/device perché la sessione precedente non costituisce autorità riutilizzabile. Non approva o avvia l'installazione. Il risultato atteso di preparazione è COMPLETE_PRIVATE_REVIEW_READY_NOT_STARTED con reviewPath e reviewHash.

Questa correzione non prova ancora che la review completa verrà prodotta sul VPS: vanno completati i restanti controlli della preparazione. Non chiude applicazione reale, ACK/commit/lineage, lettura chatbot Teatri o secondo source MATCH/NOOP. Non giustifica una promessa di durata residua. Gli8 Cinema restano il riferimento da preservare durante la successiva accettazione.
