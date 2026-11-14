# Lettura delle ricette della nuova generazione — 9 novembre 2026

**Conclusa sul VPS alle 12:25:29 CET. Non ripetere il lettore.** La [ricevuta operatore](../evidence/discovery-generation-sources-read-operator-20261109.json) riporta `DISCOVERY_GENERATION_SOURCES_READ`, phaseCOMPLETE: 25 metadata stabili durante la lettura. Entrambe le ricette indipendenti ricompilate coincidono con le policy installate; nessuna differenza OCI rilevata in questo confronto tra documenti. Runtime non osservato e nessun effetto runtime.

Adapter a due NIC, southbound a tre; dichiarazioni reciproche coerenti. Il secondo flusso southbound resta `WORKLOAD_GATEWAY`, da 172.18.0.6 a 172.18.0.14:10443/tcp, con BRIDGE_PORT storico 1377. Non è una dichiarazione indipendente del Semantic corrente. [Composizione successore implementata separatamente](OUF_DISCOVERY_SUCCESSOR_COHORT_20261109.md).

## Perché occorre questo passo

La ricevuta delle 11:55:17 CET vincola tre file per hash, ma espone soltanto il numero dei riferimenti a identità storiche. Mancano i binding NIC/peer effettivi e la relazione tra le ricette OCI indipendenti dell'8 ottobre e i profili poi installati. Il componente `provider_installation_template.py` attuale richiede una sola rete e un Registry creato nella propria finestra: non può essere presentato come installer già compatibile con la coppia a più reti e il Semantic corrente.

Il lettore consuma l'esatta ricevuta, la relativa completion e i tre file già preparati. Verifica i cinque binding originali e il puntatore boot conservato nel piano; segue soltanto broker, template, metadata dell'attestor, policy OCI e record storico di autorizzazione nominati da questi binding. Non segue i riferimenti alle chiavi di firma né apre i file montati nell'applicazione.

Le ricette indipendenti originali sono fissate per hash: launch, template, contesto e policy di ciascun ruolo. Il compilatore originale ricostruisce la policy e ne richiede l'uguaglianza completa. Il confronto con la policy installata riporta i percorsi JSON delle differenze, senza valori di environment, argv o contenuti privati. Un'eventuale differenza non diventa una normalizzazione ammessa.

Il risultato espone i binding NIC, i peer dichiarati e i riferimenti numerici storici del trasporto. Un indice BRIDGE_PORT storico non diventa un peer corrente. Il sigillo rootfs v1 storico resta distinto dall'aspettativa per la nuova generazione; le firme storiche non vengono verificate o riutilizzate da questo lettore. Tutti i metadata letti sono ricontrollati per stabilità; la lettura non è uno snapshot atomico.

## Pacchetto e qualifica

- Sorgente: `a14e6b61c2efe56f838507990850812d694407d1`.
- [Lettore](../scripts/read-discovery-generation-sources-20261109.py), SHA256 `8c2057538e3cfc3b3c6f1ef3a315268a0a4362e409b09ce527e67360e5a9d77b`.
- [Consegna](../scripts/deliver-discovery-generation-sources-20261109.sh), SHA256 `2fa6efe644ee81094c62408312b81bf60aecff5469118b198eec851b0fe90b3f`.
- [CI 42608238333](https://github.com/GioNob/ouf-deploy/actions/runs/42608238333), job129129595875: **11 test, zero skip, PASS**, log diretti letti. Fixture con documenti sintetici e baseline Engine indipendenti già conservate; nessuna osservazione VPS o prova native di nuova creazione.
- Consegna verificata localmente: sintassi bash, 17 hash corrispondenti, un solo dispatch al lettore e pulizia dei soli download temporanei. curl/sudo sostituiti nella prova; nessuna esecuzione operativa locale.

## Esito conservato

Evidenza privata: `/var/lib/ouf-storage-migration/discovery-generation-sources-b57yoer0`. Ricevuta `result.json`, 7.224 byte nel formato del produttore (JSON canonico più LF), SHA256 `8a0ed83e6cbbcd4f46802d610c5382a57605381242896a0145174f7fe2a31d3d`. Il file pubblico conserva tutti i 36 campi e i due ruoli; il suo formato indentato ha byte diversi.

La ricevuta conferma zero letture dei file credenziali/mount, firme, CREATE, richieste Engine o applicative. Puntatore, wrapper e journal invariati. I sigilli rootfs restano storici; firme non verificate e nessuna nuova autorità o ammissione. Non trasformare il confronto positivo dei documenti in readiness o compatibilità live.

La composizione pura della nuova coppia è ora qualificata separatamente: usa queste ricette e sostituisce il solo peer numerico storico con una dichiarazione completa. Restano l'aspettativa indipendente del Semantic corrente, la prova delle nuove creazioni e dei sigilli rootfs, l'autorità e l'integrazione di pubblicazione/switch/avvio. Non ripetere boot, staging, preparazione o questo lettore. Nessun nuovo comando VPS è qualificato da questo checkpoint.
