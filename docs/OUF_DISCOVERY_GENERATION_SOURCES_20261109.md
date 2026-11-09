# Lettura delle ricette della nuova generazione — 9 novembre 2026

**Qualificata, ricevuta VPS ancora attesa.** Boot e preparazione degli input sono conclusi. Questa lettura serve a ricostruire i riferimenti privati necessari per comporre il profilo di creazione della nuova coppia; non è un installer.

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

## Invocazione ed esito

Eseguire una volta il comando di consegna fissato al commit fornito in chat. Python opera con `-I -B`, limite totale di90secondi, metadata bounded e directory di evidenza nuova sotto `/var/lib/ouf-storage-migration/discovery-generation-sources-*`. La consegna scarica e verifica17 sorgenti; importa le dipendenze precedenti senza chiamarne gli entrypoint operativi.

Esito atteso: `DISCOVERY_GENERATION_SOURCES_READ`, phaseCOMPLETE. Inviare soltanto il JSON finale. In caso HELD conservare la directory e la ricevuta, senza rilanciare il comando. Il lettore scrive solo la nuova evidenza; non modifica configurazioni, puntatore, journal, servizi o container. Non effettua richieste Engine, database, provider, token, DNS o S3; i contatori si riferiscono al lettore Python, non al download HTTPS della consegna.

La ricevuta consentirà di chiudere la composizione concreta delle ricette e identificare le correzioni di contesto già presenti. Restano poi peer Semantic corrente con aspettative indipendenti, nuove identità/autorità, pubblicazione e switch/avvio governati. Non ripetere boot, staging o preparazione. Provider pronto, discovery ed E2E restano non provati.
