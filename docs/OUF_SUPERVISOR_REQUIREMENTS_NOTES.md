# OUF Supervisor — requisiti da conservare

Appunto richiesto il 23 ottobre 2026. Da incorporare nel PET del nuovo modulo dopo il ripristino del 502 e l'E2E.

Il Supervisor governa la configurazione degli indirizzi, hostname, IP configurabili, URL, porte, protocolli e relativi riferimenti di rete per l'intera piattaforma e i miniservizi presenti e futuri. I moduli consumano configurazione verificata e versionata: nessun endpoint dell'installazione deve essere incorporato nel codice applicativo. Le fonti attuali dei parametri restano vincolanti finché la migrazione non è progettata e verificata.

Il Supervisor valida schema e coerenza dei parametri, distingue valori pubblici e segreti, conserva provenienza/versione e gestisce la propagazione e riconciliazione idempotente in presenza di concorrenza e riavvii. Le modifiche devono rispettare autorizzazioni, isolamento tra ambienti, controllo degli egress e identità TLS; non introdurre fallback automatici verso endpoint arbitrari o disabilitare verifiche TLS.

Kubernetes mantiene la responsabilità di allocare gli IP dei pod, mantenere Service/EndpointSlice e DNS del cluster e gestire scheduling, restart e probe. Il Supervisor configura o riferisce questi oggetti attraverso le API dichiarative previste; non mantiene un inventario parallelo degli IP effimeri e non duplica il control plane. Privilegiare nomi di servizio stabili, lasciando gli IP come parametri espliciti soltanto dove richiesto dall'integrazione.

Questo appunto non avvia l'implementazione del Supervisor e non cambia l'ordine concordato: 502, E2E, Supervisor.
