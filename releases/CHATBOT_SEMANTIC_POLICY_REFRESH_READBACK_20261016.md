# Diagnostica finita del percorso di refresh policy

## 16 ottobre — binding dinamico Authorization osservato sul target

Fasi tecniche 8/8 conservate, funzionali 0/6; tappa 1 ancora bloccata.
Il reader b8823885060654097bb43b635b8c664f031793c8 termina complete=true:
generazione Registry stabile tra due letture; authority precedente scaduta.
Nell'ambiente esplicito sono presenti REGISTRY_URL, REGISTRY_TOKEN_FILE,
REFRESH_SECONDS=30, MAX_STALENESS_SECONDS=300; riferimento token assoluto
coperto da mount readonly. Nessun BUNDLE_FILE/ID/VERSION/SHA256 esplicito.
SPRING_CONFIG_IMPORT presente, altri override Authorization non rilevati.
Il falso matchesObservedPolicy40Hash è dovuto al riferimento statico assente:
NON dimostra che il Registry usi una policy diversa dalla 40.
Configurazione dinamica osservata != successo del refresh o snapshot caricato.
Il reader non ha aperto policy o credenziali e non ha effettuato GET applicativi.

Una nuova lettura governata GRANTS sul subject ouf-admin conferma policy40 e
hash d4e2478c… con grant nominali semantic.propose e proposal.read, ancora
CONFIGURED_GRANTS_NOT_EFFECTIVE_PERMISSIONS. La prima invocazione incompleta
(senza selettore subjectId/externalRoleRef) è stata rifiutata dalla validazione
degli argomenti; la lettura corretta usa subjectId e non cambia grant.
Nessun altro tentativo semantic.propose/proposal.read è stato eseguito.

Prossima lettura: scripts/read-chatbot-semantic-policy-refresh-20261016.py.
È una diagnostica specifica dell'installazione, non un rinnovo runtime:
richiede URL e path token uguali alla creationRequest custodita, origine HTTPS
uguale alla selection Authorization già approvata, mount bind readonly con
source/target corrispondenti alla request. Apre un solo token workload già
montato (mai client secret, chiavi o credenziali alternative), controlla custodia
no-follow e drift, espone solo exp e scadenza come metadati JWT non verificati.
Esegue un solo GET al percorso configurato, con TLS/hostname verificati tramite
trust di sistema, senza redirect/proxy/retry/emissione token.
Un 401/403 non viene ritentato né aggirato. Risposta200: proietta solo versione,
conteggi dei due grant, presenza capability e confronti hash; nessun body grezzo.
Il confronto del JSON compatto è diagnostico, non prova che Java abbia installato
il bundle. Trasporto dal VPS != trasporto JVM del Registry. Snapshot in memoria,
causa precisa del precedente403, DRAFT e accettazione restano non provati.

Sei nuovi test locali PASS; sedici complessivi PASS. Nessun test locale prova il
target. Nessun grant, refresh forzato, restart, modifica DB/Gateway, nuovo worker,
budget reset o replay. Cumulativo69 e cancellazione precedente restano conservati.
La decisione HUMAN su Teatri rimane esclusivamente nel THS.
Attesa solo l'esecuzione VPS della nuova lettura pinned.


Reader SHA256: 504bc62c548020628b9bdc5e71f47ca5701f8ef90195915a9e5e7bcdaa478919.
Massimo120 secondi, due GET metadati Docker, un file token workload, un GET policy.
Custodia non corrispondente o drift fermano la lettura; non cambiare permessi o binding per farla passare.
