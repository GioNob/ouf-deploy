# Azione amministrativa HUMAN per Ingestion operational READ

### Azione amministrativa HUMAN distinta — 2026-10-19, preparata per avvio nativo

Tecniche **8/8**, funzionali **4/6**. Il codice standalone `1e1a9f9eddca649e64db36fe018f59f2f15a2105` ha superato73 test nella run [39222837925](https://github.com/GioNob/ouf-deploy/actions/runs/39222837925), con firme Ed25519 reali/journal privati e fixture HTTP/IAM esplicite. Il job117962337255 ha predisposto10 file pubblici qualificati sul server; nessun input privato letto, login, authority o effetto amministrativo eseguito.

Lo stage è `/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-ingestion-read-administrative-code-39222837925`; manifest SHA256 `633bbf2a17dc0395dd362694833b2264e7aef9501a06d5ce3fc54a4569e879c2`. Il nuovo launcher `scripts/launch-ingestion-human-administration-20261019.sh` verifica gli hash prima del processo root. La preparazione privata verifica solo la storia/frozen custody già acquisita, costruisce una nuova closure isolata e non richiama installazione o readback uow4n8lp. Dopo PREPARED, la fase nativa verifica la sessione IAM e HUMAN; eventuale RIAPRO LOGIN conserva il cumulativo256, poi APPROVO vincola il piano corrente a massimo900secondi.

Perimetro: registrazione `ingestion.operations.read`, aggiunta del descrittore nella policy immutabile e relativo scope OAuth del client ChatGPT. Ruoli, assegnazioni e grant rimangono invariati. Il successivo grant temporaneo sulla fonte `teatri-csv-6609b245` richiede una proposta e decisione THS distinte. Nessuna attivazione della revisione approvata, acquisizione, modifica infrastrutturale o retry job. Dopo STOP/interruzione: conservare il contesto e riconciliare, senza rilanciare il launcher.

La preparazione root e l'esecuzione sul target restano **NON ESEGUITE**: dal CLOUD manca un terminale operatore autenticato per i gate nativi. CI e staging non dimostrano pubblicazione della capability o token aggiornati. Tappe5–6 ancora aperte.


Il profilo installativo esplicito e versionato è `releases/ingestion-read-administrative-installation-20261019.json`: riusa i riferimenti IAM già qualificati di questa installazione, senza introdurli come default portabili. Endpoint/issuer/client/container/socket sono risolti dagli input originali sotto custodia e confrontati con il piano autorizzativo completato.

Il nuovo esecutore riusa le due firme installer esistenti nel formato di authority finita, ma firma soltanto `chatbotFileAuthorization` e `ingestionReadAdministration`; nessuno scope infrastrutturale. Il piano firmato contiene baseline completa, hash delta, scope fonte e vincolo `roleProposal=null`; il token umano resta nel processo nativo. Nessun tool MCP di conferma o nuova API di amministrazione è introdotto.

Verifiche:22 regressioni autorizzazione firmata,6 osservazioni durevoli,11 revisione,11 profilo READ,11 READ nel successore governato,5 authority amministrativa e7 custodia/session binding, tutti PASS. Le fixture verificano lost registration reply, draft ambiguo senza duplicati, revoca, grant/ruoli invariati, source scope, firme ed esclusione attestor. La qualifica della consegna verifica separatamente lo shim root e il blocco prima di letture private se il preparer è alterato. Il caricamento completo degli input sotto custodia e gli effetti owner/IAM sul target devono ancora avvenire nel gate nativo.

Originali consultati per questo sprint: Matrix1.7 §1; Authorization1.5 §§20–22 e109.6; Onboarding/THS1.6 §103 eTHS-A02/A09; Ingestion1.3 §46 Persistent Operational Event Model/46.3 eOA-ING-05. Fonte: PET allegati, archivio e63df67e8817eec38a9d4b3eb736b020f693b932f3360dc02f4555330f2201ce. La lettura non costituisce accettazione completa del sistema.

Gate successivi: dopo il risultato nativo riconciliato, creare un solo grant HUMAN24h con risorsa operational, module INGESTION, sourceRef teatri-csv-6609b245 e dettaglio TENANT_OPERATIONAL; decisione nella THS, rinnovo consapevole del token ChatGPT, lettura status/history, quindi attivazione governata e prove delle tappe5–6.

La qualifica iniziale della consegna39222473524 ha rilevato che il diagnostico dello STOP poteva riportare un messaggio arbitrario maiuscolo. La correzione232535d2106f39bf46e8a4e4ee30b015365fdb06 oscura integralmente il testo dell'eccezione; il test corretto1e1a9f9eddca649e64db36fe018f59f2f15a2105 inietta un canary privato nel boundary nativo. La run39222837925 passa73 test e ristagia il codice corretto. Lo stage39221983431 e il launcher7f7773990f25a86c9a0c8ded945e79fa4e59c5c3 sono superati: non usare quella consegna. Nessuno dei due è stato eseguito sul target.
