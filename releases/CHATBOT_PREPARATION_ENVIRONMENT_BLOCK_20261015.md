# Preparazione VPS: blocco ambiente, 15 ottobre 2026

Il preparatore d8f23a4 ha superato sul VPS tutti i controlli nativi, incluso il confronto storico completo. Il nuovo tentativo prepare-only si è fermato con REVIEWED_APPLICATION_AND_IMAGE_ENVIRONMENT_REQUIRED dopo le autenticazioni, prima della review completa. Non prova il ciclo CSV end-to-end.

Il controllo accorpa due condizioni: nomi ENV dell'immagine candidata e nomi ENV della richiesta storica di creazione. La lettura dell'artefatto semantic esatto11907831957, run produttore38584614991, ha verificato l'hash del TAR e del config immagine, oltre alla revisione del sorgente. La CI di lettura38672848037/job116219722868 è PASS. L'immagine sha256:29e32c1487b5ba29d6d29ec04f7daa3baeb1e30f392a46c838eef01493d60489 contiene solo JAVA_HOME, JAVA_VERSION, LANG, LANGUAGE, LC_ALL e PATH: tutte ammesse dal preparatore. Nessuna ricostruzione dell'immagine o operazione sul VPS.

È dunque il lato della richiesta storica a fallire: contiene almeno un nome ENV non ammesso. Il nome non è ancora acquisito. L'inventario condiviso riporta conteggi ENV, non i nomi; non basta a determinarlo. Non si attribuisce il blocco a un'opzione JVM senza leggerne la presenza. Non è stata allargata alcuna allowlist.

## Limite del metodo identificato

La CI precedente prova componenti reali e guardie, ma la fixture creation impiegava un'immagine con solo PATH e un ambiente storico sintetico. Non prova la compatibilità dell'intera preparazione con i veri input del VPS. Il nuovo risultato impedisce di usare i193 test come garanzia di preparazione completa. Il confronto immagine reale è ora riproducibile dal workflow chatbot-exact-image-environment.yml; non equivale a una prova dell'ambiente storico o dell'E2E.

Il prossimo passo è una lettura diagnostica dei soli due JSON storici fissati per hash. Non richiede riavviare preparazione, leggere di nuovo1,7GB, accedere a IAM o autorizzare device code. Il programma legge in memoria gli input privati e stampa solo nomi/check, nessun valore ENV e nessun hash dei valori. Nessun comando nativo, rete, DB, IAM o scrittura viene eseguito dal lettore; il bootstrap scarica il lettore e crea il suo file temporaneo.

## Diagnosi predisposta

Script: scripts/read-retained-registry-environment.py.
SHA256: 870f7de4c5d020652011209a7a15d325ddc0268ce03affb5b6237fcbe4834c90.

Controlla insieme: nomi ammessi, canali JVM vietati, override Spring, alias feature, password DB in ENV, import configtree esatto, IAM non disabilitato, presenza riferimento token e limiti delle voci. Confronta anche i nomi della richiesta storica con quelli del frame nativo storico. Non controlla né dichiara completata la restante preparazione.

Verifiche locali: nessuna fuga di un valore segreto sentinella nel report; più dinieghi simultanei osservati; nomi illegali/duplicati/NUL rifiutati; lettura reale di file root0600 con hash esatto; hash errato, permessi errati e symlink rifiutati. Sono controlli del lettore, non una diagnosi già eseguita sul target.

I sei sorgenti applicativi e il pacchetto restano invariati. B01 confronto storico target dimostrato; B03 preparazione completa ancora aperta; B04 applicazione reale, B05 Teatri e B06 seconda sorgente ancora da dimostrare. Nessuna conclusione su abbandono o breve distanza dall'obiettivo è sostenuta da questo output.
