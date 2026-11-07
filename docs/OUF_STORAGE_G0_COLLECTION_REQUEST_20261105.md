# G0 — richiesta unica delle evidenze correnti

La raccolta16 e il piano17 sono consumati e restano intatti:17controlli,52GET Docker,265richieste S3 della raccolta16,120record/203743byte storici e zero corpi reali verificati. Non rieseguire i launcher13–17. Il dossier pubblico non contiene gli inventari privati e le capabilities MCP disponibili non espongono Docker, S3 o SQL.

Questa richiesta riunisce il residuo G0 in una sola consegna per l'operatore. **Il pacchetto candidato è ora consegnato; binding, rete, custodia e ammissione target restano aperti.** Non chiedere di eseguire comandi storici; non presentare la disponibilità ouf-admin o il modulo di raccolta come autorità HUMAN. La preparazione del collector completo deve usare questa chiusura, evitando microdiagnostiche separate.

## Consegna richiesta e criterio di completezza

Tutte le evidenze devono riferirsi alla stessa installazione e a una finestra esplicita, con timestamp, produttore, contatori e digest. L'inventario non è atomico per la sola vicinanza dei timestamp. Le configurazioni, chiavi degli oggetti e riferimenti DB restano nello scope privato protetto; alla chat arrivano soltanto riepiloghi redatti e riferimenti verificabili.

| ID | Evidenza privata richiesta | Verifica necessaria e risultato pubblico |
|---|---|---|
| G0-RUNTIME | Roster corrente dei13ruoli noti; IDcontainer, image/rootfs/source, PID/avvio, mount e binding effettivi; confronto con le osservazioni14/16 | Distinguere installato, candidato e main; riportare drift per ruolo senza esporre ENV/segreti. Un cambio runtime non rinnova autorità né riammette un owner. Identificare anche ruoli/consumer esterni al roster |
| G0-OBJECTS | Inventario corrente completo di bucket, versioni/marker/multipart/funzioni e metadati; lettura autenticata di ogni corpo richiesta dal profilo, condizionata all'identità osservata; SHA256 calcolati e nuova verifica della sorgente | Conteggi/byte e100%corpi, mismatch/stale/unsupported espliciti. Non assumere ancora120oggetti o assenza di versioni. Hash annunciato non vale come hash verificato; mutazione concorrente impedisce snapshot/parità, senza replay cieco |
| G0-ACCESS | ACL complete e classificazione grantee/owner, policy e identità effettive; risposta publicAccessBlock e controllo equivalente per ogni bucket | Le due risposte UNSUPPORTED del controllo17 non significano funzione assente. Mappatura motivata e verificata; nessun grant aggiunto per superare un diniego. Valori/secretRef privati |
| G0-WRITERS | Mappa runtime dei percorsi sotto, scheduler/queue/intenti in volo, identità S3/DB e consumer amministrativi/esterni | Ogni percorso ha owner, binding, stato, modalità di drain/fence e prova. Nessuna deduzione «zero writer esterni» dalla sola ricerca Java. Percorsi assenti richiedono evidenza e review dell'applicabilità |
| G0-DB | Export read-only minimizzato dei riferimenti managed-file, cataloghi/lake/shadow/manifest UDP, lineage/outbox/ACK/watermark Ingestion e degli intenti pendenti; schema/migrazioni e snapshot DB identificati | Join completo con gli oggetti: missing/mismatch/extra classificati; conservare tenant, asset/source/job/version/hash/locator e lineage. Niente payload business o credenziali nel rapporto pubblico. Una transazione read-only non prova un common-cut con S3 |
| G0-CAPACITY | Spazio/RAM e crescita correnti; collocazione indipendente destinazione/backup, risorse per copia e rollback, throughput rappresentativo e interferenza sugli altri moduli | Margine e durata contro la finestra concordata. Le misure14 e i3,207s/2,273s della fixture120 sono storici/non rappresentativi del VPS |
| G0-CUSTODY | Custodia corrente delle credenziali operative e dei backup/configurazioni/chiavi; riferimenti alle ricevute di conservazione dell'immagine esatta | Il vecchio file0600 con owner non-root era osservabile, non ammesso. Nessun chmod/chown automatico; review e cambi operativi separati. Actions con scadenza3febbraio2027 non è custodia durevole |
| G0-WINDOW | Finestra di manutenzione e criterio di quiescenza, RPO/RTO infrastrutturali validati, modalità HOLD/recupero e responsabilità operative | RPO cutover=0scritture confermate perse. PET iniziale RPOdisaster900s/RTO14400s da validare; nessuna durata di fermo inventata. Preferire fermo completo se le misure lo consentono; delta online solo se necessario |

Percorsi da coprire: upload HUMAN; upload delegato; worker profile; esecuzione/replay Ingestion; consegna outbox/ACK/watermark; UDP store; UDP shadow; UDP purge/compaction; UDP maintenance/reconciliation; bootstrap/manutenzione amministrativa; consumer esterni. La mappa sorgenti del5novembre non è un censimento live. Il nuovo Onboarding d5155899 modifica intento/riserva, ma non viene assunto installato.

## Collegamento delle prove e limiti

[Manifesto della richiesta](../releases/storage-g0-evidence-request-20261105.json): ogni sezione rimane REQUIRED_CURRENT_PRIVATE_EVIDENCE. I riferimenti storici servono per confronto e conservazione, mai come sostituti di nuove prove correnti. Le evidenze possono essere composte solo dopo autenticazione della loro origine e review degli input; una dichiarazione manuale non diventa osservazione tecnica.

Il [pacchetto unico G0](OUF_STORAGE_G0_OPERATOR_PACKAGE_20261105.md) è consegnato e qualificato nel profilo documentato: host/capacità, corpi condizionali, tre export DB, join, ACL e intake operatore. [Ricevuta](../evidence/storage-g0-package-qualified-20261105.json): run42120934027,13test e fixture host reale; non qualifica della composizione nativa completa S3+DB, né raccolta target.

Il [preflight operativo](../evidence/storage-g0-operator-preflight-20261105.json) resta HOLD: canale operatore e binding privati non disponibili, rete host da verificare, census/finestra/custodia da confermare. `check` è locale e non consuma scope; il template non contiene un comando target ammesso. Le17ricevute storiche restano vincolate e non riusabili. Nessun controllo18 assegnato.

Occorre identificare l'operatore o il canale di accesso già disponibile al VPS e il custode delle configurazioni private, senza inviare segreti in chat. Completati input e verifica locale, si potrà sottoporre il comando concreto al gate applicabile. Non è ancora richiesta l'esecuzione di `collect`. Nessun gate chiuso o credito MiniPET.
