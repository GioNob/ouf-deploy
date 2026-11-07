# Input G0 dopo la preparazione delle quattro connessioni

Aggiornamento6novembre, esito operatore albd779aa8: S3 e tre DB predisposti in aree private separate, rete e runtime/bucket compilati,17ricevute conservate. Nessuna connessione ai servizi; niente check composto eseguito finora. La precedente fase di template vuoti è superata.

| Campo | Evidenza disponibile | Residuo effettivo |
|---|---|---|
| Bundle/manifest |9053aa38 verificato e custodito sul VPS|Riutilizzarlo, nessun nuovo download |
|17ricevute|Digest verificati nelle preparazioni|Conservarle, mai rieseguire13–17 |
|13ruoli|ID/immagini storici attesi, cinqueprocessi verificati durante preparazione|Il collector confronta runtime corrente e nega drift; non sono attestazioni correnti di tutti i ruoli |
|Rete|Binding dei processi MinIO/PG compilato; namespace qualificati|Validazione locale e verifica di generazione durante la futura raccolta |
|Identità|operationId seaweedfs-g0-20261106-v1 / installationRef ouf-retained-14e42ac9|Correlazione locale, non IAM o autorità |
|Quattro connessioni|S3 pronta e tre DB aggiunti; overlay JSON/file controllati|Primo preflight composto; autenticazione e schema non ancora provati |
|Onboarding|Profilo retained candidato e guard SQL di compatibilità|Review installazione; nessun fallback o migrazione automatica |
|Runtime/bucket|Bozza da environment dei processi fissati|Configurazione effettiva completa e writer non provati |
|Capacità|Percorsi proposti,272,95GiB disponibili riportati nella ricognizione precedente|Precheck locale esistenza/ancestry dei percorsi esatti; poi misure e review per capacità/backup |
|Accessi/writer/custodia/finestra|Intake previsto, documenti mancanti espliciti|Prove da raccolta e dichiarazioni operatore distinte, nessuna falsa completezza |
|Decisione raccolta|Assente|Comando concreto e gate applicabile; riferimento non autentica HUMAN |

Usare [il primo check composto](OUF_STORAGE_G0_FIRST_COMPOSED_CHECK_20261106.md), ora che le quattro connessioni sono presenti. Il vincolo precedente contro check su template vuoti non impone di attendere tutte le evidenze di accettazione per questa verifica locale. Il codice preflight elenca gli input operatore mancanti e non autorizza collect.

La seconda verifica proposta evita un errore prevedibile: collect chiama capacity dopo aver riservato lo scope e richiede directory esistenti/custodite. Non sostituire percorsi con antenati, creare directory o cambiare owner automaticamente. Non ripetere la scansione backup né chiedere DR come prerequisito di preparazione. Tutte le condizioni di accettazione restano aperte; MiniPET39,78%,credito0.
