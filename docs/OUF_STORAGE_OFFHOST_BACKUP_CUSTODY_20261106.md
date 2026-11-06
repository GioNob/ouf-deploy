# Copia indipendente per il passaggio storage — proposta da completare

Scopo: rendere ripristinabile il passaggio MinIO→SeaweedFS. Non apre un programma DR autonomo. La richiesta dell'operatore autorizza la preparazione del trasferimento sul proprio PC; non autorizza implicitamente il fermo dei servizi, nuove letture privilegiate per produrre il backup o un restore. Fonte: MiniPET G3/G4 e [runbook](OUF_STORAGE_OFFLINE_CUTOVER_RUNBOOK_20261106.md).

## Dati già disponibili

Lo staging /var/lib/ouf-storage-migration/backup-staging e la destinazione SeaweedFS sono sullo stesso filesystem della sorgente. Sono adatti alla preparazione locale, non provano indipendenza dalla perdita del VPS. Le prove storiche di backup non attestano un insieme attuale e ripristinabile della migrazione.

Il container attivo fuori roster è ora identificato esattamente come **ouf-etcd**: image ID, hash del nome /ouf-etcd e hash del container ID coincidono con evidence/provider-r8-independent-runtime-readback-20261009.json, ricevuta di lettura indipendente tramite runner. Volume storico scrivibile /etcd-data. [Riscontro e join](../evidence/storage-g0-unmapped-runtime-operator-20261106.json). Non dedurre da ciò un consumer S3 o una quiescenza provata. Trattarlo come stato di configurazione del control plane da preservare/verificare per lo switch; nessuno stop o restore automatico.

## Perimetro minimo del backup di migrazione

| Contenuto | Perché serve | Criterio di verifica |
|---|---|---|
| Oggetti MinIO e metadati richiesti |Conservare i120corpi osservati e l'intera generazione effettiva al fermo |Manifest completo/hash dei corpi, key/bucket/metadati,nessuna differenza inspiegata |
| DB completi dei3owner coinvolti |Gli export G0 sono proiezioni; mancano campioni DB e altre righe necessarie |Backup consistente Onboarding/UDP/Ingestion,schemi e prove owner incluse; restore isolato e join DB/oggetti |
| Configurazioni effettive e autorità necessarie |Ripristinare routing,binding,policy e identità coerenti |Manifest degli input realmente usati,chiavi sotto custodia privata; niente segreti nei report |
| Stato etcd pertinente al routing |Conservare configurazioni del control plane che il passaggio può modificare |Metodo coerente con stato/configurazione effettiva e confronto pre/post; non tar del volume live assunto consistente |
| Immagini e strumenti ammessi |Ripetibilità del ripristino e rollback |Digest esatti e copia durevole; artifact Actions a scadenza non sufficiente |

Includere altri DB/volumi soltanto quando il binding effettivo ne dimostra la necessità al ripristino della generazione. Non estendere automaticamente il fermo a tutto il VPS. Il mezzo di backup deve essere qualificato per i privilegi disponibili: il client psql installato non concede ruoli di backup o replica. Nessuna concessione implicita.

## Destinazione scelta: PC Windows di Giovanni

**Scelta confermata dall'operatore: archivio cifrato sul proprio PC Windows, fuori dal VPS**, con copia tramite SSH/SFTP e chiave di decifratura custodita separatamente dall'unica macchina che si intende poter ripristinare. Non richiede pubblicare dati o credenziali in GitHub e non presume l'acquisto di servizi.

Alternativa: spazio già disponibile su un altro host o storage remoto indipendente. Servono destinazione, modalità di accesso e custode; i segreti non vanno incollati in chat. Un secondo percorso sullo stesso disco o un volume Docker sullo stesso VPS non soddisfa l'indipendenza.

[Decisione acquisita](../evidence/storage-backup-windows-destination-20261106.json): Giovanni sceglie il proprio PC e dichiara Windows. Non chiedere nuovamente destinazione o sistema operativo. PowerShell 5.1.26100.9711 e client SSH/SCP presenti sono già riportati dall'operatore; endpoint SSH e percorso locale della chiave sono stati forniti in conversazione e restano fuori dal repository. Non ripetere queste domande o verifiche. Restano spazio locale,cifratura/custodia e archivio finale con dimensione/hash. Il backup completo non è ancora prodotto;nessun trasferimento eseguito.

## Sequenza da legare al pacchetto operativo

1. Fissare perimetro,recipient di cifratura,destinazione,limiti e custode; verificare spazio e accesso senza esportare segreti.
2. Nella finestra ammessa,applicare fence e riconciliare effetti in volo; produrre backup coerenti e manifest della stessa generazione.
3. Cifrare localmente e trasferire una sola copia delimitata con ricevuta di digest/dimensione. Nessun upload a GitHub,chat o artifact pubblico.
4. Verificare il digest alla destinazione e la possibilità di decifrare/ripristinare in ambiente isolato; conservare manifest e prove redatte.
5. Solo con restore/parità e obiettivi soddisfatti,usare il backup come prova G3. La sola riuscita di SCP/SFTP non chiude il gate.
6. Conservare MinIO e la copia indipendente fino alla chiusura governata; nessuna cancellazione automatica.

Finestra/RPO/RTO sono una decisione distinta. Proposta di riferimento già nel runbook: nessuna scrittura confermata persa al cutover; obiettivi PET iniziali RPO DB<=15min e RTO core<=4h da confermare e validare. Non promettere questi tempi sulla base dei120oggetti o delle prove sintetiche.

## Stato e prossima azione

Identità del container fuori elenco risolta. Nessuna mount copre il JAR Onboarding nel documento osservato; byte del JAR e writable layer non verificati. Letture diagnostiche locali concluse: non preparare automaticamente un altro helper.

La destinazione indipendente è scelta:PC Windows. Per concretizzare il trasferimento serve il pacchetto completo,cifrato e verificato sul VPS;non inventare percorso,dimensione o hash. Rimangono inoltre accessi effettivi,admin/consumer esterni,finestra e qualifica integrata. La decisione sulla destinazione non autorizza deploy,grant,fermo,backup effettivo o riapertura.

MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120migrati. Credito aggiunto0.

## Trasferimento su Windows: procedura predisposta, non ancora eseguibile

Usare PowerShell con il client OpenSSH e Get-FileHash SHA256. Non installare il server SSH su Windows,non disattivare controllo host key,non modificare ExecutionPolicy. Il client deve usare lo stesso endpoint e l'identità SSH già utilizzati dall'operatore per il VPS; il nome nella shell Linux non dimostra un indirizzo raggiungibile dal PC.

Prerequisiti client già acquisiti nella [ricevuta](../evidence/storage-backup-windows-readiness-20261106.json). Il comando SSH fornito identifica endpoint e chiave; non è una ricevuta di connessione riuscita.

Script predisposto: [receive-storage-backup-windows.ps1](../scripts/receive-storage-backup-windows.ps1). Parametri obbligatori: SshTarget, IdentityFile, RemoteArchive, ExpectedSha256, ExpectedBytes. Directory PC predefinita: `%USERPROFILE%\OUF-backup`, modificabile con DestinationDirectory. Endpoint e percorso della chiave vengono passati localmente, non incorporati nel file pubblico.

Lo script controlla spazio disponibile, usa una directory distinta per il singolo tentativo, scarica in .partial e confronta dimensione e SHA256 con la ricevuta fissata del produttore. Solo dopo il confronto rinomina senza sovrascrivere. Host-key checking obbligatorio; nessun cambio di ExecutionPolicy, permessi remoti o retry automatico. In caso di errore mantiene il parziale. La ricevuta contiene il percorso locale: redigerlo prima di pubblicarla. Non esegue cifratura o restore.

Validazione: revisione statica manuale; PowerShell non disponibile nell'ambiente agent. Nessun test Windows o trasferimento dichiarato riuscito. L'esecuzione effettiva rimane da verificare.

Il comando di download definitivo verrà composto solo quando siano disponibili:
- archivio completo cifrato,separato dalle proiezioni G0;
- percorso remoto preciso,leggibile dall'utente di trasferimento senza ampliare i permessi degli originali;
- dimensione e SHA256 del file cifrato fissati nella ricevuta;
- directory Windows con spazio sufficiente (endpoint e identità SSH già forniti);
- custodia della chiave fuori dal solo VPS.

La sequenza sarà copia SCP in un nuovo file .partial,controllo exit code e dimensione,Get-FileHash -Algorithm SHA256 e confronto con la ricevuta;solo dopo corrispondenza,ridenominazione al nome definitivo senza sovrascrivere file esistenti. Una copia interrotta resta parziale e non diventa prova di backup. Nessun resume/retry automatico o cancellazione sul VPS. La ricevuta Windows confermerà soltanto il trasferimento integro;decrypt/restore e G3 restano verifiche separate.

Fonti ufficiali consultate il6novembre: [OpenSSH per Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-overview), [Get-FileHash per Windows PowerShell5.1](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-5.1). Nessuna esecuzione PowerShell su Windows effettuata dall'agent.

## Riuso delle procedure di backup esistenti

La revisione di tools/onboarding_profile_recovery_update/backup.py e tools/semantic_application_cutover/fenced_backup_adapter.py conferma primitive per dump PostgreSQL delimitato e verifica del payload, con controllo di quiescenza/ammissione. Sono legate a scope e binding precedenti: non sono un comando già ammesso per questo intervento. Il dump --no-owner --no-acl richiede che il contratto di ripristino conservi separatamente ruoli e privilegi necessari; il solo parsing con pg_restore non prova un restore. La prosecuzione tools/chatbot_file_cohort/backup_recovery.py è anch'essa specifica del precedente intervento e non va rilanciata.

Il blocco da completare è un pacchetto di produzione coerente: binding dei tre DB, barriera ai writer applicativi/amministrativi/esterni, copia della generazione oggetti, configurazioni effettivamente necessarie, cifratura e finestra. Deve essere concreto prima della decisione operativa. Nessun nuovo inventario diagnostico richiesto per SSH o per il container extra già identificato.
