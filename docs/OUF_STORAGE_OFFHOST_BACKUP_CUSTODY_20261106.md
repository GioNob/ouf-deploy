# Copia indipendente per il passaggio storage — proposta da completare

Scopo: rendere ripristinabile il passaggio MinIO→SeaweedFS. Non apre un programma DR autonomo e non autorizza letture di credenziali, backup, stop, trasferimento o restore. Fonte: MiniPET G3/G4 e [runbook](OUF_STORAGE_OFFLINE_CUTOVER_RUNBOOK_20261106.md).

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

## Destinazione proposta e decisione mancante

**Prima opzione da valutare: archivio cifrato conservato sul PC dell'operatore, fuori dal VPS**, con copia tramite SSH/SFTP e chiave di decifratura custodita separatamente dall'unica macchina che si intende poter ripristinare. Non richiede pubblicare dati o credenziali in GitHub e non presume l'acquisto di servizi.

Alternativa: spazio già disponibile su un altro host o storage remoto indipendente. Servono destinazione, modalità di accesso e custode; i segreti non vanno incollati in chat. Un secondo percorso sullo stesso disco o un volume Docker sullo stesso VPS non soddisfa l'indipendenza.

**Scelta ancora non fornita:** PC (e sistema operativo) oppure destinazione remota già disponibile. Nessun trasferimento è ancora predisposto o autorizzato; dimensione, spazio disponibile, cifratura e custodia devono essere verificati prima di produrre il comando esatto.

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

Per completare questo pezzo del pacchetto serve ora la scelta della destinazione indipendente. Rimangono inoltre accessi effettivi,admin/consumer esterni,finestra e qualifica integrata. La decisione sulla destinazione non autorizza deploy,grant,fermo,backup effettivo o riapertura.

MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120migrati. Credito aggiunto0.
