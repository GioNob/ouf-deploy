# Contenimento dei writer host per la prima copia non produttiva

## Risultato corrente

Il controllo sul VPS identifica cinque timer attivi e il collegamento ReadWritePaths alle cinque fonti runtime cambiate. I cinque servizi erano inattivi all'osservazione, ma i timer potevano riattivarli. Un sesto servizio OUF token, registry, era attivo. La coppia semantic era già mascherata. [Ricevuta riportata dall'operatore](../evidence/storage-runtime-writer-metadata-operator-20261106.json).

Questo rimuove l'incertezza sul perimetro minimo host da considerare: il fermo Docker da solo non basta. Non dimostra chi abbia scritto ogni byte o l'autenticità dei token. Includiamo registry nella proposta in modo conservativo, senza affermare che scriva nelle fonti backup.

## Preparazione concreta

Programma scripts/prepare-storage-host-containment-20261106.py,14229byte,SHA256a4fe4def22c21889c313c7c32e885aedd8e4c0de43fba1d76c2657ab746dbb47.

Crea soltanto /var/lib/ouf-storage-host-containment-preparation-20261106-v1 (0700), draft.private.json e result.json (0600). Legge metadati systemd e configurazioni delle unità con custodia protetta. Conserva privatamente configurazioni potenzialmente segrete; restituisce soltanto stati, flag di revisione, conteggi e digest. Tre comandi systemctl di lettura,10s/call,1MiB/call,60s complessivi; max64configurazioni da256KiB; bozza massimo16MiB. Nessun corpo token o API Docker/IAM. Nessun comando di mutazione; non ha modalità apply.

Pinna il piano legacy1c0bb62c, derivato0f71ecd2, claim786b60aa e proposta62b2afd0 del tentativo consumato. Non modifica piani o scope, non rinnova scadenza1794081219 e rifiuta directory preparatoria preesistente prima delle query. La bozza non è snapshot atomico dello stato systemd e non autorizza un successivo stop: il mutatore dovrà riverificare le configurazioni e le condizioni correnti.

I dati aggiunti rispetto al reader precedente servono a scegliere il comando esatto: Type/Restart/KillMode/SendSIGKILL, ExecStop/ExecStopPost, configurazioni/drop-in, propagazione stop, Also e alias. Non è una ripetizione della prova di cifratura o del readback dei corpi runtime.

## Perimetro proposto e lavoro da completare

1. Impedire l'attivazione automatica dei cinque timer; attendere naturalmente le eventuali cinque esecuzioni oneshot entro un budget finito.
2. Contenere anche il servizio registry continuo; definire arresto senza SIGKILL e senza riavvio automatico sulla base della configurazione conservata.
3. Lasciare invariata la coppia semantic già masked.
4. Verificare tutti sei servizi inattivi; acquisire identità stabili delle cinque fonti e legarle a una nuova operazione esplicita, con lineage verso il tentativo consumato, stessi vincoli temporali e nessun reset dei budget precedenti.
5. Eseguire il core stop/capture Docker già qualificato, con controllo del contenimento host prima e dopo; mantenere offline, trasferire archivio cifrato al PC e provare restore isolato.

**Executor host e composizione della nuova operazione non ancora implementati.** La preparazione raccoglie e conserva quanto necessario a completarli; non richiedere approvazione di un mutatore inesistente. Prima dell'uso target servono implementazione/qualifica e decisione sull'esatto perimetro esteso. Non rilanciare il vecchio stop o capture.

I6test del nuovo preparatore verificano confini di lettura, redazione, custodia output, nooverwrite e vincolo al vecchio tentativo; non qualificano un fermo host. Nessun nuovo test Docker/restore/crypto riuscito viene ripetuto. Il difetto iniziale della fixture (helper run omonimo di unittest.TestCase.run) è corretto:6/6PASS locali, CI dedicata separata.

## Stato progetto

MiniPET invariato39,78%,0/8gate,0/21AT,0/120migrati;120corpi verificati. Questo blocco serve a ottenere il primo archivio reale, non chiude da solo G0/G3/G4. Nessun credito per la preparazione. Prossimi traguardi restano archivio reale → custodiaPC/restore → criteri migrazione, non ulteriori qualificheIAM.

CI generale del parent2db26f14: osservati48success,2incorso,1failure(run42299748754,job128174139252 sealed-worker): PROTOCOL_AUTHORITY_EXPIRED_OR_NOT_YET_VALID. Failure registrata, non ritentata né classificata risolta. Le3altre matrix del run risultanoSUCCESS. Separata dalle qualifiche storage pregresse.
