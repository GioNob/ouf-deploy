# Contenimento dei writer host per la prima copia non produttiva

## Qualifica corrente completata

[Run42304356159](https://github.com/GioNob/ouf-deploy/actions/runs/42304356159) SUCCESS:13unità sintetiche inattive,10configurazioni acquisite; symlink della registry fixture respinto da nofollow/ELOOP e conservato come finding. I campi ExecStop/ExecStopPost vuoti sono omessi anche con --all e restano null+rilievo. I2comandi ExecStop presenti restano privati. La bozza si completa con REVIEW_REQUIRED; replay della preparazione negato prima delle query. Nessuno start/stop,Docker/IAM. Non prova targetDebian13 o contenimento effettivo.

13unit test delrun42303969794step3 riusati per3digest esatti. Due fallimenti nativi42303969794/42304157404 erano aspettative fixture errate (11file e vuoto→false); osservazione reale salvata e aspettative corrette senza cambiare produzione. [Dossier completo](../evidence/storage-host-preparation-systemd-qualified-20261106.json),[prova nativa](../evidence/storage-host-preparation-systemd-native-20261106.json). Non rieseguire la qualifica riuscita senza modifiche.

Consegna preparatore18228byte/SHAcaac2981e43b96150bc0875405facfc4cb34ad8b188adc210e4ed214bb5bf5b1. Nessuna nuova area per aggirare esistenza,nessun fermo precedente rilanciato. Outputtarget ancora atteso. Se compaiono rilievi non sono accettazione; usarli per completare l'executorhost che resta da implementare.

## Secondo HOLD preparatorio: gestione delle proprietà

Il preparatore acb3425e ha prodotto PROPERTY_CARDINALITY prima delle scritture. [Ricevuta](../evidence/storage-host-containment-cardinality-held-operator-20261106.json). Il vecchio messaggio non identifica unità/proprietà: non sappiamo se fosse assente o ripetuta.

La correzione richiede show --all, distingue proprietà opzionali non note da proprietà vuote, conserva gli array ExecStop/ExecStopPost e restituisce rilievi con unità/campo/numero occorrenze, senza esportare valori privati. Proprietà critiche conservano verifica stretta e diagnostica specifica. Non ridurre missing a false o a lista vuota per approvare un mutatore.

[systemctl ufficiale](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) documenta l'omissione ordinaria dei campi vuoti; --all non rende presenti proprietà non applicabili o non supportate.13test locali PASS. Il vecchio mock assumeva presenza universale delle proprietà: lacuna corretta. Nuova prova di integrazione su systemd reale GitHubRunner:13unità sintetiche inattive,11configurazioni,maschere e frammento esterno; nessun servizio viene avviato/fermato. CI verificata nel paragrafo corrente; aspettative iniziali della fixture corrette dopo osservazione reale. Non è prova del contenimentoVPS e non ripete stop/restore/crypto.

## Correzione dopo il primo tentativo preparatorio

Il preparatore2adcde61 è stato respinto con UNIT_CONFIGURATION_PATH_REQUIRES_REVIEW, prima di creare la directory o scrivere la bozza. Nessun servizio modificato. [Ricevuta e limiti](../evidence/storage-host-containment-path-held-operator-20261106.json). Non conosciamo ancora unità/percorso specifici: il vecchio errore non li esportava.

Il vecchio filtro ammetteva solo quattro prefissi. [systemd.unit ufficiale](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) documenta unità collegate fuori searchpath e destinazioni con nomi arbitrari. Il preparatore corretto accetta i percorsi canonici dichiarati dal manager soltanto attraverso lo stesso lettore protetto e invariato: root, antenati protetti, nofollow, file regolare/singlelink/stabile e max256KiB. Esclude pseudo-filesystem e percorsi non canonici. Non segue collegamenti né indebolisce permessi.

Se il percorso è invalido o la custodia non è dimostrata, salva un rilievo redatto per unità/proprietà/hash percorso e continua le altre configurazioni. Questo NON trasforma un rilievo in accettazione; executor e autorizzazione restano assenti. Conteggio massimo64tentativi include gli insuccessi.

9/9test locali PASS, inclusi3nuovi casi esterno protetto/custodia respinta/percorso invalido senza lettura. Nessuna qualifica target fermo o capture. Area preparatoria invariata: se esiste viene rifiutata, mai eliminata o sovrascritta. Il nuovo comando esegue soltanto il preparatore corretto,non il vecchio stop/capture. Scadenza e quattro digest precedenti invariati.

## Risultato corrente

Il controllo sul VPS identifica cinque timer attivi e il collegamento ReadWritePaths alle cinque fonti runtime cambiate. I cinque servizi erano inattivi all'osservazione, ma i timer potevano riattivarli. Un sesto servizio OUF token, registry, era attivo. La coppia semantic era già mascherata. [Ricevuta riportata dall'operatore](../evidence/storage-runtime-writer-metadata-operator-20261106.json).

Questo rimuove l'incertezza sul perimetro minimo host da considerare: il fermo Docker da solo non basta. Non dimostra chi abbia scritto ogni byte o l'autenticità dei token. Includiamo registry nella proposta in modo conservativo, senza affermare che scriva nelle fonti backup.

## Preparazione concreta

Programma scripts/prepare-storage-host-containment-20261106.py,18228byte,SHA256caac2981e43b96150bc0875405facfc4cb34ad8b188adc210e4ed214bb5bf5b1.

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

I9test del preparatore corretto verificano confini di lettura, redazione, custodia output, nooverwrite e vincolo al vecchio tentativo; non qualificano un fermo host. Nessun nuovo test Docker/restore/crypto riuscito viene ripetuto. Il difetto iniziale della fixture (helper run omonimo di unittest.TestCase.run) è corretto:6/6PASS locali, CI dedicata separata.

## Stato progetto

MiniPET invariato39,78%,0/8gate,0/21AT,0/120migrati;120corpi verificati. Questo blocco serve a ottenere il primo archivio reale, non chiude da solo G0/G3/G4. Nessun credito per la preparazione. Prossimi traguardi restano archivio reale → custodiaPC/restore → criteri migrazione, non ulteriori qualificheIAM.

CI generale del parent2db26f14: osservati48success,2incorso,1failure(run42299748754,job128174139252 sealed-worker): PROTOCOL_AUTHORITY_EXPIRED_OR_NOT_YET_VALID. Failure registrata, non ritentata né classificata risolta. Le3altre matrix del run risultanoSUCCESS. Separata dalle qualifiche storage pregresse.
