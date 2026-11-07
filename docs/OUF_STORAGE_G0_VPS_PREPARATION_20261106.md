# G0 — preparazione privata sul VPS, 6 novembre 2026

Giovanni opera sul VPS; GitHub Actions resta il canale CI/CD. Il checkpoint59a523b6 è51/51SUCCESS, source PR54d5155899 invariata. Le osservazioni del VPS qui riportate provengono dall'output dell'operatore: Debian13/x86_64, Python3.13.5, uid1000 con accesso locale al socket Docker; installato solo client PostgreSQL17.11 e dipendenze. Download del pacchetto e manifest SHA256 confermati. Le ricevute13–17 esistono come root:root0600. Non sono osservazioni agent dei servizi correnti.

## Preparazione consegnata

Script `scripts/prepare-storage-g0-private-20261106.py`, SHA256 `700a3e7461208bcd921270dc01d5ade29d879ae34bbe6078b5242082d50fe25d`. Il bundle qualificato e tutti i suoi12file restano byte-identici. Il preparatore si esegue come root con Python isolato, senza argomenti; legge `/home/oufadmin/ouf-g0-package-e7c46c73.tar.gz`, verifica digest archivio/manifest/tutti i membri prima di scrivere. Legge solo i17 `result.json` storici, al massimo2MiB ciascuno, tramite percorsi esatti ricostruiti dai producer del commit59a523b6. Esige file regolari root:root0600, niente symlink o hardlink, ascendenza protetta e stabilità. Verifica il numero cumulativo se presente. Non importa né esegue alcun producer storico.

Crea esclusivamente `/var/lib/ouf-g0-preparation-20261106`, con directory0700 e sottodirectory `package`, `inputs`, `evidence`. Package root-owned0400, binario0500; bozza `inputs/package-input.json`0600. `priorReceiptFiles` contiene17path/digest; config private puntano ai futuri file della sola nuova directory. OperationId, installationRef, ruoli, capacità, documenti operatore e decisione restano da compilare. Nessun file di credenziali creato o letto; nessun cambio di owner/mode sui file preesistenti.

Il comando non invoca `check`, `collect`, Docker, S3, SQL, nsenter o launcher consumati. Nessun endpoint/servizio installato, grant, riavvio, migrazione, nuovo scope di raccolta o reset. La copia privata è preparazione di file, non deployment. Il percorso di esecuzione root è necessario per leggere le ricevute root0600 senza mutarne la custodia; la shell di oufadmin può continuare a gestire il passaggio tramite sudo.

Esito atteso `DRAFT_STAGED_BINDINGS_REQUIRED`; non equivale a preflight PASS. La cartella preesistente viene respinta senza sovrascriverla. Un errore prima dello staging non crea la cartella; un errore dopo l'inizio conserva il parziale, non effettua cleanup o rigenerazione automatica. I digest correnti preservano riferimenti e stabilità, non attestano da soli integrità storica rispetto a un digest originale autenticato.

## Verifica e stato

Cinque casi locali con filesystem sintetico: preparazione e17binding, rifiuto destinazione esistente, permessi difformi, symlink e numero controllo errato; custodia/storia preservate, zero provider request. Package originale già qualificato; nessuna ripetizione dei laboratori provider. [Ricevuta](../evidence/storage-g0-vps-preparation-20261106.json). Esecuzione sul VPS **ancora da ricevere**, non presunta riuscita.

Prossimo passo operativo: preparare la bozza, poi completare i binding correnti e verificare rete host/profili e input privati. Solo dopo `check` e review dell'intento esatto si può sottoporre la raccolta al gate applicabile. La presenza di Giovanni sul VPS non costituisce automaticamente approvazione HUMAN runtime. MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali; nessun credito aggiunto.
