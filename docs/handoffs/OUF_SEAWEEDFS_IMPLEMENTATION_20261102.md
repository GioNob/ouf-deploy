> **Checkpoint laboratorio acquisito:** source9fa8c7f0, CI41385154842/job125084251041 SUCCESS; log finale letto.16test Python,4Go e7Java senza failure/error/skip. Due binari scansionati, tool inventario zero findings; server rawgate HELD1UNKNOWN OpenPGP non importato. Inventario1009record,2051richieste su soli dati sintetici, versioni/delete marker e configurazioni bucket; rilancio negato. Ripristino da copia indipendente dati+filer con lettura di ogni byte fixture PASS. Riletti intero ZIP278.488.850byte/SHA5e14ecdc,27membri checksum e tutti4390Gitblob/mode dell'upstream contro albero API indipendente. Firma publisher ancora da verificare indipendentemente; niente ammissione target/release. Audit sourcebody6moduli:1335file testuali,86file corrispondenti; CI41383597163 SUCCESS, artifact e checksum riletti. In preparazione TLS frontend, policy prefisso e prova POST di diniego. PET UDP§81 fornisce già obiettivi iniziali DB-RPO900s e core-RTO14400s, da validare sull'infrastruttura scelta; evitare domanda generica ripetuta all'owner. Scope12/35GET invariati.

# SeaweedFS — sostituzione avviata, qualifica pubblica in corso

2 novembre 2026, Europe/Rome. L'owner ha chiesto di eseguire il MiniPET e proseguire autonomamente, con aggiornamenti costanti. Questa è autorizzazione allo sviluppo e alla qualifica; gli effetti sul target restano nei contratti OUF correnti.

## Risultati acquisiti

- Ricognizione dei percorsi storage in sei generazioni pubbliche esatte, registrata in `releases/seaweedfs-public-source-audit-20261102.json`. È discovery per percorso, con lettura dei corpi degli adapter e degli strumenti citati, non audit esaustivo di tutto il codice. Trovata anche dipendenza MinIO della CI Ingestion e capability interna del Gateway con owner onboarding e `toolEligible:false`.
- Nuovo workflow `seaweedfs-evaluation.yml`: verifica SHA256/47.534.485 byte dell'asset upstream4.51, conserva sorgente separato, legge build-info Go senza eseguire il server, scansione reale rootfs e controlli fail-closed.
- Primo run41382233355 respinto per inventario Go vuoto (scan fs): nessuna falsa affermazione zero vulnerabilità. Secondo run41382483287/job125076082630 rileva1HIGH e3UNKNOWN; immagine mai eseguita. Intero ZIP177.804.806 byte/SHA bcc6ba3e verificato, ogni membro checksum riletto, metadati originali conservati. Dossier `evidence/seaweedfs-upstream-security-held-20261102.json`.
- Nuova build distinta, source bd0de83e/run41382769649/job125076949361: stesso upstream153ab668, Go1.27.3, CGO0; cambiano soltanto go.mod/go.sum, JOSE4.1.6 e x/net0.62.0. Scan reale zeroHIGH/CRITICAL,1UNKNOWN. Gate grezzo HELD, non qualificazione release. Pacchetti compilati1738, OpenPGP non importato. Non si dichiara uguaglianza con il binario vendor.
- Libreria offline per inventario/migrazione: collisioni file/directory, chiavi pericolose, versioni/marker, hash e confronti con mapping version ID. Dieci test locali PASS. Nessuna lettura S3 o Engine, nessun dato privato introdotto.
- Fixture Java pronta con i CINQUE file originali delle porte/adapter OUF, copiati dai due commit esatti, client MinIO8.6.0 e AWS2.54.17. Cinque prove previste: staging+limiti, multipart10MiB, UDP metadata/byte/delete, inventario1003, dinieghi bucket/credenziali. Non ancora eseguite al checkpoint iniziale di questo handoff.

## UNKNOWN e laboratorio

GO-2026-5932 riguarda specificamente `golang.org/x/crypto/openpgp` e sottopacchetti, non ogni uso del modulo x/crypto: fonte primaria https://pkg.go.dev/vuln/GO-2026-5932. Il grafo compilato della build non contiene tali pacchetti. Si prepara una valutazione di applicabilità legata agli hash del binario e del grafo, senza modificare/filtrare il rapporto Trivy.

Una nuova verifica stretta consente SOLTANTO diagnostica sintetica loopback quando gli unici rilievi bloccanti sono esattamente questo advisory/modulo UNKNOWN e nessun pacchetto OpenPGP è importato nella build CGO0. Qualsiasi altro UNKNOWN/HIGH/CRITICAL resta negato. Gate grezzo HELD e `releaseAdmitted:false` restano nel record; questo non chiude SW-G1 o SW-AT01 e non autorizza target o release. Sei test proteggono parser e delimitazione diagnostica.

La fixture non qualifica TLS, policy di prefisso, ripristino, reboot, backup, immagine OCI o l'applicazione OUF completa. Credenziali sintetiche, endpoint esclusivamente loopback, dati fittizi; nessun file Teatri/Farmacie copiato nel laboratorio. L'adapter originale viene compilato, senza riscriverne il comportamento per far passare la prova.

## Continuazione

Leggere esito e log finali del nuovo run; risolvere eventuali difetti del laboratorio e dei contratti. Verificare indipendentemente checksum, sorgente/pacchetto e attestazione prima di ammissioni. Ampliare policy, TLS, fault/restart/restore e packaging. Preparare l'inventario target in un'unica consegna concreta; non chiedere microdiagnostiche mentre prosegue lavoro indipendente.

SW-G0…G7 e21AT ancora OPEN. Inventario privato di tutti bucket/versioni/consumer/capacità non ancora acquisito. Nessuna shell VPS disponibile all'agente. Scope12 consumato,12controlli/35GET invariati; pin235/19/17/21/23 preservati. Teatri/M1 e stessa Farmacie61/10OPEN/STRING preservati; M2/G5–G7/dueclient OPEN. Nessun replay/reset/grant, deploy, merge o release acceptance.
