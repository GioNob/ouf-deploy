# Farmacie — riuso del controllo peer già qualificato e due STOP conservati

27 ottobre 2026, Europe/Rome. Il secondo STOP è `EXACT_CURRENT_ROOT_ENGINE_PEER_CREDENTIALS_REQUIRED`, Exit2/DeliveryExit2, prima della review. [Ricevuta e ricostruzione circoscritta](../../evidence/onboarding-pid1-peer-stop-target-20261027.json). La consegna fd831393 e il suo scope sono CONSUMATI: non rilanciare. [Handoff precedente](OUF_FARMACIE_DIAGNOSTIC_PEER_CONTINUATION_20261027.md), che contiene tutti i riferimenti a capture, preparazione, primo STOP e reader consumati.

## Difetto e riuso effettivo

L'hash del peer già conservato `7ff52993d5d3cb149089942de7fc7a6511db2671cf2125976c081ad6fff89772` è il SHA256 canonico di `[1,0,0]`. Non serve un'altra lettura VPS per identificarlo. Il nuovo guard `peer[0]>1` era un errore del controller. I [trasporti MCP già usati](https://github.com/GioNob/ouf-deploy/blob/b9697462f293d7481c9fd7cdd84c549b70214eda/tools/mcp_diagnostic_update/transport.py), redazione e acquisizione verificavano già la tupla completa ed UID0 senza escludere PID1. Si riusa quel comportamento; un PID strettamente positivo è valido. Non viene dedotta la ragione per cui il peer osservato sia PID1.

Socket/custodia e hash storici rimangono identici; ogni connessione corrente verifica la tupla completa esatta e UIDroot. Nessun cambio al trasporto live, nessuna normalizzazione generica, nessuna eliminazione del peer dai binding.

## Catena conservata, senza reset

Primo scope: `/etc/ouf/deploy-snapshots/onboarding-diagnostic-update-c22586172070809d-v1`, tre tentativi metadata. Secondo scope: child `retained-peer-credentials-continuation-v1`, otto ulteriori tentativi, payload cumulativi4–11. Sono entrambi pre-review, non emettono authority/journal e non costruiscono Engine. Il nuovo controller deve verificare inventari esatti, claim, tutti gli undici tentativi, il reader già conservato, manifest e21 fonti root0400 del secondo controller più il suo log root0600. Un effetto/authority/file inatteso comporta STOP; nessun vecchio file modificato.

Nuovo scope esclusivo: child `pid1-peer-continuation-v1` sotto il secondo scope. I contatori partono da11 nello STESSO massimo64:37 verifiche conservate,4 metadata piano e2 authority pubblica portano54 prima della review; altre2 ri-validazioni pubbliche dopo consenso portano56. Lettura contenuto YAML owner1 separata; quattro SQL tecniche READONLY restano condizionali e successive alla nuova approvazione. Il reader già consumato7metadata+22fonti/manifesto rimane una procedura separata, mai rilanciata.

## Stato e prossima azione

Correzione in qualifica CI; nessun nuovo comando qualificato consegnato in questo checkpoint. Test unitari17PASS; il socket PID1 kernel reale e il ciclo firmato Docker29.8.1/Postgres17 classic/containerd devono completarsi. Workload e chiavi CI sono sintetici: nessuna prova VPS/E2E.

Dopo qualifica: prima esecuzione della sola NUOVA consegna, checksum, copia root0400, log conservati, review concreta e `APPROVO <hash fresco>` realmente inserito nel terminale con Invio. Nessun consenso passato dal wrapper; il prompt editabile già provato viene riusato. Se STOP conservare e non rilanciare.

La stessa immagine minima diagnostica Onboarding074bd16e è già preparata e non viene ricostruita/relabelled. Preservare35migrazioni/nove tabelle/job FarmacieFAILED tentativi5, configurazione/risorse/MAC/IP/porte, tutti i peer Registry/MCP/worker/READ/Gateway. Non avviare candidato M2 più ampio, nuovo upload/profiling/acquisizione, grant o attivazione. Nessun rollback automatico. Policy54 scaduta: questa manutenzione non concede READ di dominio e non autorizza SQL per leggere la causa del job.

M1/G4 resta acquisito: due run Teatri,26join,13identità/20proprietà,8Cinema preservati. M2 resta aperto; causa Farmacie ignota. [Audit del riuso](../OUF_M2_CODE_EVIDENCE_GAP_AUDIT_20261026.md). No subagenti, automazioni, merge o release acceptance; Supervisor dopo E2E completo.
