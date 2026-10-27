# STOP acquisito: riconciliare la mappa peer conservata

27ottobre2026, Europe/Rome. [Ricevuta target](../../evidence/managed-csv-recovery-peer-map-stop-target-20261027.json). Predecessore [custodia/coorte](OUF_MANAGED_CSV_RECOVERY_CUSTODY_CAPTURE_20261027.md) SUPERATO per prima esecuzione.

La cattura è stata eseguita: tre checksum ROOT400 corretti,3metadata/483676byte letti,0Engine/0write, STOP_RECONCILE/EXACT_RETAINED_COHORT_REQUIRED, Exit2/DeliveryExit2. Scope /etc/ouf/deploy-snapshots/managed-csv-recovery-control-inputs-20261027-v1 CONSUMATO. Non rilanciare vecchio comando/wrapper. Non chiedere log APPLY36 o rifare APPLY/publisher.

Errore del consumer: cercava mcp fra le chiavi; Context.current reale della V36 emette onboarding e peer-<prime16cifre containerId>. La fixture precedente ripeteva l'assunzione e non provava questa compatibilità. Correzione persistente nel modulo condiviso: esatto numero13, chiavi peer canoniche, ID distinti e UNICO MCP attraverso hash completo bindingf5a01443...+native9a1af5be.... I nomi conservati restano intatti, alias di destinazione in mappa separata. Nessuna selezione per solo nome/immagine o adozione di peer arbitrari.

Nuovi test eseguono il metodo current() del producer effettivo e la funzione stable_binding() del suo helper; fixture native13 deve riprodurre il vecchio stop col vecchio consumer esatto5c390e... PRIMA di Engine, poi superare la riconciliazione.11test localiPASS; qualifica CI della nuova consegna ancora da completare.

Nuova riconciliazione figlia /etc/ouf/deploy-snapshots/managed-csv-recovery-control-inputs-20261027-v1/reconcile-retained-peer-binding-v1. Legge hash esatti di claim/result dello stop consumato, preserva tutti i file precedenti; poi i3metadata V36. Massimo5NUOVE letture metadata e27GET Engine; contabilità cumulativa8metadata,27Engine, byte vecchi+nuovi. Runtime/job budget restano separati e intatti. Source e custodia immagini qualificate rimangono acquisite; nessuna modifica Onboarding/MCP applicativa o import sul VPS.

Proseguire autonomamente con qualifica CI e consegna root400/checksum ROOT prima di fornire all'operatore UN nuovo comando di riconciliazione. Zero SQL/OAuth/credenziali/chiavi/import/lifecycle/grant/budget/resume/acquisizioni; Engine Config/Env solo in metadata privati, non stampati. Nessuna authority/review precedente riusata. THS esclusiva utente. FarmacieFAILED5 ultima prova; M1/G4 acquisiti, M2/G5/G6/G7 aperti; no Registry restart/reinstall, nuovo job/upload/terza acquisizione, merge/release acceptance/subagenti/automazioni; Supervisor dopo E2E.
