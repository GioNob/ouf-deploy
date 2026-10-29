# Continuità M2 discovery — 29 ottobre 2026

Il contesto operativo è conservato in questo handoff e nelle revisioni GitHub. La segnalazione dell'utente riguarda la visualizzazione della chat dopo le 9:11; non è prova di perdita del repository o dei risultati target.

- Custodia target riuscita e CONSUMATA: quattro materiali e quattro pin, candidateBindingHash `eed64887cfcf18dc4be6de32c954b67649adf72ff384c3296d4bfe21ba1188c5`. Candidati verificati, ancora NON ammessi. [Esito](../../evidence/m2-discovery-custody-target-20261029.json). Fonte JSON/footer operatore, nessuna lettura indipendente del record privato.
- PR54: proiezioni private, profilo completo con sette mount, witness e owner nodo discovery. Sorgente corrente `12ec4870a8febcebfa96a06ef43b233570e2dfc3`, nessun merge. Proiezioni compilate da record privato esatto, nessun segreto richiesto in chat e nessuna copia ancora eseguita sul VPS.
- Qualifica selezionata: 114 test PASS/0skip, run40854229009/job123381048153, log letto.
- Regressione ampia: 585 test, due skip TLS espliciti, run40855597338/job123385640094. 63 processi test indipendenti; flag -I/-B/-S preservati, dipendenza crittografica apt root esposta esplicitamente. Native Docker paused e PostgreSQL separati PASS. Gli originali paused_node_observation/paused_workload_binding sono ripristinati byte-esatti; i nuovi tipi discovery sono in moduli distinti. Non indebolire loader o membership dei capsule storici.
- Attestazioni MCP/Gateway: run40854222625, entrambi job SUCCESS/log letti; artifact12888671353/12888592058 scaricati, ZIP e subject confrontati con tutti i byte originali, otto/undici receipt letti. Verifica crittografica nel runner, non ripetuta localmente. Fiducia publisher nativa e ammissione target restano separate.
- Rootfs Registry: prima prova40856064980 STOP prima del container perché Docker29/containerd usa identità manifest, non config digest del package. Correzione in `12ec4870a8febcebfa96a06ef43b233570e2dfc3` riusa image_custody.archive/tagless_archive/native_identity/loaded già qualificati, nessun rebuild o modifica config/layer. Nuova CI da verificare, NON dichiararla riuscita. Tutti sette target sono una proposta esplicita; input privati sintetici e nessun Java.
- MCP ouf.system.status su ouf-admin: HEALTHY, senza actionRequired; non dimostra disponibilità discovery. Le tre capability discovery non sono ancora esposte da questo connector.

Prossimo lavoro: completare qualifica rootfs esatta e preparazione coordinata, con trust pubblico IAM+provider, chiavi distinte, rete/DB/cohort e generazioni correnti, backup/fencing e integrazione dell'esecutore completo a tredici fasi e worker distinto. Poi review/HUMAN e authority native finite al momento necessario. Nessun nuovo comando operatore pronto.

NON rilanciare scope custody f759 o installation f759/14e42, cancellarli o ricrearli. Nessun login/token/finestra anticipata, replay, budget reset, grant o authority riusata. Nessun effetto target di questi cambi sorgente. Tutte le decisioni Farmacie restano confermate: codice_ministeriale STRING chiave stabile, CAP STRING, dieci proprietà OPEN; stesso asset/job/profilo già SUCCEEDED.

M1/G4 acquisiti; M2/G5–G7/D5–D7, otto criteri di stabilità ed E2E restano OPEN. Flusso obbligatorio ChatGPT→MCP OUF→Gateway→Registry→OntoPiA. Nessun bypass web/Turtle/ontologia inventata. Nessun merge, acceptance, subagente o automazione.

[Checkpoint strutturato](../../evidence/m2-discovery-continuity-20261029.json).
