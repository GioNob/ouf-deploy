# OUF — Roadmap M2 basata sui delta, revisione 1.1

26 ottobre 2026 · Europe/Rome. [Mini-PET completo e matrice di riuso](OUF_M2_MINIPET_v1_0_20261026.md) · [Registro](../releases/csv-m2-plan-20261026.json).

**M1 è acquisito. La pipeline, le letture owner, l'identità e la provenienza provate sul caso Teatri sono la base di M2 e non vanno ricostruite.** I sei WP organizzano il residuo di integrazione e collaudo; non indicano sei sviluppi nuovi.

## Percorso residuo

| Ordine | Azione | Cosa riusiamo | Uscita richiesta |
| --- | --- | --- | --- |
| 1 | Diagnosticare e correggere il FAILED Farmacie | Stesso asset/job, profiling e storage esistenti; candidato diagnostico PR52 | Causa owner provata, fix mirato e recupero governato; nessun reupload o reset |
| 2 | Comporre il percorso autoguidato | Upload, stati, proposta, review, capability e letture esistenti | Niente passaggi tecnici manuali, link corretti, contesto ritrovabile e diagnosi comprensibile |
| 3 | Completare solo i delta semantici necessari | Mapping e trasformazioni già implementati, Registry e bundle | Profilo Farmacie valido; vocabolari/gap/relazione semplice qualificati dove non già coperti |
| 4 | Eseguire il nuovo percorso fino a UDP | Pipeline e riconciliazione owner provate in M1 | Tutte le 61 righe rendicontate e oggetti consultabili; correggere solo difetti osservati |
| 5 | Colmare le prove di ripetibilità/ripresa | Identità, journal, dedup, controller e test esistenti | Configurazione invariata senza revisioni gratuite; fault/nuova chat/budget provati senza riscrivere i motori |
| 6 | Collaudare due client e chiudere il dossier | Prove M1 e qualifica compatibile dei moduli | G5/G6/G7 e decisione HUMAN su M2; nessun merge o release acceptance |

Durante un'attesa si può preparare lavoro indipendente. Non si superano gate, non si eseguono azioni runtime implicite e non si contano due volte attività già concluse.

## Metodo di avanzamento

Per ciascuna voce: **codice esistente → prova riusabile → limite → delta concreto → nuovo test → ore residue**.

- Una prova M1 valida si conserva; una regressione si ripete soltanto per un impatto motivato.
- Un requisito non ancora accettato per M2 non dimostra assenza di implementazione.
- Una prova mancante è collaudo; collegare capability esistenti è integrazione; nuovo codice è stimato solo per lacune dimostrate.
- M1 ha usato due configurazioni differenti: identità conservate è già PASS, mentre no revisione gratuita a configurazione invariata resta una prova specifica.
- La matrice di riuso del mini-PET distingue proprietà già osservate da casi di conflitto/autorità/multi-fonte non coperti dal solo dossier Teatri.

## Stima corrente

**La stima 34–58 ore, centrale 46, e la riserva 8–16 della revisione precedente sono ritirate.** Mancava un inventario sufficientemente puntuale dei delta rispetto al già realizzato. Anche le finestre H+ e le giornate derivate non sono più il piano corrente.

Le 40–70 ore della baseline includevano M1 e restano storiche. Non diventano il residuo di oggi. Il nuovo residuo sarà stimato dalla causa Farmacie e dalla matrice di riuso; al momento è non determinato, senza un numero sostitutivo inventato.

## Criterio di arrivo

Un utente carica il file, verifica la proposta, decide solo le ambiguità e approva gli effetti necessari; il sistema gestisce le fasi tecniche e conserva il lavoro. Esito UDP verificato, ricerca minima, reimport senza duplicazioni, recupero e due client reali sono obbligatori. Nessun terminale, SQL o copia manuale di ID/log nel percorso ordinario.

La fusione di due oggetti canonici già esistenti, la ricerca avanzata e Supervisor restano estensioni separate. Riconciliazione multi-fonte e consultazione minima sono dentro M2.

**Prossimo passo:** diagnosi owner minimizzata dello stesso FAILED Farmacie; censire contestualmente le prove riusabili per attribuire soltanto il lavoro mancante. Nessuna nuova profilazione, terza acquisizione Teatri, reset o vecchio APPLY da rilanciare.
