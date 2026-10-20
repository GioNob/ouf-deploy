# OUF CSV E2E — cronostoria effettiva

Baseline congelata: [Mini-PET v1.1](OUF_CSV_E2E_COMPLETION_MINIPET_v1_1_20261020.md), commit d190193773116c9a59403aa42ccc9f89423eb959. Il [registro eventi](../evidence/csv-e2e-execution-timeline-20261020.json) conserva timestamp, intervalli e riferimenti delle prove. Le previsioni originali non vengono riscritte per adattarle al consuntivo.

Origine della sessione: **20 ottobre 2026,11:07:49 Europe/Rome**, timestamp della richiesta di avvio. Non è una misura al secondo della prima operazione dell'agent. La richiesta di tracciamento è arrivata a11:11:55; la marcatura dedicata inizia a **20/10/2026, 11:16:46**. I passaggi precedenti non dotati di un timestamp proprio hanno estremi noti e precisione dichiarata; non sono retrodatati arbitrariamente.

## Checkpoint attuale

| Elemento | Baseline centrale | Osservazione effettiva | Stato |
| --- | ---: | --- | --- |
| G0: selezione/baseline | H+0,5 | 20/10/2026, 11:16:46: checkpoint dei riferimenti e vincoli completato | PASS, solo repository/baseline |
| WP1: qualificazione CI | Fino a H+3 | Già in lavorazione nel periodo iniziale; primo checkpoint dedicato 20/10/2026, 11:16:46 | IN CORSO |
| G1 | H+3 | Correzioni test preparate; CI fresca Ingestion/MCP pendente, closure Deploy da qualificare | APERTO |
| G2/G3 | H+14/H+19 | Nessuna nuova qualifica completa o ammissione target | APERTI |
| F5 / F6-M1 | H+22 / H+24 | Nessuna nuova acquisizione eseguita | APERTI |
| G5/G6/G7-M2 | H+35/H+46/H+55 | Attività successive non iniziate | APERTI |

## Risultati e metodo di misura

- Sei branch owner selezionate corrispondono agli head fissati; Deploy è sulla baseline documentale d190193.
- Ingestion: preparato isolamento transazionale delle schedule nei test e una prova esplicita fra tenant. Commit 8a15d8c7e7c20fac09ea18b3a1013f659934f128; qualifica CI ancora richiesta.
- MCP: soglia25ms e80misure conservate, prova LAN obbligatoria non strumentata distinta dalla suite race. Commit e7e9d961a7555b149a760299a0fe183c8bf4eccb; qualifica CI ancora richiesta.
- Deploy: recuperato lo snapshot HUMAN esatto dalla revisione45b78c009aca4f9a93b1ffbfafffd74a3b4555e5; hash uguale al pin storico11dc195dfa0f.14test locali PASS; non equivale ancora alla chiusura completa della capsule.

Da questo checkpoint si annotano intervalli attivi, attese passive, inizio/fine dei WP e chiusure dei gate con evidenze. Il tempo di calendario dalla richiesta è distinto dall'effort tecnico; l'intervallo iniziale non segmentato non diventa automaticamente effort misurato. Le ore HUMAN sono registrate separatamente quando note. Una attesa CI sovrapposta ad altro lavoro tecnico non si somma due volte.

Stato conservato: **tecniche8/8,funzionali4/6**. Nessuna operazione target, nuovo login/refresh/reset o replay. Owner7/projection7 e tutti i contesti/claim storici restano invariati.
