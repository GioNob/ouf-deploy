# Farmacie — grant SERVICE scaduto provato; correzione strutturale in review

27 ottobre2026, Europe/Rome. [Lettura target](../../evidence/farmacie-service-policy-read-target-20261027.json), Exit0/DeliveryExit0. [Checkpoint precedente](OUF_FARMACIE_OBJECT_READ_FORBIDDEN_20261027.md). Policy55, hash b126492af85039fba88c0de4cc888bad3603356e3dcc07e6be1d4240fcc0c6ce, osservata27ottobre16:07:21 Europe/Rome. Descriptor READ/SERVICE/scope atteso coerenti. Unico matchingServiceGrant per ouf-onboarding/ouf.object-storage.content.read: grant-managed-file-read-onboarding, scaduto25ottobre2026 00:00Z; nessun ALLOW configurato corrente in quel set. Questa è prova della policy, non una nuova richiesta Gateway né prova del token workload o dell'esclusiva causa del403 storico.

## Lettura consumata

Scope /etc/ouf/deploy-snapshots/farmacie-service-policy-read-20261027-v1 CONSUMATO, non rilanciare o rimuovere claim.1GET IAM/5POST IAM/1GET owner/115286byte. Zero Engine/SQL/credenziali file/chiavi/filebytes/preview/profiling/job/grant/attivazioni/acquisizioni. Log /usr/local/lib/ouf-farmacie-service-policy-read-ad582e403e4a8016/operator.log; bootstrap /home/oufadmin/ouf-farmacie-service-policy-delivery.njwjARCn/bootstrap.log. Anche preview55, tutte le APPLY, capture e preparazioni precedenti sono consumate.

## Correzione scelta dopo osservazione dell'owner

L'owner contesta che la lettura ordinaria di un servizio dipenda da un grant breve da rinnovare manualmente. Non è stata creata alcuna nuova proposta temporanea SERVICE. Distinguere token breve rinnovabile, permesso strutturale del servizio revocabile, e budget finito delle singole esecuzioni. Il contratto AuthorizationPolicy.Grant richiede validUntil nonnull: il nuovo permesso usa l'orizzonte2036 già presente nei permessi strutturali della piattaforma; non viene spacciato per un contratto senza scadenza né per prova di monitoraggio della scadenza già implementato.

[Proposta concreta](../../evidence/onboarding-structural-object-read-proposal-20261027.json): nuovo grant service-onboarding-managed-file-read-structural-v1; SOLO capability READ ouf.object-storage.content.read, SERVICE ouf-onboarding, tenantouf-lab, subjectnull, constraintsnull come il vecchio profilo di servizio. ValidFrom 2026-10-27T14:14:50.000Z, validUntil2036-09-15T07:13:50.968730Z. Il vecchio grant scaduto resta nella storia e nella policy; nessun altro grant/ruolo/assegnazione/IAM/token modificato dalla richiesta. Ingestion escluso: la sua eventuale scadenza live non è stata letta e non va rinnovata per ipotesi.

Proposta b045ada2-f1d6-4e4e-9beb-acf85d6474f7 r0 PENDING/finalPolicyRefnull, riletta stessoID. [Decisione HUMAN diretta THS](https://api.ouf-lab.it/trusted-human/authorization/?proposal=b045ada2-f1d6-4e4e-9beb-acf85d6474f7) entro27ottobre16:29:59 Europe/Rome. Nessuna approvazione/pubblicazione da parte dell'assistente. Dopo decisione, leggere STESSO proposalId; se scade/rifiutata, conservare senza riproporre automaticamente.

## Limiti e prossimi delta

Il grant strutturale consente la sola lettura staging al servizio nel tenant; non è vincolato al singolo file/job dal contesto capability installato. Ogni uso continua a richiedere identità/token/scope validi e controlli Gateway/owner; non li aggira. La pubblicazione non crea una sessione di esecuzione o budget, non resetta i cinque tentativi, non ripete il job FAILED e non prova E2E.

D4 resta concreto: il worker attuale cattura ogni Exception e ritenta anche il403 fino5volte. Qualificare classificazione permanente/transitoria e ripresa HUMAN con nuova sessione finita sullo stesso logical operation/incident, conservando storia/cumulativi e fencing; nessun nuovo job per aggirare FAILED e nessun reset a zero. Distinguere correzione permesso da autorizzazione alla ripresa.

D2/D7 devono verificare anche i prerequisiti autorizzativi dell'intera coorte prima di lanciare il CSV, inclusi scadenze, assenza grant correnti e dipendenze mancanti. Non inventare prova live di altri servizi dai cataloghi. Monitoraggio/scadenza e readiness preventiva restano da qualificare; non lasciare che un problema strutturale diventi errore parser o consumi automaticamente il budget.

M1/G4 acquisito, M2/G5/G6/G7 aperti. Diagnostica minima installata; codice typed/ASSETS/LATEST/recovery/UDP riusabile. No merge/release acceptance/subagenti/automazioni/Registry restart/reinstall; Supervisor dopo E2E completo.
