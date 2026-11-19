# Tappa funzionale CSV1: diagnosi della consultazione semantica 503

Il rollout tecnico ha superato le otto fasi, ma il ciclo CSV rimane0/6.
Il nuovo MCP legge l'asset/profilo Teatri esistente (13righe,20colonne) e riporta
MCP HEALTHY nel suo snapshot operativo. semantic.search con qTeatri/limit20
restituisce503 senza dettaglio utile. Non si può dedurre una causa né creare
una sorgente con riferimenti semantici non verificati. Nessun nuovo upload,
profilo, proposta, sorgente o decisione HUMAN applicativa è stato creato.

Il lettore è specifico della review07ee9e8adf0d645018fb70212884f43c22e85cf3c7288bd78dad5bf0d02413bc,
autoritàa604f4981d38dc19977e551402674b70146bca8768df07c631c2054c6cc727ca,
contesto16e5f80e40d09772048f1575850b643a69d4d46520db1a56ccd79a7b1a9e055b.
Richiede l'invocazione systemd attiva con mainPID3733354; non la ferma.
Legge il bundle firmato, i journal Gateway completati e due mappe complete,
la generazione Registry, i riferimenti Lua di delega/owner e la selezione envs
NGINX custodita. Pubblica solo presenza, formato hex64 ed esposizione dei nomi,
mai nomi/valori delle chiavi. Legge al massimo200 righe bounded per ciascuno dei
log Gateway e Registry a partire dall'issuedAt della stessa autorità; pubblica
solo conteggi HTTP per quattro route contrattuali e marcatori fissi. Non pubblica
righe grezze, percorsi, credenziali, corpi o messaggi d'eccezione. Un marcatore
non è da solo una diagnosi della causa; il codiceHTTP storico non è inventato.

Nessun restart, stop/start/create, dump, restore, chiamataDB/IAM/MCP o nuovo
grant; nessuna modifica a route/permessi/configurazione, claim o budget.
Massimo180secondi, due GET Gateway e due letture log, con limiti di tempo/byte.
Trasporto e custodia sono identici per AST a quelli già qualificati; endpoint,
socket, config e chiavi restano derivati dai piani approvati. I pin storici
servono a selezionare questa installazione e non sono default di altri Enti.
Finestra12:57:06 Europe/Rome invariata, senza rinnovo automatico o accettazione
permanente. Eseguire in una seconda sessione lasciando il terminale rollout attivo.

Fonte7819b872769b096d266bd2eec12994563649ce12.
ReaderSHA2568061740bad6cd54d9ea11d420a6ae1d6783ff4a2b03622f70a3af0568096c5fb.
LauncherSHA2560d9dc8f546e12681eea9d574a4f614b01d5fa09af440ae3359de9fe192bfd115.
CI38886152124/job116924263413 PASS:50test senza skip. Sette nuovi test con
file privati reali e osservazioni Docker/Gateway simulate, redazione chiavi/log,
processoattivo, deriva journal e mancata esposizione env. Le prove native ereditate
coprono namespace e PostgreSQL; il nuovo main non chiama PostgreSQL. Nessuna
qualificaCI modifica o prova il contenuto del target.
