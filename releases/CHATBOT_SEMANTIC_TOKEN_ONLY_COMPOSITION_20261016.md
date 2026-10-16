# Componente di continuazione token-only

## 16 ottobre — candidato target verificato; composizione token-only in qualifica

Fasi tecniche8/8 conservate; funzionali0/6.
Preparatore candidato v2 ENDcomplete=true. Artefatto privato:
/etc/ouf/deploy-snapshots/semantic-session-candidate-048rn2ec/candidate.json,
SHA256 0f89461b7ec0d34078dbacc28d3281c935ca2f5c60dd185f2f763f4ffd3650b4,
reviewbeefc7f2ee79fa70c5b416d6d3efe68d3b08d15f9bb07c96c3e837995b627803.
Prova nativa target: VERO AtomicTokenFile.publish, dati sintetici,
UID/GID/modo reali PASS, fixture rimossa. Nessuna credenziale/grant/autorità,
readyForExecution=false. Questa prova non è readiness applicativa o avvio.

Nuovo componente GovernedSemanticOwnerContinuation in continued_owner.py:
riusa AggregateAction/CutoverAuthority e verifiche esistenti di doppia firma,
mandato finito, root custody e sorgenti chiuse. Nessuna funzione di primo grant,
rotazione credenziale, IAM admin, lifecycle container, DB o Gateway è invocata.
Costruisce solo scope. install richiede NUOVA autorità esatta, consuma prima
un record-fence O_EXCL deterministico per scope logico, poi stage dei sorgenti e
inizializzazione di un NUOVO journal bloccato con cumulativo69. Primo tick del
worker può consumare un nuovo tentativo: cumulativo70, mai un nuovo primo grant.
Claim o inizializzazione parziali restano reconciliation-only, senza reset.
Directory inode e review privata sono vincolati. Predecessori cancellati, primo
receipt e gap legacy UNKNOWN restano immutati.
Guardia runtime nuova: il record di fence deve corrispondere, authority/firme
correnti, scope esatto e hash source. In più legge SOLO i metadati dell'esatto
Registry tramite socket Engine root/inode/mode vincolato: PID/start/image/config/
mount/network devono corrispondere alla generazione firmata. Nessun fallback
endpoint o allowlist ampliata. Il vecchio ramo di recupero rimane invariato.
Prima di effetti anche il vecchio budget viene controllato:59<=128. Non si
ridenomina un profilo precedente né si deduce contabilità dalla versione.

Cinque prove composte locali PASS, senza callback come autorità:
installazione senza grant/rotazione o mutazioni predecessori; tick69→70;
deny prima della claim per scope mancante/generazione diversa; fence assente e
mandato revocato; due installazioni concorrenti/una sola claim; budget197 fermo.
Le cinque funzioni test raggruppano questi casi. Firme Ed25519, TLS issuer mock
e file I/O sono reali; Work richiede ADATTATORI ESPLICITI per UID/GID, boot_id e
AF_UNIX→loopbackTCP. Non è qualifica nativa Linux di questi tre boundary.
Driver locale tests/run_governed_owner_local_metadata.py etichetta il limite.
Dieci test esistenti di firma reali PASS; sei di regressione owner installation
PASS con stessi adattatori.32test locali precedenti continuano PASS.
Nuova CI governed-semantic-owner.yml usa runner Ubuntu24.04 root, veri gruppi,
boot_id e Unix socket, OUF_NATIVE_UIDS=1: nessun adapter locale/skip consentito per
gruppo nativo. Nessuna connessione a VPS/IAM target: solo fixture locali sintetiche.
Esito CI ancora da leggere prima di dichiarare qualifica nativa composta.

NON pronto all'esecuzione: manca ancora confezionamento/entrypoint e review
sigillata dell'esatto nuovo comando, nuova decisione HUMAN e prova di effettiva
policy Registry. NON riusare il vecchio applicatore a8fasi né firmare da questa
documentazione. Nessun comando operativo nuovo consegnato da questa qualifica.
Le approvazioni semantiche rimangono esclusivamente nel THS; riconciliare
teatri-semantic-draft-be74308e098aa3a6-20261016 prima di riprenderne l'intento.

