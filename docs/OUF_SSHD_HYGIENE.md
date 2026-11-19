# Igiene sshd — R-007, task-45

`scripts/apply-sshd-hygiene-20261115.py` sostituisce esclusivamente le ultime
due direttive residue con commenti fissi. I pin SHA-256 del VPS sono costanti:
configurazione, drop-in e binario devono corrispondere. Richiede root, file
regolari senza hard link, proprietario/gruppo root, configurazioni 0644 e
binario 0755; gli antenati devono essere directory root non scrivibili da altri.
Il file deve avere 125 righe, Include alla riga 12, nessun Match attivo e la
coda esatta verificata. Tutti gli altri byte restano invariati.

```sh
sudo python3 scripts/apply-sshd-hygiene-20261115.py --plan
sudo python3 scripts/apply-sshd-hygiene-20261115.py --apply --plan-sha256 <digest-del-plan>
sudo python3 scripts/apply-sshd-hygiene-20261115.py --restore --plan
sudo python3 scripts/apply-sshd-hygiene-20261115.py --restore --apply --plan-sha256 <digest-del-plan-di-restore>
```

Il plan crea solo un temporaneo privato effimero: non cambia file operativi.
Esegue `sshd -t -f` e `sshd -T -f` su originale e candidato; gli output effettivi
devono coincidere byte per byte. JSON espone diff, hash effettivi e digest del
plan, senza output grezzi dei processi. Apply ricostruisce il plan sotto lock
esclusivo non bloccante sulla directory della configurazione, confronta il
digest, poi crea esclusivamente lo snapshot versionato
`/etc/ouf/deploy-snapshots/sshd-hygiene-20261115/` (0700).
`claim.json` e `original` (0600) sono sincronizzati prima del rename.
Una nuova verifica precede il rename; il temporaneo nella directory SSH viene
impostato root:root 0644 e sincronizzato, seguito da rename e fsync directory.
Readback di hash, sintassi ed effettivo precedono `result.json` (0600).
Non esegue reload, restart o comandi sul daemon: le sessioni aperte restano attive.

Restore richiede lo snapshot originale integro e il file corrente esattamente
uguale al target; ripete gli stessi controlli e conserva una propria copia del
file sostituito in `snapshot/restore/`. Anche questa directory è esclusiva.
Lo snapshot originario resta disponibile dopo il ripristino.

Gli errori producono JSON `BLOCKED` e codice pubblico, exit 1; digest CLI
malformato produce exit 2. Non sono emessi traceback o stderr di sshd.
`doNotRerunApply` diventa vero dal primo effetto persistente e in presenza
di una prenotazione esistente. `failure.json` è scritto quando possibile;
un crash può lasciare solo il claim, che comunque impedisce il replay.
Nessuna cancellazione automatica dei claim, rollback implicito o retry.
Profilo locale v1: un tentativo, subprocess con timeout 30 secondi;
nessun errore è classificato esplicitamente transitorio. Esiti sconosciuti o
mutativi ambigui richiedono riconciliazione umana secondo la policy v3.
Un fallimento dopo il rename consente un nuovo plan di restore solo se tutte
le verifiche risultano valide. Un fallimento durante restore richiede intervento.

Limiti: il lock coordina le istanze di questo script, non editor esterni;
occorre escludere altre modifiche amministrative concorrenti, inclusi drop-in
e binario. Non è una transazione con gli editor o il daemon. Nessuna prova
di conformità runtime generale, outage remoto, IAM o delivery sul VPS è qui
asserita. Il modello gateway citato nel task non era presente nella worktree.

Test portabili: `python -B -m unittest discover -s tests -p test_sshd_hygiene_20261115.py -v`.
Il workflow `sshd-hygiene.yml` esegue anche il gate
`OUF_SSHD_HYGIENE_NATIVE=1` con sudo e OpenSSH reale: fixture e host key sotto
`/var/lib`, mai configurazioni in `/etc/ssh`. L'eventuale installazione del
pacchetto è preparazione del runner; non è una prova né un deploy sul VPS.
I pin della fixture sono iniettati tramite `Settings` nei test: la CLI non
espone override dei pin di produzione. L'esecuzione nativa resta da osservare
in CI; non viene eseguita localmente su Windows.
