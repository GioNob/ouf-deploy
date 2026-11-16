# Ripristino dei volatili southbound — D-047 / task-59

Il modulo `tools/semantic_provider_r3/volatile_restore.py` appartiene alla
consegna di `operate`, prima degli start R3. Riporta l'upper del southbound
allo stato D-042 già accettato. Non compone una nuova versione R3, non cambia
closure installata, configurazione OCI, sigilli, autorizzazioni o journal.
Il runtime continua a verificare il sigillo originale durante il create.

## Input da consegnare con il runbook

Oltre agli argomenti di `operate`, `--action start` richiede:

```text
--volatile-rootfs-result /PERCORSO/risultato-rootfs-v3/result.json
--volatile-rootfs-result-sha256 SHA256_DEL_RISULTATO
--volatile-source /PERCORSO/sorgente-storico-cohort
```

Il risultato deve essere D-042/PREPARED e corrispondere ai CID installati.
Le comparison, le configurazioni OCI e le ricevute offline sono lette dai
binding path/hash del risultato. `effectiveSeal` deve coincidere con il
sigillo collegato al broker installato e con `expectedSeal` della comparison.
L'OCI deve coincidere interamente con `expectedOci` della policy installata:
da `process.user.uid/gid` si ricava il proprietario, senza costanti 636.

`--volatile-source` indica il sorgente storico con `sources.json` e la sua
closure di 29 file, verificati da `load_sealer` contro
`sourceManifestSha256` del risultato. Non è il sourceRoot del runtime R3.
La ricostruzione offline `bundle/rootfs` deve essere ancora disponibile e
coincidere con il sigillo della relativa `offlineDockerReceipt`.
Da lì provengono i metadati indipendenti delle directory dell'immagine.

Il runbook deve consegnare questo modulo insieme a `operate` e ai moduli
storici importati dal rootfs v3, nei percorsi del repository. Il task non
modifica `ops/vps/r3-*`: l'aggiornamento del trasporto spetta al relativo owner.
La presenza dei file di consegna non richiede di aggiungerli alla closure R3.

## Precondizioni e proposta

Entrambi i CID devono essere created/exited, Running false, PID 0, senza
epoche aperte o vive. Valgono anche le precondizioni ordinarie dello start:
RestartPolicy no, supervisore WAITING, lease QUIESCED/non autorizzato.

Root, upper, lower e work vengono dalle comparison D-042 e sono validati
dalla stessa `overlay_binding` v3, applicata alla riga di mount conservata.
I percorsi restano quelli dello snapshot Docker/containerd originario.
La primitiva storica di export apre temporaneamente ciascun root fermo:
la riga di mount corrente deve coincidere interamente con il binding storico,
prima di ammettere qualunque rimozione. Non basta che i vecchi percorsi esistano.
`/proc/self/mountinfo` deve escludere root e upper montati, submount e altri
overlay che usino l'upper. I descrittori escludono anche attraversamenti di
filesystem; mountinfo intercetta i bind mount sullo stesso device.

Il plan osserva questi mount temporanei dell'export senza modificare file
dell'upper né creare claim; al termine devono essere nuovamente smontati.
Il config Docker è un leaf assente accanto all'output, controllato prima e
dopo l'export, per non leggere configurazioni dell'operatore.
Il corpo canonico include
`volatileRestore`: sorgente storico, hash degli input, snapshot, sigillo upper
osservato, `expectedUpperSeal`, `effectiveSeal` e rimozioni relative per ruolo.
L'adapter ha sempre zero rimozioni; un suo upper diverso dall'atteso è negato.

La previsione usa i record del walker storico e il suo encoder, ordine DFS e
framing originali. Sottrae soltanto i record dichiarati e il contributo delle
directory rimosse al nlink del padre. Il risultato deve già coincidere con
`expectedUpperSeal` prima di qualunque cancellazione. Non viene salvato un
nuovo sigillo accettato e nessun campo del confronto è escluso globalmente.

## Allowlist e dinieghi

Solo nell'upper southbound:

| Percorso relativo | Requisiti |
| --- | --- |
| `usr/local/apisix/{fastcgi_temp,scgi_temp,client_body_temp,proxy_temp,uwsgi_temp}` | Directory; discendenti solo directory/file regolari. Profondità relativa massima 8, complessivamente 10.000 elementi incluse le cinque radici, 256 MiB di file. |
| `usr/local/apisix/conf/{nginx.conf,apisix.uid}` | File regolari, nlink 1, massimo 1 MiB ciascuno. |
| `usr/local/apisix/conf/apisix.yaml` | Symlink, nlink 1, destinazione esattamente `/run/ouf-southbound-runtime/apisix.yaml`. |
| `usr`, `usr/local`, `usr/local/apisix`, `usr/local/apisix/conf` | Copy-up con modo, uid, gid e xattr normalizzati identici all'immagine. Rimozione soltanto quando vuoti. |
| xattr `trusted.overlay.impure` delle directory padre degli elementi rimossi | Marcatore che il kernel imposta sul padre di un copy-up, invisibile nella vista unita. Viene rimosso solo se nessun figlio rimasto porta `trusted.overlay.origin`; la previsione esatta del sigillo continua a decidere. Riga di evidenza `kind = overlay-impure-xattr`. Emerso dal gate nativo: la copia di `usr` marca la radice dell'upper. |

Volatili e discendenti devono appartenere all'utente OCI e avere
`mode & 0o7000 == 0`. Si applica esattamente `physical(..., new=True)` v3:
soli xattr contabili overlay, inclusa opaque soltanto sulle directory nuove;
redirect/metacopy e xattr applicativi sono negati. I file hardlink nelle
directory temporanee restano file regolari; durante la rimozione è ammessa
soltanto la riduzione di nlink causata dagli unlink già eseguiti dal modulo.

Symlink temporanei, FIFO, socket, device, proprietari/modi/xattr non ammessi,
destinazioni diverse e altri delta nell'upper producono
`R3_VOLATILE_UNDECLARED_ENTRY` prima delle rimozioni. Anche contenuti modificati
fuori allowlist o elementi mancanti sono intercettati dalla previsione esatta.
Container non fermi/epoche vive: `R3_VOLATILE_IDLE_REQUIRED`; overlay montato:
`R3_VOLATILE_OVERLAY_MOUNTED`. Gli input mancanti danno
`R3_VOLATILE_INPUTS_REQUIRED`.

## Apply, evidenze e verifica

Dopo il claim esclusivo di `operate`, l'apply prende i lock CID esistenti,
ricontrolla osservazione, input e intero plan, valida entrambi i ruoli e
mantiene descrittori di directory `O_DIRECTORY|O_NOFOLLOW` fino alla fine
delle cancellazioni. Nessuna ricorsione segue link; `unlink`/`rmdir` sono
relativi ai descrittori. Non viene usato `shutil.rmtree` per il ripristino.

Ogni rimozione riuscita incrementa subito `volatileEntriesRemoved` e aggiunge
una riga a `volatileRemovals`. Il file esclusivo
`volatile-removal-NNNNN.json` contiene soltanto `path` relativo e `kind`.
Nessun contenuto o hash di contenuto è copiato nelle evidenze delle rimozioni.
Errori successivi conservano claim, contatore ed evidenze parziali, senza rollback.

Il walker storico ricalcola l'upper. La primitiva storica
`stopped_export_view` apre poi la vista unita direttamente nel root OCI del
container fermo, mantenendo aperto l'export Docker e scartandone il tar.
`overlay_binding` deve coincidere con lo snapshot storico; il sigillo diretto
della vista unita deve essere `effectiveSeal`. Dopo l'export viene verificato
di nuovo l'upper e l'assenza del mount. Anche l'adapter passa questi controlli.
L'export non invoca create/start e non sostituisce i metadati con quelli del tar.

Un sigillo diverso produce `R3_VOLATILE_RESTORE_SEAL_MISMATCH`, esito HELD e
zero richieste di start. Gli altri errori di custodia/export conservano il
proprio codice pubblico. Se già sigillato, non si rimuove nulla e si eseguono
comunque entrambe le verifiche. I lock sono rilasciati prima dei due start
concorrenti: i figli del runtime devono poterli acquisire.

## Test e limiti della prova

`test_semantic_provider_r3_volatile_restore.py` usa record e descrittori
simulati per eseguire il codice di cancellazione anche su Windows.
La suite operate verifica inclusione nel digest, ordine restore/start,
contatori e HELD con zero start su errore.

Il gate `OUF_R3_VOLATILE_NATIVE=1` richiede Linux root:root, Python `-I -B`,
unshare, mount/umount, runc, ip/nsenter e sleep/ldd locali; prerequisiti mancanti
falliscono. Usa namespace privati e un overlay equivalente con layout
containerd, nessun daemon Docker o download. Sigilla il post-create runc con
`NodeObservation.observe`, simula le scritture APISIX, smonta, ripristina,
verifica upper/vista unita e ricrea il task runc: i sigilli devono coincidere.
Solo le verifiche firmate di trasporto/live-profile, estranee al rootfs, sono
simulate. La vista equivalente sostituisce il trasporto export, mantenendo
reali sealer, filesystem, binding snapshot e create/state/delete runc.

Il workflow R3 esegue esplicitamente questo gate. La sua definizione non
attesta un'esecuzione CI né un risultato VPS. Non prova l'avvio applicativo
APISIX, il lease o l'E2E; non consuma claim operativi esistenti.
