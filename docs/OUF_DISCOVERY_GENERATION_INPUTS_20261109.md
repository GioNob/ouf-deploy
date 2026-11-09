# Discovery: input privati per la nuova generazione

9 novembre 2026. Boot concluso; preparazione input qualificata nel codice, esecuzione VPS pendente.

## Risultato del passo

Il [preparatore](../scripts/prepare-discovery-generation-inputs-20261109.py) conserva i template storici di adapter/southbound e seleziona separatamente il coordinatore QUIESCED collegato al boot. Produce due file per ruolo e un piano privato; non produce una configurazione runtime eseguibile, nuove identità o autorizzazioni.

Questa separazione serve al lavoro successivo: gli owner esistenti di creazione, profili e ammissione richiedono nuovi CID, transazioni, binding correnti del peer Semantic, aspettative OCI/rootfs indipendenti e autorità correnti. Il vecchio template non può essere riutilizzato cambiando soltanto il coordinatore. I riferimenti di identità storici sono censiti come percorsi JSON, non promossi a valori nuovi. La lista dei percorsi è un ausilio, non una prova di ammissione o un inventario esaustivo di ogni dipendenza.

## Controlli ed effetti

Richiede la [ricevuta completa del boot](../evidence/discovery-successor-boot-bound-operator-20261109.json), hash originale ffd4362f, e il completamento identico dell'intento. Verifica il puntatore attivo nell'installazione b3c3uwwt, il sorgente dell'osservatore, comandi systemd caricati, contesto staged e guard corrente. Riusa i lettori e i lock qualificati per confermare vecchi provider terminali, assenza di residui nativi e set lease vuoti; nessuno dei vecchi controller viene eseguito in modalità mutativa.

Legge soltanto configurazione runtime, broker e template preparer vincolati per hash. Richiede che entrambi i template corrispondano al vecchio coordinatore; kernel, DNS e lock devono essere identici nel successore. Mantiene template storico e nuova selezione separati. Controlla nuovamente sorgenti, puntatore e metadata caricati prima/dopo la scrittura privata.

Crea un intento in `/var/lib/ouf-storage-migration/discovery-generation-inputs-20261109`, prove private e una nuova directory `/etc/ouf/deploy-snapshots/discovery-generation-inputs-*` con:

- `adapter-inputs.private.json` e `southbound-inputs.private.json`;
- `generation-plan.private.json`;
- ricevuta finale di preparazione.

Non crea container, non cambia reti/MAC, wrapper runtime, puntatore, journal storici, nft o servizi. Nessuna firma, lettura di credenziali, token, DNS, DB, S3 o richiesta applicativa. Nessun nuovo budget o autorità emessi. I file parziali sono conservati; intento esistente rifiutato senza replay. Deadline complessiva180s; i lettori ereditati mantengono timeout e limiti per comando.

## Consegna

Source `b088b1f84b70e2203aa2f5c7463e37f4b988ca07`.

| File | SHA-256 |
| --- | --- |
| Preparatore | `7a3d618aa933c42cfcdac3eb5965e97521a64934dd778aa1c66b244f7d4f99a0` |
| Wrapper | `965059899e07456c97d5345ddfe74cea5e3a150cc92daef541007d03a56a6046` |

Il [wrapper](../scripts/deliver-discovery-generation-inputs-20261109.sh) verifica15sorgenti prima di invocare il solo preparatore con sudo/Python isolato. Non invoca main del controller boot. Eseguire una volta tramite la consegna con URL/hash fissati al commit; restituire il JSON finale.

Esito atteso `DISCOVERY_GENERATION_INPUTS_PREPARED`, rolesPrepared=2, inputsAreNotRuntimeProfiles=true, pendingFreshIdentityAndAuthority=true. Le autorizzazioni restano false. Se HELD, conservare l'esito e non rilanciare.

## Prove e limiti

[CI42604343907](https://github.com/GioNob/ouf-deploy/actions/runs/42604343907), job129116339541: SUCCESS, log letti; 8 test, zero skip. Ricevuta completa e omissione di ciascuno dei43campi; caricamento della chiusura sorgenti; separazione senza mutare gli originali; rifiuto CID/coordinatore/kernel/DNS/lock errati; creazione reale di file0600 e rifiuto del replay; parziali conservati. Nessun test di sistema di ammissione o avvio provider viene dichiarato.

Verificati sintassi Bash,15hash locali e readback Git, dispatch esclusivo al preparatore e rifiuto di argomenti imprevisti con curl/sudo/mktemp simulati. La simulazione usa una directory del workspace perché /tmp non è disponibile nell'ambiente locale. L'intero controller sul VPS resta da eseguire; i guard nft/lifecycle/systemd sono riusati senza modifiche dalla consegna boot già completata. Questi pass non dimostrano nuova generazione ammessa, trasporto Semantic, discovery o E2E.
