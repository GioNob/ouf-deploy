# Reboot presidiato della piattaforma

La linea A4 prevede due esercizi distinti. Chiudere il primo sul kernel corrente con
il confronto delle ricevute e la lettura MCP. Aprire poi una nuova finestra, con una
nuova coppia di ricevute, per il kernel approvato (D-061 punto 2, D-094).

## Prima della finestra

- Verificare il pin installato del riavvio governato e la ricevuta di uno start
  presidiato riuscito. Verificare il digest del profilo privato, i livelli, i nomi
  gestiti, i due ruoli R3 e i container conservati. Usare l'inventario dell'host.
  [Riavvio governato](OUF_PLATFORM_RESTART.md)
- Concordare autorizzazione, operatore alla console, tempo massimo di ritorno di SSH
  e del runner e kernel di ritorno. Aprire **prima** la console fuori banda
  dell'hosting e verificare che permetta di selezionare la voce precedente di GRUB.
- Verificare l'ultima cattura cifrata fuori dal VPS, se disponibile, e annotarne il
  riferimento privato. Verificare che l'esecutore non abbia transazioni aperte.
  Riservare la finestra contro operazioni concorrenti su pacchetti, Docker e lifecycle.
- Per questo esercizio con start manuale verificare che l'unità di boot della
  piattaforma sia disabilitata. Se abilitata, usare il `disable` governato nella
  finestra autorizzata e verificarne l'esito. L'abilitazione richiede la ricevuta
  di uno start presidiato riuscito (D-063). Lasciare non installato l'avvio al
  boot di R3 finché vale D-048.
- Verificare Python ≥ 3.11, `jq`, accesso dell'utente ordinario a Docker, systemd,
  dpkg e al filesystem delle ricevute. Provare il solo comando R3 ammesso con
  `sudo -n`, interprete e lettore fissati. [Lettori R3](OUF_R3_READERS.md)

Se un prerequisito obbligatorio manca, rinviare il reboot. Le ricevute e gli output
dei lifecycle sono in custodia privata dell'operatore (D-065). Il lettore scrive
JSON su stdout. La shell dell'operatore salva i documenti con permessi privati.
Usare directory nuove per ciascun esercizio e per il ritorno. Trasferire la
ricevuta iniziale fuori dall'host prima del reboot tramite il canale di custodia.

## Preparazione del terminale

In Bash sul VPS, sostituire i segnaposto e scegliere una directory privata già
predisposta per questo esercizio. Usare una copia revisionata del file Python
come stdin. Il lettore gira con l'utente ordinario. Usare i privilegi previsti
dai singoli runbook soltanto per le rispettive operazioni. Dopo il reboot
ricaricare le stesse variabili e funzioni dal profilo privato dell'operatore.

```bash
umask 077
set -euo pipefail
set -o noclobber
R='<directory-privata-esercizio>'
SRC='<file-reboot-receipt.py-revisionato>'
PLAT='<runbook-platform-restart.sh>'
R3='<runbook-r3-operate.sh>'
export OUF_INSTALL_ROOT='<radice-installazione>'
RUNNER='<unita-runner>'
SUP='<unita-supervisore-lease>'
COL='<unita-collector>'
RS='sudo -n <interprete-fissato> -I -B <lettore-r3-status-fissato>'
obs=(--receipts-dir "$R" --unit "$RUNNER" --unit "$SUP" --unit "$COL" --r3-status "$RS")
snap() {
  python3 -I -B - observe --phase "$1" "${obs[@]}" < "$SRC" > "$R/$2.json"
}
```

Usare una shell dedicata. Eseguire una riga alla volta e leggere ogni plan prima dell'apply. Qualsiasi
exit diverso da zero interrompe il passo. Conservare anche gli output parziali.
Per i comandi piattaforma, `pf` rappresenta l'invocazione nella shell autorizzata
del runbook. Se serve root, usare il canale operatore previsto dall'installazione.

```bash
pf() { bash "$PLAT" "$@"; }
r3() { AZIONE="$1" bash "$R3" "$2" "${@:3}"; }
```

## Esercizio a kernel invariato

1. **Ricevuta iniziale.** Acquisire `pre`. Verificare ID, release, immagini
   avviabili, versioni Docker/containerd e relativi hold, spazio sufficiente,
   unità attive, entrambi i ruoli R3 vivi e container conservati fermi. Accertare
   che la voce di avvio selezioni proprio il kernel corrente. `grubDefault` è
   il selettore del menu generato, che può essere un indice o un ID. In caso
   di `unreadable` verificare la voce dalla console autorizzata. Se identità,
   capacità o baseline restano indeterminate, fermarsi prima dello stop.

   ```bash
   snap pre pre
   jq -e 'all(.checks[]; .status != "FAIL") and all(.units[]; .ActiveState=="active")' "$R/pre.json"
   jq -e 'all(.r3.roles[]; .state=="STARTED" and .live)' "$R/pre.json"
   ```

2. **Stop governato R3.** Acquisire il plan, leggerne esito, azione e motivi,
   approvare il digest del solo plan corrente ed eseguire una volta l'apply.
   Conservare la ricevuta e verificare con il lettore fissato entrambi i ruoli
   arrestati. Un diniego o un ruolo ancora vivo richiede diagnosi con status,
   timeline e journal del supervisore prima di toccare la piattaforma.

   ```bash
   r3 stop plan > "$R/r3-stop-plan.json"
   F="$R/r3-stop-plan.json"
   jq -e '.status=="PLAN_READY" and .action=="stop"' "$F"
   D=$(jq -er .planSha256 "$F")
   r3 stop apply "$D" > "$R/r3-stop-apply.json"
   jq -e '.status=="SEMANTIC_PROVIDER_R3_STOPPED"' "$R/r3-stop-apply.json"
   ```

3. **Stop piattaforma.** Esaminare azione, profilo, inventario e motivi del plan.
   Autorizzare l'apply del digest solo con `PLAN_READY` e `plan.reasons` vuoto.
   Esigere `SUCCEEDED`, livelli completati e container gestiti fermi. Con
   `HELD`, timeout o modifica del plan conservare i parziali, rileggere
   l'inventario e riconciliare prima di pianificare ancora.

   ```bash
   pf plan stop > "$R/stop-plan.json"
   F="$R/stop-plan.json"
   jq -e '.status=="PLAN_READY" and .action=="stop" and .plan.reasons==[]' "$F"
   D=$(jq -er .planSha256 "$F")
   pf apply stop "$D" > "$R/stop-apply.json"
   jq -e '.status=="SUCCEEDED" and .action=="stop"' "$R/stop-apply.json"
   ```

4. **Reboot.** Solo dopo le due ricevute di stop, con console presidiata e
   copia privata di `pre` al sicuro, impartire una volta il reboot dalla shell
   autorizzata. In caso di esito incerto osservare la console.

   ```bash
   systemctl reboot
   ```

5. **Ritorno di SSH e runner.** Attendere fino a `<N-minuti-concordati>`.
   Verificare la stessa identità SSH, l'unità e il runner online nel controllo
   CI. Se SSH non torna, passare alla console fuori banda. Se il runner resta
   offline, raccogliere stato e journal e sospendere lo start.

   ```bash
   systemctl is-active "$RUNNER"
   ```

6. **Ricevuta intermedia.** `post-boot.json` usa `--phase post` e precede
   qualsiasi start. Verificare nuovo boot ID e kernel atteso, stato delle unità,
   assenza di avvii inattesi dei gestiti, di R3 o dei conservati. Con anomalie
   mantenere la piattaforma ferma e diagnosticare da console.

   ```bash
   snap post post-boot
   OLD=$(jq -er .bootId "$R/pre.json")
   K=$(jq -er .kernelRelease "$R/pre.json")
   jq -e --arg b "$OLD" --arg k "$K" '.bootId!=$b and .kernelRelease==$k' "$R/post-boot.json"
   ```

7. **Start presidiato della piattaforma.** Rivedere livelli, readiness e
   inventario. Con motivi nel plan fermarsi prima dell'apply e di R3. Con
   apply parziale conservare la ricevuta, verificare livello e container
   interessati e riconciliare lo stato prima di un nuovo plan.

   ```bash
   pf plan start > "$R/start-plan.json"
   F="$R/start-plan.json"
   jq -e '.status=="PLAN_READY" and .action=="start" and .plan.reasons==[]' "$F"
   D=$(jq -er .planSha256 "$F")
   pf apply start "$D" > "$R/start-apply.json"
   jq -e '.status=="SUCCEEDED" and .action=="start"' "$R/start-apply.json"
   ```

8. **Start governato R3.** Verificare il nuovo plan nel contesto del boot
   corrente e approvare il digest solo se ammissibile. A fronte di un diniego
   sospendere senza secondo apply. Usare i lettori di stato, epoca e supervisore
   e conservare la ricevuta per la riconciliazione.

   ```bash
   r3 start plan > "$R/r3-start-plan.json"
   F="$R/r3-start-plan.json"
   jq -e '.status=="PLAN_READY" and .action=="start"' "$F"
   D=$(jq -er .planSha256 "$F")
   r3 start apply "$D" > "$R/r3-start-apply.json"
   jq -e '.status=="SEMANTIC_PROVIDER_R3_STARTED"' "$R/r3-start-apply.json"
   ```

9. **Ricevuta finale.** Dopo la qualificazione di R3 acquisire `post`.
   Verificare anche stato/epoche di supervisore e lease secondo il profilo.
   Se un lettore fallisce, conservare il codice dal relativo `check` e
   sospendere la chiusura.

   ```bash
   snap post post
   ```

10. **Confronto locale.** Trasferire i JSON integri alla custodia locale.
    Usare la copia verificata del profilo dalla quale sono stati eseguiti
    i plan. Costruire `--managed` da **tutti** i membri dei livelli.
    Aggiungere i due nomi R3 se il profilo li richiede in esecuzione con gli
    stessi CID. Per `STARTED` il confronto richiede entrambi i ruoli vivi.
    Un exit diverso da zero lascia l'esercizio aperto. Conservare il confronto
    con i motivi e i due originali. Il digest rileva alterazioni dei byte
    canonici e va custodito con la provenienza delle ricevute. Il calcolo SHA-256
    usa il JSON senza `digest`, chiavi ordinate, escape ASCII e separatori `,` e `:`
    senza spazi. I campioni e `StartedAt` documentano gli avvii osservabili.

    ```bash
    L='<directory-custodia-locale>'
    SRC='<file-locale-reboot-receipt.py>'
    PROFILE='<profilo-privato-verificato>'
    names=$(jq -er '.levels[].containers[].containerName' "$PROFILE")
    args=(--expect-r3 STARTED)
    while IFS= read -r n; do args+=(--managed "$n"); done <<< "$names"
    cmp=(python3 -I -B "$SRC" compare "$L/pre.json" "$L/post.json")
    "${cmp[@]}" "${args[@]}" > "$L/confronto.json"
    ```

11. **Lettura applicativa.** Dopo `PASS`, l'operatore del chatbot esegue
    `ouf.system.status` sulla connessione prevista e conserva l'esito nella
    stessa custodia. Su errore aprire la diagnosi applicativa e trattenere il
    passaggio al kernel nuovo. Registrare insieme esito MCP, confronto e
    ricevute dei quattro apply.

## Seconda finestra, kernel nuovo

Ripetere i prerequisiti e i passi 1–11 con directory nuove. Concordare
`<pacchetto-kernel>`, la versione esatta e la **release attesa in esecuzione**
prima dell'aggiornamento. Prima della nuova `pre` applicare o verificare gli
hold di tutti i pacchetti Docker e containerd installati, compresi i plugin,
secondo l'inventario verificato. Conservare gli hold per tutta la prova.

```bash
PKG='<pacchetto-kernel>'
VER='<versione-pacchetto>'
NEW='<release-kernel-attesa>'
docker_pkgs=('<pacchetto-docker>' '<pacchetto-containerd>' '<altro-pacchetto-docker>')
sudo apt-mark hold "${docker_pkgs[@]}"
apt-mark showhold
```

Tra lo stop completo (passo 3) e il reboot (passo 4), simulare la transazione
con i pacchetti approvati già disponibili. Verificare che l'unico pacchetto
installato o aggiornato sia `$PKG` alla versione `$VER`. Se apt propone altre
modifiche, rimozioni o variazioni dei blocchi, fermarsi. Controllare lo stesso
riepilogo prima della conferma interattiva.

```bash
apt_args=(--no-remove --no-install-recommends install "$PKG=$VER")
apt-get -s "${apt_args[@]}"
sudo apt-get "${apt_args[@]}"
snap pre prima-del-boot-nuovo
```

Verificare versione installata, file kernel/initramfs, selettore GRUB effettivo
e disponibilità della voce precedente dalla console. Se la voce è illeggibile
all'utente, verificarla con il presidio. In caso di discrepanza sospendere il
reboot. Al passo 6 usare `K="$NEW"` al posto dell'assegnazione da `pre`.
Al passo 10 sul terminale locale usare la release attesa già concordata.

```bash
NEW='<release-kernel-attesa>'
"${cmp[@]}" "${args[@]}" --expect-kernel "$NEW" > "$L/confronto.json"
```

## Ritorno presidiato

Se il kernel nuovo non parte, non corrisponde alla release prevista o impedisce
il ritorno del runner, conservare l'evidenza disponibile e passare alla console.
Se dei servizi sono già ripartiti ed è possibile governarli, eseguire gli stop
dei passi 2–3 prima del reboot di ritorno. Dal menu di avvio selezionare la
voce del kernel precedente verificata prima della prova. Se anche questa
fallisce, mantenere il presidio fuori banda e interrompere la procedura.

Dal passo 5 ripetere osservazione, start governato e qualificazione R3 con
ricevute di ritorno in una nuova directory. Copiarvi la `pre` originale e
usare il `post` del ritorno. Ricostruire `cmp` e `args` come al passo 10,
con `L` sulla directory locale del ritorno. Ripetere la lettura MCP dopo PASS.

```bash
OLD_KERNEL=$(jq -er .kernelRelease "$L/pre.json")
"${cmp[@]}" "${args[@]}" --expect-kernel "$OLD_KERNEL" > "$L/confronto-ritorno.json"
```

Registrare separatamente l'esito del tentativo con kernel nuovo e quello del
ritorno. L'eventuale abilitazione del boot piattaforma segue il percorso D-063
con la ricevuta dello start presidiato riuscito e l'autorizzazione prevista.
