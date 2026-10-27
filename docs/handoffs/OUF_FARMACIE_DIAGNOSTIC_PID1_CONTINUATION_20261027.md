# Farmacie — riuso del controllo peer già qualificato e due STOP conservati

27 ottobre 2026, Europe/Rome. Il secondo STOP è `EXACT_CURRENT_ROOT_ENGINE_PEER_CREDENTIALS_REQUIRED`, Exit2/DeliveryExit2, prima della review. [Ricevuta e ricostruzione circoscritta](../../evidence/onboarding-pid1-peer-stop-target-20261027.json). La consegna fd831393 e il suo scope sono CONSUMATI: non rilanciare. [Handoff precedente](OUF_FARMACIE_DIAGNOSTIC_PEER_CONTINUATION_20261027.md), che contiene tutti i riferimenti a capture, preparazione, primo STOP e reader consumati.

## Difetto e riuso effettivo

L'hash del peer già conservato `7ff52993d5d3cb149089942de7fc7a6511db2671cf2125976c081ad6fff89772` è il SHA256 canonico di `[1,0,0]`. Non serve un'altra lettura VPS per identificarlo. Il nuovo guard `peer[0]>1` era un errore del controller. I [trasporti MCP già usati](https://github.com/GioNob/ouf-deploy/blob/b9697462f293d7481c9fd7cdd84c549b70214eda/tools/mcp_diagnostic_update/transport.py), redazione e acquisizione verificavano già la tupla completa ed UID0 senza escludere PID1. Si riusa quel comportamento; un PID strettamente positivo è valido. Non viene dedotta la ragione per cui il peer osservato sia PID1.

Socket/custodia e hash storici rimangono identici; ogni connessione corrente verifica la tupla completa esatta e UIDroot. Nessun cambio al trasporto live, nessuna normalizzazione generica, nessuna eliminazione del peer dai binding.

## Catena conservata, senza reset

Primo scope: `/etc/ouf/deploy-snapshots/onboarding-diagnostic-update-c22586172070809d-v1`, tre tentativi metadata. Secondo scope: child `retained-peer-credentials-continuation-v1`, otto ulteriori tentativi, payload cumulativi4–11. Sono entrambi pre-review, non emettono authority/journal e non costruiscono Engine. Il nuovo controller deve verificare inventari esatti, claim, tutti gli undici tentativi, il reader già conservato, manifest e21 fonti root0400 del secondo controller più il suo log root0600. Un effetto/authority/file inatteso comporta STOP; nessun vecchio file modificato.

Nuovo scope esclusivo: child `pid1-peer-continuation-v1` sotto il secondo scope. I contatori partono da11 nello STESSO massimo64:37 verifiche conservate,4 metadata piano e2 authority pubblica portano54 prima della review; altre2 ri-validazioni pubbliche dopo consenso portano56. Lettura contenuto YAML owner1 separata; quattro SQL tecniche READONLY restano condizionali e successive alla nuova approvazione. Il reader già consumato7metadata+22fonti/manifesto rimane una procedura separata, mai rilanciata.

## Stato e prossima azione

Correzione e consegna QUALIFICATE, NON eseguite sul VPS. [Evidenza completa](../../evidence/onboarding-pid1-continuation-qualified-20261027.json). Source `fc40492ee048b6cb6521027c0f9c0b0e26739bcf`; delivery `cda3a58c46644f5692a4d7d9753a8ddadf8b57a7`; wrapper `releases/apply-onboarding-diagnostic-pid1-continuation-20261027.sh`; SHA256 `1f7c1a634ac74f99755f35907eb5405d915402742d5add755f44a8588f6b8dd2`; closure21fonti `67bc4cd76ccb43526d52c331c5f04454a869d4611251a8cb7092ff8803470f88`; codice `/usr/local/lib/ouf-onboarding-diagnostic-update-67bc4cd76ccb4352`.

CI source push40484538466 PASS:11protocollo/17compatibilità e contatori/6MAC/9fence senza skip;7native per classic/containerd (Docker29.8.1/Postgres17), socket Unix PID1 kernel reale su entrambi,11TTY per ciascun sudo. Nuova delivery push40484826693/job122123886839 PASS: HTTPS pubblico, sudo reale, root0400, main/TTY protetti, vecchi21codici+log invariati, contatori12–49 e rifiuto su hash input sintetico errato prima di authority/Engine/SQL/chiavi. Log diretti letti. Tutti21blob della closure verificati byte per byte al sourcepin; wrapper letto al deliverypin e identico. Workload e chiavi CI sono sintetici: nessuna prova VPS/E2E.

NEXT prima esecuzione della sola NUOVA consegna, checksum, copia root0400, log conservati, review concreta e `APPROVO <hash fresco>` realmente inserito nel terminale con Invio. Nessun consenso passato dal wrapper; il prompt editabile già provato viene riusato. Se STOP conservare e non rilanciare.

La stessa immagine minima diagnostica Onboarding074bd16e è già preparata e non viene ricostruita/relabelled. Preservare35migrazioni/nove tabelle/job FarmacieFAILED tentativi5, configurazione/risorse/MAC/IP/porte, tutti i peer Registry/MCP/worker/READ/Gateway. Non avviare candidato M2 più ampio, nuovo upload/profiling/acquisizione, grant o attivazione. Nessun rollback automatico. Policy54 scaduta: questa manutenzione non concede READ di dominio e non autorizza SQL per leggere la causa del job.

M1/G4 resta acquisito: due run Teatri,26join,13identità/20proprietà,8Cinema preservati. M2 resta aperto; causa Farmacie ignota. [Audit del riuso](../OUF_M2_CODE_EVIDENCE_GAP_AUDIT_20261026.md). No subagenti, automazioni, merge o release acceptance; Supervisor dopo E2E completo.

## Comando unico — prima esecuzione nuova, come oufadmin

Le due consegne precedenti rimangono consumate. Incollare questo blocco nel terminale VPS. Il controller mostra una nuova review concreta; la sua riga APPROVO va inserita separatamente con Invio. Non esiste un hash da approvare in chat.

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_pid1_bootstrap=$(mktemp -d "$HOME/ouf-onboarding-pid1-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 131072 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/cda3a58c46644f5692a4d7d9753a8ddadf8b57a7/releases/apply-onboarding-diagnostic-pid1-continuation-20261027.sh" \
    -o "$ouf_pid1_bootstrap/run.sh"
  printf '%s  %s\n' '1f7c1a634ac74f99755f35907eb5405d915402742d5add755f44a8588f6b8dd2' "$ouf_pid1_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_pid1_bootstrap/run.sh"
  /usr/bin/bash "$ouf_pid1_bootstrap/run.sh"
)
```

Log runtime previsto: `/usr/local/lib/ouf-onboarding-diagnostic-update-67bc4cd76ccb4352/operator.log`; log bootstrap nella nuova directory `$HOME/ouf-onboarding-pid1-continuation-delivery.*`. Conservare JSON finale, Exit, Directory, Log, DeliveryExit, DeliveryDirectory e DeliveryLog. In caso STOP nessun rilancio. Solo dopo risultato completo provato passare alla diagnosi governata dello stesso job: policy54 non si rinnova con questa manutenzione. [Invariante appresa e riferimenti al codice storico](../OUF_LEARNED_NATIVE_TRANSPORT_INVARIANTS.md).
