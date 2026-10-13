# Policy-token: integrazione minima e lettura delle policy IAM

La migrazione ora compone i componenti esistenti: arresto governato del vecchio writer, credenziale, primo grant con introspezione e pubblicazione protetta. Non introduce journal, servizio o scheduler aggiuntivi. I registri esistenti impediscono replay; credenziali completate e verificate possono essere riusate, esiti ambigui richiedono riconciliazione.

Resta da osservare un dato target necessario prima di proporre la rigenerazione: le policy del client/realm, incluse quelle globali e i profili degli executor. La lettura del client e i mapper già raccolti non contengono questa informazione. Il codice Keycloak 26.7.4 richiede esplicitamente le query include-global-policies e include-global-profiles. La presenza di un executor secret-rotation in un profilo non dimostra da sola che sia attivo/applicabile; il report mantiene questa distinzione. L'esclusività dei consumer della credenziale resta da stabilire separatamente, non viene dedotta dall'assenza di eventi storici.

Il comando sottostante riusa gli snapshot 93fa9bc… e 7e0f46ad…, verifica il programma Docker già registrato, esegue al massimo tre GET nella sessione amministrativa esistente e conserva un'osservazione privata root0600. Mostra solo conteggi, flag, hash, fase/motivo ed eventuali categorie diagnostiche. Nessun login automatico, client-secret endpoint, grant del client SERVICE, chiave privata, modifica IAM o servizio. Limite 15 secondi per GET, 60 complessivi per le richieste e 90 per l'osservazione. È un probe operatore single-attempt, senza retry automatico; il risultato non autorizza la migrazione né ripristina budget. I dati non sono dichiarati uno snapshot transazionale o prova di policy applicabile.

## Comando VPS

Usa questo comando soltanto dopo la qualificazione registrata nella ricevuta associata. Non rieseguire i vecchi apply IAM, la preparazione host o R12. Se il risultato è BLOCKED, conserva e incolla il report; non ripetere automaticamente il comando. La diagnosi distingue fase e categoria senza stampare risposte private.

```bash
set -o pipefail
(
  set -eu
  umask 077
  ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  [ -x "$ouf_gh" ] || ouf_gh="$(command -v gh || true)"
  [ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || { echo "EXISTING_GH_UNAVAILABLE"; exit 1; }
  ouf_work="$(mktemp -d "$HOME/ouf-client-policies.XXXXXXXX")"
  "$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/observe-policy-token-client-policies.py?ref=0c028ec51ac7c8f60cd24185ef5ab6b6012a0e1b' --jq '.content' |
    base64 --decode > "$ouf_work/observe.py"
  printf '%s  %s\n' '5bcd6556d1f0505456550a3469fe81b6577fc553029e2aa130611a2002822449' "$ouf_work/observe.py" | sha256sum -c -
  python3 "$ouf_work/observe.py"
) | tee ouf-policy-token-client-policies-receipt.json
```

## Limiti aperti

La composizione qualificata e questo observer non costituiscono l'installer completo: restano il binding target delle directory create, la revisione di policy/consumer e la consegna dell'autorità di esecuzione corrente. Nessuna prova CI viene presentata come prova sul VPS. Il precedente consenso al design UNKNOWN-history resta valido e non viene richiesto nuovamente.


Fonti primarie verificate: [ClientPoliciesResource](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/resources/admin/ClientPoliciesResource.java), [DefaultClientPolicyManager](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/clientpolicy/DefaultClientPolicyManager.java) e [ClientSecretRotationExecutorFactory](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/clientpolicy/executor/ClientSecretRotationExecutorFactory.java).

## Qualificazione completata

Il commit `0c028ec51ac7c8f60cd24185ef5ab6b6012a0e1b` ha superato [la CI 38438841539](https://github.com/GioNob/ouf-deploy/actions/runs/38438841539), job `115439820481`: **211 test, zero esclusioni**, oltre alla prova Keycloak reale delle tre GET incluse policy globali. Anche la PR CI `38438848199` è passata. La composizione usa TLS, crittografia e filesystem reali con issuer sintetico e comandi di servizio/IAM simulati; la prova Keycloak verifica separatamente il protocollo reale. [Ricevuta strutturata](../evidence/policy-token-minimal-composition-and-policy-observer-qualified-20261013.json). Il comando VPS è pronto per la sola osservazione; non è un apply.
