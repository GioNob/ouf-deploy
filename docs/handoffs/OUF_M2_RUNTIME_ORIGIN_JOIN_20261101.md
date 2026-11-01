# M2 — collegamento delle origini ai runtime verificati

1 novembre 2026, Europe/Rome. Sorgente e consegna QUALIFICATI. Operazione target
NON eseguita: l'agente non dispone di shell VPS o dei suoi archivi privati; il
plugin OUF espone capability applicative, non questa lettura amministrativa.
L'unico intervento indispensabile è eseguire UNA VOLTA il comando sotto come
oufadmin sul VPS e restituire JSON pubblico e footer. Non richiede un APPROVO
applicativo, login IAM, nuovo grant, reset o rinnovo di autorità runtime.

## Base acquisita e scopo unico

[Byte runtime verificati](../../evidence/m2-selected-runtime-target-20261101.json):
Exit0,13runtime completi,2.774.726.144byte di archivi/4.010.055.680espansi,
risultato039f03a7593c0b826e6597f755c838f85efa197d17d7df3339512f5ee7c52bcc,
prova privata c52a0e2a0ebcdb9c8a826426386a9172c0507231199815c09ab32eb144fd713e.
Scope11 consumato e tutti10precedenti preservati, totale11controlli/35GET.
NON rilanciare cattura, byte-verifica, diagnosi o qualunque vecchio comando.
I22manifesti di altre piattaforme/ausiliari rimangono esclusi dall'ammissione.

Il nuovo lettore collega il record privato ESATTO c52a ai13native ID pubblici e
richiede10config digest già qualificati (4core,2READ,4vendor); per i4vendor richiede
anche il manifesto runtime pubblico esatto. Legge solo `manifest.json` e config
nei TRE archivi originali delle origini ancora aperte: Gateway-owner,MinIO,Semantic.
Digest della config, hash della configurazione di esecuzione e platform devono
corrispondere alla prova consumata. Seek sui layer: nessun membro layer aperto,
nessun hash integrale/espansione/verifica byte ripetuto e nessun nuovo export.

Il pubblico contiene conteggi e tre identità config/manifesto, più eventuali
source label soltanto per repository esplicitamente ammessi e Git SHA canonici.
Env, altre label, path, tag, byte/config completa e hash degli archivi non escono.
Le label sono DICHIARAZIONI, non autenticazione di publisher. La riuscita di questa
operazione non ammette tutti gli artifact, la policy corrente o il runtime.

## Qualifica e conservazione

[Qualifica finale](../../evidence/m2-runtime-origin-join-delivery-qualified-20261101.json),
[source/publisher](../../evidence/m2-runtime-origin-join-source-qualified-20261101.json).
Source cbbc1276/23moduli; capsula710edec8/65092df6/332.958byte;
launcher d51807fe/b50d274c. Push41342126387 e PR41342134036 SUCCESS, ciascuno
23test/5suite, zero failure/error/skip/ResourceWarning. Tutti sei log finali letti.
Otto test controllo11scope, cinque capsule, sette confine download, due native
su13exportDocker29.8.1, una consegnaHTTPS reale. Nei test nativi il lettore apre
esattamente manifesto/config, mai layer; rimozione/corruzione negata. Tutti235,
19,17 e21sorgenti precedenti esatti. ZIP originale13097274138 e tutti5membri
confrontati, soggetto firmato/source/repoID/workflow/ref/runner corrispondenti;
verifica crittografica gh2.97 eseguita nel CI, non rieseguita localmente dall'agente.

Nuovo scope separato `m2-runtime-origins-c52a0e2a-20261101-v1`, massimo1controllo/
180s, totale12controlli/35GET. Tutti11scope vecchi, claim, risultati e prove
restano invariati. Zero Engine, registry fetch, import, lifecycle, file montati,
file credenziali, SQL o OAuth. Nessun riarmo, budget runtime/reset/grant/authority.
Drift, errore, interruzione o scope consumato richiedono riconciliazione: conservare
l'output e NON rilanciare. Root necessario solo per leggere archivi/prove già0700/
0400 e creare il nuovo risultato privato0600. Password sudo soltanto nel terminale.

## Unico comando VPS

[File della consegna](../../releases/OUF_M2_RUNTIME_ORIGIN_JOIN_COMMAND_20261101.sh).
Eseguirlo una volta e riportare soltanto JSON pubblico e `RuntimeOriginJoinExit`.

```bash
(
  set -euo pipefail
  umask 077
  ouf_origin_join_tmp=$(mktemp -d)
  trap 'rm -rf -- "$ouf_origin_join_tmp"' EXIT
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 \
    --tlsv1.2 --connect-timeout 10 --max-time 30 --retry 0 --max-filesize 16384 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/d51807fed8edc2d66a3e5a5bbde51834547184c7/scripts/launch-m2-retained-runtime-origins-20261101.sh \
    --output "$ouf_origin_join_tmp/run.sh"
  printf '%s  %s\n' b50d274cfdfa59848a99e2b1f8713c88e2c5ac45d77c67e9a106871cbda07b10 "$ouf_origin_join_tmp/run.sh" | sha256sum --check --strict
  sudo -v
  set +e
  bash "$ouf_origin_join_tmp/run.sh"
  ouf_origin_join_exit=$?
  set -e
  printf 'RuntimeOriginJoinExit=%s\n' "$ouf_origin_join_exit"
  exit "$ouf_origin_join_exit"
)
```

Successo atteso: `VERIFIED_RUNTIME_ROLES_JOINED_ORIGIN_CLAIMS_NOT_ADMITTED`,
13ruoli,10configmatch,3configaperte,11scope preservati,12controlli/35GET,
`RuntimeOriginJoinExit=0`. Non equivale a publisher autenticati o M2 accettato.

## Continuità e residuo

[Rilettura normativa](../../evidence/m2-runtime-origin-join-normative-review-20261101.json):
i PET ORIGINALI sono disponibili nel repo `docs/baseline/v1.7/package`, con testi
consultabili. Il vecchio limite documentale che li indicava indisponibili era
errato; corretto nel nuovo record con hash DOCX e sezioni effettivamente consultate.
Matrix1.7§1/4, Blueprint0.3§1/7/9, Gateway1.5T1/T2 e Semantic1.3§159.2/160.6.
Non è una nuova accettazione completa di tutti sette PET.

Teatri SEMPRE: handoffM1/auditM2,26join/13identità/20proprietà/8Cinema; tecnico8/8,
funzionale6/6 acquisiti. Riuso contratti owner/provenance/identity/property/recovery,
nessun nuovo motore o terza acquisizione. Stessa Farmacie61righe/10campiOPEN/
ministerialeSTRING preservata; nessun upload/profiling/acquisizione aggiuntiva.

Dopo il readback, completare i collegamenti source/publisher/scan pertinenti,
Gateway privato, policy/owner/custody/bearer correnti, coorte/pacchetto/review e
HUMAN/dual-role. Le riparazioni OS restano non selezionate/installate. M2/G5/G6/G7/
dueclient OPEN fino a61esiti UDP, repeatability e fault; poi grafo/search e
verticali/API scheduler/delta. Nessun merge o release acceptance.
