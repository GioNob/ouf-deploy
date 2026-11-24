"""Matrice D-082 per 55n-01…08, passi e ricevute richieste agli owner."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Scenario:
    titolo: str
    riga: str
    sedi: str
    passi: tuple
    # Nome stabile della misura qualitativa e condizione attestata dal custode.
    oracoli: dict
    misure: tuple = ()


CAPACITY_METRICS = (
    "searchPerMinute", "fetchPerMinute", "searchPeak60", "fetchPeak60", "inFlight",
    "slotP95Seconds", "lockWaitP99Ms", "lockHeldP99Ms", "introspectionsPerDecision",
    "callsPerDecision", "introspectionPeak60", "decisionPeak60", "iamCapacityPerMinute",
    "controlP99Ms", "controlTimeouts", "scrapeIncreaseFraction", "scrapeP99Seconds",
)
CELLS = tuple(f"e2e.{cols}.{cache}.{queue}.{band}"
              for cols in (18, 1000) for cache in ("cold", "warm")
              for queue in ("free", "queued") for band in ((50,) if cols == 18 else (50, 80)))

CATALOG = {
    "55n-01": Scenario("Autorità corrente", "C · autorità ed effetti", "B",
        ("Far scadere il mandato a 30 s. Alterare body e path separatamente e negare la decisione.",
         "Revocare durante la pausa e durante l'inoltro. Rendere IAM indisponibile."),
        {"expiry": "Scadenza a 30 s rispettata.", "body": "Body alterato respinto.",
         "path": "Path alterato respinto.", "denied": "Decisione negata senza invio.",
         "revokePaused": "Nessuna ripresa dopo revoca in pausa.",
         "revokeForward": "Corsa revoca/inoltro riconciliata, effetto incerto in quarantena.",
         "iamDown": "Zero nuovi invii durante l'indisponibilità IAM."}),
    "55n-02": Scenario("Effetti e punti di commit", "C · autorità ed effetti", "B",
        ("Arrestare prima dell'inserimento owner.",
         "Arrestare dopo il commit owner con risposta trattenuta.",
         "Arrestare prima del commit MCP. A ogni barriera riavviare sugli stessi volumi e ritentare."),
        {"beforeOwner": "Prima dell'inserimento: una chiave owner, un job, un esito corrente e un consuntivo per tentativo.",
         "afterOwner": "Dopo il commit owner: stessi quattro invarianti nel ledger.",
         "beforeMcp": "Prima del commit MCP: stessi quattro invarianti nel ledger."}),
    "55n-03": Scenario("Due repliche e worker tardivo", "C · autorità ed effetti", "B",
        ("Contendere lo stesso lavoro su due repliche. Rilasciare il worker dopo il cambio di fence.",),
        {"replicas": "Un job e un solo esito corrente.",
         "fence": "Il worker tardivo non sovrascrive l'esito e non duplica la spesa."}),
    "55n-04": Scenario("Outage e ripresa", "C · resilienza", "B",
        ("Saturare la quota, applicare pressione su un tenant e provare la cancellazione.",
         "Interrompere la dipendenza per almeno due ore effettive. Riavviare durante la pausa.",
         "Confrontare ledger e checkpoint dopo la ripresa."),
        {"twoHours": "Almeno 7.200 secondi effettivi con restart durante l'outage.",
         "checkpoint": "notBefore, spesa e chiavi sopravvivono.",
         "cancel": "Cancellazione e pressione restano circoscritte."}),
    "55n-05": Scenario("Rinnovo HUMAN", "C · resilienza", "B",
        ("Esaurire il budget e inviare due conferme concorrenti del titolare.",
         "Riavviare e rileggere incidente, consumi, termini del mandato e nuova sessione."),
        {"session": "Una sessione e un rinnovo per incidente anche dopo restart.",
         "increase": "Incremento per voce entro il 25% del tetto iniziale.",
         "duration": "Durata entro 1 h, mandato e scadenza assoluta."}),
    "55n-06": Scenario("Capacità e controllo", "C · resilienza / R-043", "BA",
        ("Contendere l'ultimo posto tra avvio e rinnovo su più tenant e repliche.",
         "Saturare dati e relay con traffico PET confinato. Misurare controllo e costo IAM.",
         "Ripetere lo stesso carico con e senza scrape raccogliendo ogni processo."),
        {"admission": "Quattro attivi, uno per soggetto, un vincitore senza doppio posto.",
         "fifo": "FIFO e slot unico condiviso fino alla riconciliazione, attesa senza spesa.",
         "controlProof": "Due controlli serviti con dati saturi, due relay e riserva sui pool.",
         "r043": "100 soggetti distinti e 3.000 workflow vivi con attività per classe.",
         "counters": "Invii fisici e contatori riconciliati al netto della retention."}, CAPACITY_METRICS),
    "55n-07": Scenario("Prestazioni fino al riepilogo", "E2E e prestazioni / R-043", "BA",
        ("Misurare da avvio a SUMMARY con 18 e 1.000 colonne, caldo/freddo e con/senza coda.",
         "Eseguire a parte il caso di 1.000 residui unici sul simulatore."),
        {"ordinals": "Riepilogo completo per ordinale, anche con coda."}, (*CELLS, "unique1000")),
    "55n-08": Scenario("Isolamento HUMAN e percorso chatbot", "E2E / D-071", "A",
        ("Avviare dal chatbot senza istruzioni OUF, usare solo MCP e conferme THS.",
         "Usare due HUMAN con incarichi diversi sullo stesso client MCP.",
         "Leggere A con A e accedere a B con A. Correlare il 404 con la traccia custodita."),
        {"chatbot": "Percorso completato tramite MCP e THS.",
         "isolation": "A legge A, riceve 404 su B e causa zero inoltri su B.",
         "probe": "Sonda reale funzionale con un search e al massimo tre fetch inclusi i retry."}),
}

PREREQUISITES = {
    "B": "Digest candidati, owner reali, DB persistente, due repliche, APISIX, IAM e uscita confinata verificata.",
    "A": "T2 installata spenta, IAM applicato e qualify superata, worker drenati e inventario E2E. "
         "Aprire la finestra tipizzata approvata, provare controlProof sui pool prima del dispatch PET.",
}
STOP = "Fermare per deriva, scadenza, perdita di isolamento, quota o autorità, ricevuta assente o effetto incerto."
RETURN = {
    "B": "Esportare le tracce. Provare D-080 su DB popolato, quindi rimuovere realm e volumi dedicati.",
    "A": "Chiudere il dispatch e tornare a T2 spenta. Recintare i worker, riconciliare, revocare i grant PET, "
         "pulire gli ID inventariati e confrontare i checkpoint E2E.",
}


def requirements(sid, site):
    scenario = CATALOG[sid]
    if sid == "55n-07" and site == "A":
        return ("ordinals", "functionalSample")
    return (*scenario.oracoli, *scenario.misure)


def plan(manifest):
    site = manifest["site"]
    load = manifest["load"]
    cleanup = manifest["cleanup"]
    lines = [f"Piano PET C · sede {site} · {manifest['runId']}",
             f"Prerequisiti — {PREREQUISITES[site]}",
             f"Finestra — {manifest['createdAt']} / {manifest['expiresAt']}",
             f"Carico — {load['subjects']} soggetti, {load['tenants']} tenant, {load['workflows']} workflow",
             "Mix — " + ", ".join(f"{k}={v}" for k, v in sorted(load["mix"].items())),
             "Tenant PET — " + ", ".join(cleanup["tenants"]),
             "Sorgenti PET — " + ", ".join(cleanup["sources"]),
             f"Pulizia — prefisso {cleanup['idPrefix']}, inventario {cleanup['objectsManifest']}"]
    for key, value in sorted(manifest["candidates"].items()):
        lines.append(f"Candidato {key} — {value}")
    if manifest["provider"]["mode"] == "simulator":
        lines.append(f"Simulatore confinato — {manifest['provider']['baseUrl']}")
    steps = []
    for sid in sorted(manifest["scenarios"]):
        scenario = CATALOG[sid]
        actions = scenario.passi
        if sid == "55n-07" and site == "A":
            actions = ("Raccogliere un campione funzionale da avvio a SUMMARY sui pool reali.",)
        steps.extend(f"{sid} · {scenario.titolo} — {step}" for step in actions)
    if site == "A":
        provider = manifest["provider"]
        if provider["mode"] == "real-probe":
            steps.append(f"Sonda reale · tetto complessivo {provider['search']} search e "
                         f"{provider['fetch']} fetch, retry inclusi. Tenere confinato il carico.")
    lines.extend(f"{n}. {step}" for n, step in enumerate(steps, 1))
    lines.extend((f"Arresto — {STOP}", f"Ritorno — {RETURN[site]}"))
    return "\n".join(lines)
