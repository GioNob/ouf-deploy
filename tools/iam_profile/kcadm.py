"""Render a review sheet. Keycloak is never contacted and no native IDs are guessed."""
from .plan import plan
from .profile import ACTIONS, RENEW, THS, require


EXAMPLE_SCOPES = THS | {RENEW} | {f"ouf.analysis.mandate.{action}" for action in ACTIONS}


class Review:
    def __init__(self, plan_hash):
        self.header = [
            "# kcadm-plan " + plan_hash,
            "# Confrontare ANDATA e RITORNO col plan. Copiare solo le funzioni revisionate.",
            "# Eseguire le andate in ordine e i ritorni necessari in ordine inverso.",
        ]
        self.variables = {}
        self.blocks = []
        self.count = 0

    def variable(self, name, source, *, initial=None):
        assignment = initial if initial is not None else "${" + name + "-}"
        self.variables[name] = (source, assignment)
        return '"${' + name + ':?}"'

    def pair(self, write, verify, undo, verify_undo):
        self.count += 1
        for label, command, check in (("andata", write, verify), ("ritorno", undo, verify_undo)):
            self.blocks.extend([f"{label}_{self.count}() {{", "  " + command + " &&",
                                "  " + check, "}"])

    def render(self):
        result = self.header.copy()
        for name, (source, assignment) in self.variables.items():
            result.extend(["# " + source, f"{name}={assignment}"])
        return "\n".join([*result, *self.blocks, ""])


def scope_changes(review, role, desired, before):
    client = review.variable(role.upper() + "_ID", f"UUID Keycloak verificato del client {role}.")
    for adding, names, other in ((True, desired, before), (False, before, desired)):
        source = "PROFILE" if adding else "BEFORE.managed"
        for i, name in enumerate(names):
            if name in other:
                continue
            prefix = role.upper() + ("_ADD_" if adding else "_DEL_") + str(i + 1)
            ref = f"{source} clients.{role}.scopes[{i}]"
            uuid = review.variable(prefix + "_ID", "UUID dello scope corrispondente a " + ref)
            mode = review.variable(prefix + "_MODE", "Binding approvato: default oppure optional.")
            members = f'clients/{client}/{mode}-client-scopes'
            target = f'{members}/{uuid}'
            review.blocks.append(f"# {ref}")
            if adding:
                scope = review.variable(prefix + "_NAME", ref,
                                        initial=name if name in EXAMPLE_SCOPES else None)
                review.blocks.extend([
                    "# DA VERIFICARE: presenza e proprieta dello scope nel realm.",
                    "# Solo per uno scope assente: creare e conservare l'UUID restituito.",
                ])
                created = prefix + "_CREATED"
                native_id = review.variable(created, "UUID assegnato dalla sola creazione qui sotto.",
                                            initial="''")
                scopes = 'kcadm.sh get client-scopes -r "$REALM" --fields id,name'
                review.pair(
                    f'{created}=$(kcadm.sh create client-scopes -r "$REALM" -i \\\n'
                    f'    -s name={scope} -s protocol=openid-connect \\\n'
                    """    -s 'attributes={"include.in.token.scope":"true"}')""",
                    f'kcadm.sh get client-scopes/{native_id} -r "$REALM" --fields id,name',
                    f'kcadm.sh delete client-scopes/{native_id} -r "$REALM"', scopes)
                review.blocks.append(f"# Per il nuovo scope impostare {prefix}_ID=${created}")
            review.blocks.append("# DA VERIFICARE: usare il binding nativo approvato per questo scope.")
            bind = f'kcadm.sh update -n \\\n    {target} \\\n    -r "$REALM"'
            unbind = f'kcadm.sh delete \\\n    {target} \\\n    -r "$REALM"'
            check = f'kcadm.sh get {members} \\\n    -r "$REALM" --fields id,name'
            review.pair(bind if adding else unbind, check, unbind if adding else bind, check)


def client_change(review, path, inverse):
    server = path == "grant.resourceServer.clientId"
    prefix = "RS" if server else path.split(".")[1].upper()
    name = review.variable(prefix + "_CLIENT", "PROFILE " + path)
    if inverse == "delete":
        uuid = review.variable("RS_ID", "UUID restituito alla creazione del resource-server.", initial="''")
        review.blocks.append("# Verificare assenza e proprieta del client prima della creazione.")
        write = ('RS_ID=$(kcadm.sh create clients -r "$REALM" -i \\\n'
                 f'    -s clientId={name} -s protocol=openid-connect -s publicClient=false \\\n'
                 '    -s authorizationServicesEnabled=true -s serviceAccountsEnabled=true)')
        undo = f'kcadm.sh delete clients/{uuid} -r "$REALM"'
        verify_undo = 'kcadm.sh get clients -r "$REALM" -q clientId="$RS_CLIENT" --fields id,clientId'
    else:
        uuid = review.variable(prefix + "_ID", "UUID Keycloak verificato per BEFORE.managed " + path)
        old = review.variable("OLD_" + prefix + "_CLIENT", "BEFORE.managed " + path)
        update = f'kcadm.sh update clients/{uuid} -n -r "$REALM"'
        write = f"{update} -s clientId={name}"
        undo = f"{update} -s clientId={old}"
        if server:
            review.blocks.append("# DA VERIFICARE: stato precedente di Authorization Services e service account.")
        verify_undo = f'kcadm.sh get clients/{uuid} -r "$REALM" --fields id,clientId'
    check = (f'kcadm.sh get clients/{uuid} -r "$REALM" \\\n'
             '    --fields id,clientId,authorizationServicesEnabled,serviceAccountsEnabled')
    review.pair(write, check if server else verify_undo, undo, verify_undo)


def kcadm_plan(profile, snapshot):
    projected = plan(profile, snapshot)
    require(profile["kind"] == "keycloak-ouf", "KEYCLOAK_PROFILE_REQUIRED")
    review = Review(projected["planSha256"])
    inverse = {row["path"]: row["action"] for row in projected["returnDiff"]}
    for row in projected["diff"]:
        path, action = row["path"], row["action"]
        if action not in ("create", "update"):
            continue
        review.blocks.extend(["", f"# {path} | ANDATA {action} | RITORNO {inverse[path]}"])
        if path.endswith(".scopes"):
            role = path.split(".")[1]
            scope_changes(review, role, profile["clients"][role]["scopes"],
                          snapshot["managed"].get(path, []))
        elif path == "grant.resourceServer.clientId" or (path.endswith(".clientId") and action == "update"):
            client_change(review, path, inverse[path])
        elif path.endswith(".clientId"):
            review.blocks.append("# DA VERIFICARE: flussi e autenticazione del nuovo client MCP o THS.")
        elif ".mappers." in path:
            review.blocks.append("# DA VERIFICARE: provider, configurazione e UUID del mapper effettivo.")
        elif path == "grant.resourceType":
            review.blocks.append("# DA VERIFICARE: il tipo non identifica una risorsa di incarico da creare.")
        elif path.endswith(".secretRef"):
            review.blocks.append("# DA VERIFICARE: binding del riferimento nel canale privato del custode.")
        else:
            review.blocks.append("# DA VERIFICARE: lo schema non specifica la scrittura nativa e il ritorno.")
    if review.count:
        review.variable("REALM", "Realm dal suffisso /realms/<realm> di PROFILE trust.issuer.",
                        initial="${REALM:?}")
    return review.render()
