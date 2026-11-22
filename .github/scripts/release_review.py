"""Render the public facts of a release before its next deployment review."""


# Budget the encoded workflow command in UTF-8, including its title and suffix.
NOTICE_BYTES = 4096
MORE = "… vedi il riepilogo del job"


def command_data(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace("::", "%3A%3A")


def approval(summary, phase, digest, facts):
    lines = [f"Job {phase} {digest}", *facts]
    body = "\n".join(lines)
    prefix = f"::notice title=Da approvare: {phase}::"
    command = prefix + command_data(body)
    if len(command.encode()) > NOTICE_BYTES:
        # Slice the source so neither a UTF-8 character nor an escape is split.
        budget = NOTICE_BYTES - len((prefix + MORE).encode())
        low, high = 0, min(len(body), budget)
        while low < high:
            mid = (low + high + 1) // 2
            if len(command_data(body[:mid]).encode()) <= budget:
                low = mid
            else:
                high = mid - 1
        command = prefix + command_data(body[:low]) + MORE
    print(f"**Cosa approvi con il job {phase}**", file=summary)
    print(file=summary)
    for line in body.splitlines():
        print("    " + line, file=summary)
    print(file=summary)
    print(command)
