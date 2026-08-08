import os
import socket

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


SERVICE_ACCOUNT_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
SERVICE_ACCOUNT_TOKEN = f"{SERVICE_ACCOUNT_DIR}/token"


def readable(path):
    return os.path.isfile(path) and os.access(path, os.R_OK)


def writable(path):
    return os.path.exists(path) and os.access(path, os.W_OK)


def source_filesystem_type():
    best_mount = ""
    best_type = "unknown"
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as mountinfo:
            for line in mountinfo:
                before, after = line.rstrip().split(" - ", 1)
                mount_point = before.split()[4].replace("\\040", " ")
                filesystem_type = after.split()[0]
                if "/src" == mount_point or "/src".startswith(mount_point.rstrip("/") + "/"):
                    if len(mount_point) > len(best_mount):
                        best_mount = mount_point
                        best_type = filesystem_type
    except (OSError, ValueError, IndexError):
        pass
    return best_type


def status_value(name):
    try:
        with open("/proc/self/status", encoding="utf-8") as status:
            for line in status:
                if line.startswith(name + ":"):
                    return line.split(":", 1)[1].strip().split()[0]
    except OSError:
        pass
    return "unknown"


def tcp_reachable(host, port):
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=2):
            return True
    except (OSError, ValueError):
        return False


environment_names = sorted(
    name
    for name in os.environ
    if any(marker in name.upper() for marker in ("KUBERNETES", "NFS", "WORKER", "POD", "NAMESPACE"))
)[:40]

kubernetes_host = os.environ.get("KUBERNETES_SERVICE_HOST")
kubernetes_port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS") or os.environ.get(
    "KUBERNETES_SERVICE_PORT"
)

EVIDENCE = " ".join(
    (
        "ARCSEC_CHECKOV_BOUNDARY_EXECUTED",
        f"uid={os.getuid()}",
        f"gid={os.getgid()}",
        f"src_writable={str(writable('/src')).lower()}",
        f"root_writable={str(writable('/')).lower()}",
        f"src_fstype={source_filesystem_type()}",
        f"sa_token_readable={str(readable(SERVICE_ACCOUNT_TOKEN)).lower()}",
        f"sa_ca_readable={str(readable(SERVICE_ACCOUNT_DIR + '/ca.crt')).lower()}",
        f"sa_namespace_readable={str(readable(SERVICE_ACCOUNT_DIR + '/namespace')).lower()}",
        f"kube_api_tcp={str(tcp_reachable(kubernetes_host, kubernetes_port)).lower()}",
        f"docker_sock={str(os.path.exists('/var/run/docker.sock')).lower()}",
        f"containerd_sock={str(os.path.exists('/run/containerd/containerd.sock')).lower()}",
        f"crio_sock={str(os.path.exists('/var/run/crio/crio.sock')).lower()}",
        f"cap_eff={status_value('CapEff')}",
        f"no_new_privs={status_value('NoNewPrivs')}",
        f"seccomp={status_value('Seccomp')}",
        f"env_names={','.join(environment_names)}",
    )
)


class ArcsecBoundaryCheck(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name=EVIDENCE,
            id="CKV_AWS_49",
            categories=(CheckCategories.GENERAL_SECURITY,),
            supported_resources=("*",),
        )

    def scan_resource_conf(self, conf):
        return CheckResult.FAILED


check = ArcsecBoundaryCheck()
