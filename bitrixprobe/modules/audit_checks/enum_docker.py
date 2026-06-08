import json
import re
import shlex
from datetime import datetime, timezone
from bitrixprobe.console import red_badge, red, yellow, green, blue
from bitrixprobe.modules.ssh_client import run_remote_shell

"""
Enumerate Docker Engine resources and identify common container security risks.
"""


CHECK_ID = "system.docker.enum_security"
CHECK_NAME = "Docker Engine Security Enumeration"
OWASP_DOCKER_CHEAT_SHEET = "h_ttps://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"

DEPENDS_ON = []
REQUIRES_DETECTED = []

DOCKER_COMMANDS = [
    {
        "key": "info",
        "title": "docker info",
        "command": "docker info --format '{{json .}}'",
    },
    {
        "key": "containers",
        "title": "docker ps",
        "command": "docker ps -a --no-trunc --format '{{json .}}'",
    },
    {
        "key": "networks",
        "title": "docker network ls",
        "command": "docker network ls --format '{{json .}}'",
    },
    {
        "key": "volumes",
        "title": "docker volume ls",
        "command": "docker volume ls --format '{{json .}}'",
    },
    {
        "key": "images",
        "title": "docker images",
        "command": "docker images --digests --no-trunc --format '{{json .}}'",
    },
]

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

SENSITIVE_ENV_PATTERN = re.compile(
    r"(^|_)(PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|"
    r"ACCESS_KEY|CREDENTIAL|AUTH)(_|$)",
    re.IGNORECASE,
)

SENSITIVE_SERVICE_KEYWORDS = (
    "admin",
    "database",
    "elasticsearch",
    "jenkins",
    "mariadb",
    "mongo",
    "mysql",
    "opensearch",
    "postgres",
    "rabbitmq",
    "redis",
    "ssh",
    "vault",
)

SENSITIVE_SERVICE_PORTS = {
    22,
    2375,
    2376,
    3306,
    5432,
    5672,
    6379,
    8200,
    9200,
    9300,
    15672,
    27017
}


def compact_error(text, limit=500) -> str:
    """
    Normalize command error text and limit its size for reports.
    """

    normalized = " ".join((text or "").split())

    if len(normalized) <= limit:
        return normalized

    return normalized[:limit].rstrip() + "..."


def is_privilege_error(*texts) -> bool:
    """
    Return True when command output contains a known privilege failure marker.
    """

    safe_texts = []
    for text in texts:
        if text:
            safe_texts.append(text)
        else:
            safe_texts.append("")

    combined = " ".join(safe_texts)
    combined = combined.lower()

    markers = (
        "access denied",
        "a password is required",
        "authentication is required",
        "must be run as root",
        "no tty present",
        "a terminal is required",
        "not in the sudoers",
        "no password was provided",
        "operation not permitted",
        "permission denied",
        "sorry, try again",
        "sudoers",
    )

    for marker in markers:
        if marker in combined:
            return True

    return False


def redact_secret(text, secret) -> str:
    """
    Remove a sensitive value from command output before reporting it.
    """

    text = text or ""

    if not secret:
        return text

    return text.replace(secret, "[REDACTED]")


def run_command_with_sudo(client, title, command, ssh_config) -> dict:
    """
    Run a command directly and retry permission failures through sudo.
    """

    direct_result = run_remote_shell(client, command)

    if direct_result["exit_code"] == 0:
        return {
            "title": title,
            "command": command,
            "status": "ok",
            "access": "direct",
            "exit_code": 0,
            "stdout": direct_result["stdout"],
            "stderr": direct_result["stderr"].strip(),
        }

    direct_privilege_error = is_privilege_error(
        direct_result["stdout"],
        direct_result["stderr"],
    )

    if not direct_privilege_error:
        error_text = compact_error(
            " ".join(
                part
                for part in (
                    direct_result["stderr"],
                    direct_result["stdout"],
                )
                if part
            )
        )

        return {
            "title": title,
            "command": command,
            "status": "failed",
            "access": "none",
            "exit_code": direct_result["exit_code"],
            "stdout": "",
            "stderr": error_text,
        }

    if ssh_config:
        ssh_password = ssh_config.get("ssh_password")
    else:
        ssh_password = ""

    if ssh_password:
        ssh_password = str(ssh_password)
    else:
        ssh_password = ""

    sudo_stdin = None

    if ssh_password:
        sudo_command = f"sudo -S -p '' /bin/sh -c {shlex.quote(command)}"
        sudo_stdin = ssh_password + "\n"
    else:
        sudo_command = f"sudo -n /bin/sh -c {shlex.quote(command)}"

    sudo_result = run_remote_shell(
        client=client,
        command=sudo_command,
        stdin_data=sudo_stdin,
    )

    if sudo_result["exit_code"] == 0:
        return {
            "title": title,
            "command": command,
            "status": "ok",
            "access": "sudo",
            "exit_code": 0,
            "stdout": sudo_result["stdout"],
            "stderr": redact_secret(
                sudo_result["stderr"],
                ssh_password,
            ).strip(),
        }

    privilege_error = is_privilege_error(
        direct_result["stdout"],
        direct_result["stderr"],
        sudo_result["stdout"],
        sudo_result["stderr"],
    )
    if privilege_error:
        status = "insufficient_privileges"
    else:
        status = "failed"

    error_parts = [
        direct_result["stderr"],
        direct_result["stdout"],
        sudo_result["stderr"],
        sudo_result["stdout"],
    ]
    error_text = compact_error(
        redact_secret(
            " ".join(part for part in error_parts if part),
            ssh_password,
        )
    )

    return {
        "title": title,
        "command": command,
        "status": status,
        "access": "none",
        "exit_code": sudo_result["exit_code"],
        "stdout": "",
        "stderr": error_text,
    }


def parse_json_lines(output, title) -> tuple:
    """
    Parse newline-delimited Docker JSON output into dictionaries.
    """

    items = []
    errors = []

    for line_number, line in enumerate(output.splitlines(), start=1):
        line = line.strip()

        if not line:
            continue

        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            errors.append(f"{title} line {line_number}: invalid JSON ({error})")
            continue

        if isinstance(value, dict):
            items.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    items.append(item)
        else:
            errors.append(f"{title} line {line_number}: unexpected JSON value")

    return items, errors


def detect_docker_presence(client) -> dict:
    """
    Detect the Docker CLI, daemon process, and service state.
    """

    command = r"""
docker_path="$(command -v docker 2>/dev/null || true)"
service_load_state="unknown"
service_state="unknown"
daemon_process="absent"

if command -v systemctl >/dev/null 2>&1; then
    service_load_state="$(
        systemctl show docker.service -p LoadState --value 2>/dev/null || true
    )"
    service_state="$(systemctl is-active docker.service 2>/dev/null || true)"
fi

if ps -eo args= 2>/dev/null | grep -E '[d]ockerd([[:space:]]|$)' >/dev/null 2>&1; then
    daemon_process="present"
fi

printf 'docker_path=%s\n' "$docker_path"
printf 'service_load_state=%s\n' "$service_load_state"
printf 'service_state=%s\n' "$service_state"
printf 'daemon_process=%s\n' "$daemon_process"
"""
    probe_result = run_remote_shell(client, command)
    values = {}

    for line in probe_result["stdout"].splitlines():
        key, separator, value = line.partition("=")

        if separator:
            values[key.strip()] = value.strip()

    detected = (
        bool(values.get("docker_path"))
        or values.get("service_load_state") == "loaded"
        or values.get("daemon_process") == "present"
    )

    return {
        "detected": detected,
        "docker_path": values.get("docker_path", ""),
        "service_load_state": values.get("service_load_state", "unknown"),
        "service_state": values.get("service_state", "unknown"),
        "daemon_process": values.get("daemon_process", "absent"),
        "exit_code": probe_result["exit_code"],
        "stderr": probe_result["stderr"].strip(),
    }


def get_daemon_configuration(client, ssh_config) -> tuple:
    """
    Collect Docker daemon arguments and daemon.json with sudo fallback.
    """

    process_result = run_remote_shell(
        client,
        "ps -eo args= 2>/dev/null | grep -E '[d]ockerd([[:space:]]|$)' || true",
    )
    config_result = run_command_with_sudo(
        client=client,
        title="Docker daemon configuration",
        command=(
            "if [ -e /etc/docker/daemon.json ]; then "
            "cat /etc/docker/daemon.json; else printf '{}\\n'; fi"
        ),
        ssh_config=ssh_config,
    )
    daemon_config = {}
    errors = []

    if config_result["status"] == "ok" and config_result["stdout"].strip():
        try:
            parsed_config = json.loads(config_result["stdout"])

            if isinstance(parsed_config, dict):
                daemon_config = parsed_config
            else:
                errors.append("Docker daemon configuration is not a JSON object.")
        except json.JSONDecodeError as error:
            errors.append(f"Docker daemon configuration: invalid JSON ({error})")

    if process_result["exit_code"] != 0 and process_result["stderr"]:
        errors.append(compact_error(process_result["stderr"]))

    return {
        "process_arguments": process_result["stdout"].strip(),
        "daemon_config": daemon_config,
        "config_access": config_result["access"],
        "config_status": config_result["status"],
        "config_error": config_result["stderr"],
        "config_command_result": config_result,
    }, errors


def extract_tcp_hosts(process_arguments, daemon_config) -> list:
    """
    Extract configured Docker TCP daemon listeners from arguments and JSON.
    """

    hosts = []

    for line in process_arguments.splitlines():
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = line.split()

        index = 0

        while index < len(tokens):
            token = tokens[index]
            host = ""

            if token in ("-H", "--host") and index + 1 < len(tokens):
                host = tokens[index + 1]
                index += 1
            elif token.startswith("--host="):
                host = token.split("=", 1)[1]
            elif token.startswith("-H") and token != "-H":
                host = token[2:]

            if host.startswith("tcp://") and host not in hosts:
                hosts.append(host)

            index += 1

    configured_hosts = daemon_config.get("hosts", [])

    if isinstance(configured_hosts, str):
        configured_hosts = [configured_hosts]

    if isinstance(configured_hosts, list):
        for host in configured_hosts:
            if isinstance(host, str) and host.startswith("tcp://"):
                if host not in hosts:
                    hosts.append(host)

    return hosts


def daemon_tls_enabled(process_arguments, daemon_config) -> bool:
    """
    Determine whether Docker daemon TLS is enabled in arguments or JSON.
    """

    for line in process_arguments.splitlines():
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = line.split()

        for token in tokens:
            if token in ("--tls", "--tlsverify"):
                return True

            if token in ("--tls=true", "--tlsverify=true"):
                return True

    return daemon_config.get("tls") is True or daemon_config.get("tlsverify") is True


def get_container_name(container) -> str:
    """
    Return a stable human-readable container name.
    """

    name = str(container.get("Name", "")).lstrip("/")

    if name:
        return name

    return str(container.get("Id", container.get("ID", "unknown")))[:12]


def get_container_identity(container) -> dict:
    """
    Build a compact container identity dictionary.
    """

    config = container.get("Config") or {}

    return {
        "container_id": str(container.get("Id", container.get("ID", ""))),
        "container_name": get_container_name(container),
        "image": str(config.get("Image", container.get("Image", ""))),
    }


def add_finding(
    findings,
    finding_id,
    severity,
    title,
    evidence,
    recommendation,
    owasp_rule,
    container=None,
) -> None:
    """
    Append a normalized security finding.
    """

    finding = {
        "finding_id": finding_id,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
        "owasp_rule": owasp_rule,
    }

    if container:
        finding.update(get_container_identity(container))

    findings.append(finding)


def is_docker_socket_mount(mount) -> bool:
    """
    Return True when a mount exposes the Docker daemon Unix socket.
    """

    source = str(mount.get("Source", "")).rstrip("/")

    return source in ("/var/run/docker.sock", "/run/docker.sock")


def is_host_root_mount(mount) -> bool:
    """
    Return True when a bind mount exposes the host root directory.
    """

    return mount.get("Type") == "bind" and str(mount.get("Source", "")) == "/"


def get_sensitive_env_keys(container) -> list:
    """
    Return suspicious environment variable names without exposing values.
    """

    config = container.get("Config") or {}
    environment = config.get("Env") or []
    keys = []

    for entry in environment:
        key = str(entry).split("=", 1)[0]

        if SENSITIVE_ENV_PATTERN.search(key) and key not in keys:
            keys.append(key)

    return sorted(keys)


def container_runs_as_root(container) -> bool:
    """
    Determine whether Docker configured the container to run as root.
    """

    config = container.get("Config") or {}
    user = str(config.get("User") or "").strip().lower()

    root_like_users = ("", "0", "root")
    if user in root_like_users:
        return True
    if user.startswith("0:"):
        return True

    return False


def image_uses_latest_tag(image_reference) -> bool:
    """
    Determine whether an image reference uses the latest or implicit latest tag.
    """

    image_reference = str(image_reference or "").strip()

    if not image_reference:
        return False

    if image_reference.startswith("sha256:") or "@sha256:" in image_reference:
        return False

    final_component = image_reference.rsplit("/", 1)[-1]

    if final_component.endswith(":latest"):
        return True
    if ":" not in final_component:
        return True

    return False


def has_resource_limits(host_config) -> bool:
    """
    Return True when at least one memory, CPU, or process limit is configured.
    """

    numeric_fields = (
        "Memory",
        "NanoCpus",
        "CpuQuota",
        "CpuCount",
        "PidsLimit",
    )

    for field in numeric_fields:
        value = host_config.get(field)

        if isinstance(value, (int, float)) and value > 0:
            return True

    return False


def get_exposed_ports(container) -> list:
    """
    Return normalized exposed container port specifications.
    """

    config = container.get("Config") or {}
    exposed_ports = config.get("ExposedPorts") or {}

    if not isinstance(exposed_ports, dict):
        return []

    ports_as_strings = []
    for port in exposed_ports:
        port_as_string = str(port)
        ports_as_strings.append(port_as_string)
    sorted_ports = sorted(ports_as_strings)

    return sorted_ports


def container_has_sensitive_service(container) -> bool:
    """
    Heuristically identify a sensitive service in a host-network container.
    """

    identity = get_container_identity(container)
    searchable = " ".join(
        [
            identity["container_name"],
            identity["image"],
            " ".join(str(item) for item in (container.get("Args") or [])),
        ]
    ).lower()

    if any(keyword in searchable for keyword in SENSITIVE_SERVICE_KEYWORDS):
        return True

    for port_specification in get_exposed_ports(container):
        port_text = port_specification.split("/", 1)[0]

        if port_text.isdigit() and int(port_text) in SENSITIVE_SERVICE_PORTS:
            return True

    return False


def analyze_daemon_security(daemon_data) -> list:
    """
    Analyze Docker daemon listener configuration for unsafe remote API access.
    """

    findings = []
    tcp_hosts = extract_tcp_hosts(
        daemon_data.get("process_arguments", ""),
        daemon_data.get("daemon_config", {}),
    )
    tls_enabled = daemon_tls_enabled(
        daemon_data.get("process_arguments", ""),
        daemon_data.get("daemon_config", {}),
    )

    if tcp_hosts and not tls_enabled:
        add_finding(
            findings=findings,
            finding_id="docker_remote_api_without_tls",
            severity="critical",
            title="Docker remote API is configured without TLS",
            evidence="Configured TCP listener(s): " + ", ".join(tcp_hosts),
            recommendation=(
                "Disable the TCP listener or require mutually authenticated TLS "
                "and restrict network access to trusted management hosts."
            ),
            owasp_rule="OWASP Docker Security Rule #1",
        )

    return findings


def analyze_container_security(container) -> list:
    """
    Analyze one Docker inspect object and return security findings.
    """

    findings = []
    host_config = container.get("HostConfig") or {}
    mounts = container.get("Mounts") or []
    security_options = [
        str(option).lower() for option in (host_config.get("SecurityOpt") or [])
    ]
    privileged = host_config.get("Privileged") is True
    bind_mounts = [
        mount for mount in mounts if mount.get("Type") == "bind"
    ]

    socket_mounts = [mount for mount in mounts if is_docker_socket_mount(mount)]

    if socket_mounts:
        destinations = [
            str(mount.get("Destination", "-")) for mount in socket_mounts
        ]
        add_finding(
            findings=findings,
            finding_id="docker_socket_mounted",
            severity="critical",
            title="Docker daemon socket is mounted into a container",
            evidence="Container destination(s): " + ", ".join(destinations),
            recommendation=(
                "Remove the Docker socket mount. A read-only socket mount still "
                "provides dangerous control over the Docker daemon."
            ),
            owasp_rule="OWASP Docker Security Rule #1",
            container=container,
        )

    writable_root_mounts = [
        mount
        for mount in bind_mounts
        if is_host_root_mount(mount) and mount.get("RW") is True
    ]

    if writable_root_mounts:
        add_finding(
            findings=findings,
            finding_id="docker_host_root_mounted",
            severity="critical",
            title="Host root filesystem is mounted writable",
            evidence="The host path / is exposed through a writable bind mount.",
            recommendation=(
                "Remove the host root mount or narrowly scope the required path "
                "and mount it read-only."
            ),
            owasp_rule="OWASP Docker Security Rule #8",
            container=container,
        )

    if privileged and bind_mounts:
        sources = sorted(
            {
                str(mount.get("Source", "-"))
                for mount in bind_mounts
                if mount.get("Source")
            }
        )
        add_finding(
            findings=findings,
            finding_id="docker_privileged_host_mount",
            severity="critical",
            title="Privileged container has host bind mounts",
            evidence="Host path(s): " + ", ".join(sources),
            recommendation=(
                "Disable privileged mode and replace broad host mounts with "
                "minimal read-only mounts."
            ),
            owasp_rule="OWASP Docker Security Rules #3 and #8",
            container=container,
        )

    if privileged:
        add_finding(
            findings=findings,
            finding_id="docker_container_privileged",
            severity="high",
            title="Container runs in privileged mode",
            evidence="HostConfig.Privileged is true.",
            recommendation=(
                "Disable privileged mode and grant only the capabilities and "
                "devices required by the workload."
            ),
            owasp_rule="OWASP Docker Security Rule #3",
            container=container,
        )

    capabilities = [
        str(capability).upper()
        for capability in (host_config.get("CapAdd") or [])
    ]

    if "SYS_ADMIN" in capabilities:
        add_finding(
            findings=findings,
            finding_id="docker_sys_admin_capability",
            severity="high",
            title="Container has the SYS_ADMIN capability",
            evidence="HostConfig.CapAdd contains SYS_ADMIN.",
            recommendation=(
                "Remove SYS_ADMIN and grant only narrowly required capabilities."
            ),
            owasp_rule="OWASP Docker Security Rule #3",
            container=container,
        )

    if "seccomp=unconfined" in security_options:
        add_finding(
            findings=findings,
            finding_id="docker_seccomp_unconfined",
            severity="high",
            title="Docker seccomp filtering is disabled",
            evidence="HostConfig.SecurityOpt contains seccomp=unconfined.",
            recommendation="Use Docker's default seccomp profile or a stricter profile.",
            owasp_rule="OWASP Docker Security Rule #6",
            container=container,
        )

    apparmor_profile = str(container.get("AppArmorProfile") or "").lower()

    if (
        "apparmor=unconfined" in security_options
        or apparmor_profile == "unconfined"
    ):
        add_finding(
            findings=findings,
            finding_id="docker_apparmor_unconfined",
            severity="high",
            title="Docker AppArmor confinement is disabled",
            evidence="The container explicitly uses an unconfined AppArmor profile.",
            recommendation="Apply docker-default or a workload-specific AppArmor profile.",
            owasp_rule="OWASP Docker Security Rule #6",
            container=container,
        )

    network_mode = str(host_config.get("NetworkMode") or "")

    if network_mode == "host":
        sensitive_service = container_has_sensitive_service(container)
        severity = "high" if sensitive_service else "medium"
        evidence = "HostConfig.NetworkMode is host."

        if sensitive_service:
            evidence += " The container appears to run a sensitive service."

        add_finding(
            findings=findings,
            finding_id="docker_host_network_mode",
            severity=severity,
            title="Container shares the host network namespace",
            evidence=evidence,
            recommendation=(
                "Use a dedicated bridge network and publish only required ports "
                "on explicitly selected host addresses."
            ),
            owasp_rule="OWASP Docker Security Rules #5 and #5a",
            container=container,
        )

    sensitive_env_keys = get_sensitive_env_keys(container)

    if sensitive_env_keys:
        add_finding(
            findings=findings,
            finding_id="docker_sensitive_env_vars",
            severity="high",
            title="Potential secrets are stored in container environment variables",
            evidence="Suspicious variable name(s): " + ", ".join(sensitive_env_keys),
            recommendation=(
                "Move sensitive values to Docker secrets or an external secrets "
                "manager and rotate values that may have been exposed."
            ),
            owasp_rule="OWASP Docker Security Rule #12",
            container=container,
        )

    if container_runs_as_root(container):
        add_finding(
            findings=findings,
            finding_id="docker_container_runs_as_root",
            severity="medium",
            title="Container is configured to run as root",
            evidence="Config.User is empty, root, or UID 0.",
            recommendation="Configure a dedicated unprivileged user for the workload.",
            owasp_rule="OWASP Docker Security Rule #2",
            container=container,
        )

    writable_bind_mounts = [
        mount
        for mount in bind_mounts
        if mount.get("RW") is True
        and not is_host_root_mount(mount)
        and not is_docker_socket_mount(mount)
    ]

    if writable_bind_mounts:
        mount_pairs = [
            f"{mount.get('Source', '-')}:{mount.get('Destination', '-')}"
            for mount in writable_bind_mounts
        ]
        add_finding(
            findings=findings,
            finding_id="docker_writable_host_mount",
            severity="medium",
            title="Container has writable host bind mounts",
            evidence="Writable mount(s): " + ", ".join(mount_pairs),
            recommendation=(
                "Use named volumes where possible and make host bind mounts "
                "read-only unless writes are strictly required."
            ),
            owasp_rule="OWASP Docker Security Rule #8",
            container=container,
        )

    if not has_resource_limits(host_config):
        add_finding(
            findings=findings,
            finding_id="docker_no_resource_limits",
            severity="medium",
            title="Container has no memory, CPU, or process limits",
            evidence="Memory, CPU quota, NanoCPUs, CPU count, and PIDs limits are unset.",
            recommendation="Define memory, CPU, PIDs, ulimit, and restart constraints.",
            owasp_rule="OWASP Docker Security Rule #7",
            container=container,
        )

    config = container.get("Config") or {}
    image_reference = config.get("Image", "")

    if image_uses_latest_tag(image_reference):
        add_finding(
            findings=findings,
            finding_id="docker_latest_image_tag",
            severity="medium",
            title="Container image is not pinned to an immutable version",
            evidence=f"Image reference: {image_reference}",
            recommendation="Pin the image to a reviewed version tag and digest.",
            owasp_rule="OWASP Docker Security Rules #9 and #13",
            container=container,
        )

    healthcheck = config.get("Healthcheck") or {}
    healthcheck_test = healthcheck.get("Test") if isinstance(healthcheck, dict) else None

    if not healthcheck_test or healthcheck_test == ["NONE"]:
        add_finding(
            findings=findings,
            finding_id="docker_no_healthcheck",
            severity="info",
            title="Container has no configured healthcheck",
            evidence="Config.Healthcheck is not configured.",
            recommendation="Add a workload-specific healthcheck and monitor failures.",
            owasp_rule="Operational hardening",
            container=container,
        )

    exposed_ports = get_exposed_ports(container)
    network_settings = container.get("NetworkSettings") or {}
    published_ports = network_settings.get("Ports") or {}

    if len(exposed_ports) >= 10 and not any(published_ports.values()):
        add_finding(
            findings=findings,
            finding_id="docker_broad_internal_ports",
            severity="info",
            title="Container declares a broad set of internal ports",
            evidence=f"Declared internal ports: {len(exposed_ports)}",
            recommendation="Review exposed ports and retain only required services.",
            owasp_rule="OWASP Docker Security Rules #5 and #5a",
            container=container,
        )

    return findings


def parse_docker_created_at(value):
    """
    Parse the timestamp emitted by docker images --format JSON output.
    """

    value = str(value or "").strip()

    if not value:
        return None

    try:
        return datetime.strptime(value[:25], "%Y-%m-%d %H:%M:%S %z")
    except ValueError:
        return None


def analyze_image_security(images, maximum_age_days=365) -> list:
    """
    Identify locally stored images whose creation time is unusually old.
    """

    findings = []
    current_time = datetime.now(timezone.utc)

    for image in images:
        created_at = parse_docker_created_at(image.get("CreatedAt"))

        if created_at is None:
            continue

        age_days = (current_time - created_at.astimezone(timezone.utc)).days

        if age_days <= maximum_age_days:
            continue

        repository = str(image.get("Repository") or "<none>")
        tag = str(image.get("Tag") or "<none>")
        image_id = str(image.get("ID") or "")
        findings.append(
            {
                "finding_id": "docker_old_image",
                "severity": "low",
                "title": "Locally stored Docker image is old",
                "evidence": (
                    f"Image {repository}:{tag} is approximately "
                    f"{age_days} days old ({created_at.date()})."
                ),
                "recommendation": (
                    "Confirm that the image is still supported, scan it for "
                    "known vulnerabilities, and rebuild it from current bases."
                ),
                "owasp_rule": "OWASP Docker Security Rules #0, #9, and #13",
                "image_id": image_id,
                "image": f"{repository}:{tag}",
            }
        )

    return findings


def normalize_engine_info(info) -> dict:
    """
    Keep a safe allowlist of Docker Engine inventory fields.
    """

    allowed_fields = (
        "Architecture",
        "CgroupDriver",
        "CgroupVersion",
        "Containers",
        "ContainersPaused",
        "ContainersRunning",
        "ContainersStopped",
        "DockerRootDir",
        "Driver",
        "ID",
        "Images",
        "KernelVersion",
        "MemTotal",
        "NCPU",
        "Name",
        "OperatingSystem",
        "OSType",
        "ServerVersion",
        "SecurityOptions",
    )

    result = {}
    for field in allowed_fields:
        if field in info:
            result[field] = info[field]

    return result


def normalize_container_inventory(container) -> dict:
    """
    Build a container inventory record without environment values.
    """

    config = container.get("Config") or {}
    host_config = container.get("HostConfig") or {}
    state = container.get("State") or {}
    mounts = container.get("Mounts") or []

    return {
        **get_container_identity(container), # Unpack dictionary
        "state": state.get("Status", ""),
        "running": state.get("Running", False),
        "user": config.get("User", ""),
        "network_mode": host_config.get("NetworkMode", ""),
        "privileged": host_config.get("Privileged", False),
        "read_only_rootfs": host_config.get("ReadonlyRootfs", False),
        "cap_add": host_config.get("CapAdd") or [],
        "security_options": host_config.get("SecurityOpt") or [],
        "environment_keys": sorted(
            str(entry).split("=", 1)[0] for entry in (config.get("Env") or [])
        ),
        "mounts": [
            {
                "type": mount.get("Type", ""),
                "source": mount.get("Source", ""),
                "destination": mount.get("Destination", ""),
                "read_write": mount.get("RW", False),
            }
            for mount in mounts
        ],
        "exposed_ports": get_exposed_ports(container),
    }


def normalize_list_inventory(items, allowed_fields) -> list:
    """
    Keep selected fields from Docker list command records.
    """

    normalized_items = []

    for item in items:
        normalized_items.append(
            {
                field: item.get(field)
                for field in allowed_fields
                if field in item
            }
        )

    return normalized_items


def format_command_status(command_results) -> str:
    """
    Format command access and privilege status for terminal output.
    """

    lines = ["[Command access status]"]

    for command_result in command_results:
        title = command_result["title"]
        status = command_result["status"]

        if status == "ok":
            lines.append(f"- {title}: ok ({command_result['access']})")
        elif status == "insufficient_privileges":
            lines.append(
                f"- {title}: insufficient privileges after direct and sudo -n attempts"
            )
        else:
            lines.append(f"- {title}: failed after direct and sudo -n attempts")

    return "\n".join(lines)


def format_findings(findings) -> str:
    """
    Format Docker security findings for terminal and report output.
    """
    if not findings:
        return "[Security findings]\nNo analyzed Docker security issues were detected."

    def get_finding_sort_key(item):
        severity = item["severity"]
        severity_order = SEVERITY_ORDER.get(severity, 99)
        finding_id = item["finding_id"]
        container_name = item.get("container_name", "")

        return (
            severity_order,
            finding_id,
            container_name,
        )


    lines = ["[Security findings]"]

    sorted_findings = sorted(
        findings,
        key=get_finding_sort_key,
    )

    for finding in sorted_findings:
        if finding['severity'] == "high":
            finding_severity = red("HIGH")
        elif finding['severity'] == "medium":
            finding_severity = yellow("MEDIUM")
        elif finding['severity'] == "low":
            finding_severity = blue("LOW")
        else:
            finding_severity = finding['severity'].upper()

        lines.append(
            f"[{finding_severity}] {finding['finding_id']}"
        )
        lines.append(f"Title: {finding['title']}")

        if finding.get("container_name"):
            lines.append(
                "Container: "
                f"{finding['container_name']} "
                f"({finding.get('container_id', '-')[:12]})"
            )
            lines.append(f"Image: {finding.get('image', '-')}")

        lines.append(f"Evidence: {finding['evidence']}")
        lines.append(f"Recommendation: {finding['recommendation']}")
        lines.append(f"Reference: {finding['owasp_rule']}")
        lines.append("")

    return "\n".join(lines).rstrip()


def build_summary(presence, engine_info, inventories, findings) -> str:
    """
    Build a concise Docker inventory and severity summary.
    """

    severity_counts = {
        severity: sum(
            1 for finding in findings if finding["severity"] == severity
        )
        for severity in SEVERITY_ORDER
    }
    version = engine_info.get("ServerVersion") or "not available"
    lines = [
        "[Docker inventory]",
        f"Docker CLI: {presence.get('docker_path') or 'not found'}",
        (
            "Docker service load state: "
            f"{presence.get('service_load_state', 'unknown')}"
        ),
        f"Docker service state: {presence.get('service_state', 'unknown')}",
        f"Docker daemon process: {presence.get('daemon_process', 'unknown')}",
        f"Docker Engine version: {version}",
        f"Containers enumerated: {len(inventories['containers'])}",
        f"Images enumerated: {len(inventories['images'])}",
        f"Networks enumerated: {len(inventories['networks'])}",
        f"Volumes enumerated: {len(inventories['volumes'])}",
        (
            "Findings: "
            f"critical={severity_counts['critical']}, "
            f"high={severity_counts['high']}, "
            f"medium={severity_counts['medium']}, "
            f"low={severity_counts['low']}, "
            f"info={severity_counts['info']}"
        ),
        f"Guidance: {OWASP_DOCKER_CHEAT_SHEET}",
    ]

    return "\n".join(lines)


def build_command_context(command_results) -> list:
    """
    Build safe command metadata without storing raw Docker command output.
    """

    return [
        {
            "title": item["title"],
            "status": item["status"],
            "access": item["access"],
            "exit_code": item["exit_code"],
            "error": item["stderr"],
        }
        for item in command_results
    ]


def run(client, audit_config, ssh_config, context) -> dict:
    """
    Enumerate Docker resources over SSH and analyze container security settings.
    """

    result = {
        "exit_code": 1,
        "status": "error",
        "detected": False,
        "stdout": "",
        "stderr": "",
    }
    errors = []
    presence = detect_docker_presence(client)

    if "bitrix" not in context:
        context["bitrix"] = {}

    if not presence["detected"]:
        context["bitrix"]["docker_security"] = {
            "detected": False,
            "presence": presence,
            "engine": {},
            "containers": [],
            "images": [],
            "networks": [],
            "volumes": [],
            "findings": [],
            "commands": [],
            "errors": [],
        }
        result["exit_code"] = 0
        result["status"] = "ok"
        result["detected"] = False
        result["stdout"] = "Docker Engine was not detected on the remote host."
        result["stderr"] = presence["stderr"]

        return result

    command_results = []
    parsed_results = {}

    for command_definition in DOCKER_COMMANDS:
        command_result = run_command_with_sudo(
            client=client,
            title=command_definition["title"],
            command=command_definition["command"],
            ssh_config=ssh_config,
        )
        command_results.append(command_result)

        if command_result["status"] != "ok":
            parsed_results[command_definition["key"]] = []

            if command_result["stderr"]:
                errors.append(
                    f"{command_definition['title']}: {command_result['stderr']}"
                )

            continue

        parsed_items, parse_errors = parse_json_lines(
            output=command_result["stdout"],
            title=command_definition["title"],
        )
        parsed_results[command_definition["key"]] = parsed_items
        errors.extend(parse_errors)

    container_inspections = []
    container_list = parsed_results.get("containers", [])

    for container_item in container_list:
        container_id = str(
            container_item.get("ID")
            or container_item.get("Id")
            or container_item.get("Names")
            or ""
        )

        if not container_id:
            errors.append("docker inspect: container identifier is missing")
            continue

        inspect_command = (
            "docker inspect --type container --format '{{json .}}' "
            + shlex.quote(container_id)
        )
        inspect_result = run_command_with_sudo(
            client=client,
            title=f"docker inspect {container_id[:12]}",
            command=inspect_command,
            ssh_config=ssh_config,
        )
        command_results.append(inspect_result)

        if inspect_result["status"] != "ok":
            if inspect_result["stderr"]:
                errors.append(
                    f"{inspect_result['title']}: {inspect_result['stderr']}"
                )

            continue

        inspected_items, parse_errors = parse_json_lines(
            output=inspect_result["stdout"],
            title=inspect_result["title"],
        )
        container_inspections.extend(inspected_items)
        errors.extend(parse_errors)

    daemon_data, daemon_errors = get_daemon_configuration(
        client=client,
        ssh_config=ssh_config,
    )
    command_results.append(daemon_data["config_command_result"])
    errors.extend(daemon_errors)
    findings = analyze_daemon_security(daemon_data)
    findings.extend(analyze_image_security(parsed_results.get("images", [])))

    for container in container_inspections:
        findings.extend(analyze_container_security(container))

    info_items = parsed_results.get("info", [])
    engine_info = normalize_engine_info(info_items[0]) if info_items else {}
    inventories = {
        "containers": [
            normalize_container_inventory(container)
            for container in container_inspections
        ],
        "images": normalize_list_inventory(
            parsed_results.get("images", []),
            ("ID", "Repository", "Tag", "Digest", "CreatedAt", "Size"),
        ),
        "networks": normalize_list_inventory(
            parsed_results.get("networks", []),
            ("ID", "Name", "Driver", "Scope", "IPv6", "Internal", "CreatedAt"),
        ),
        "volumes": normalize_list_inventory(
            parsed_results.get("volumes", []),
            ("Name", "Driver", "Scope", "Mountpoint"),
        ),
    }
    context["bitrix"]["docker_security"] = {
        "detected": True,
        "presence": presence,
        "engine": engine_info,
        "containers": inventories["containers"],
        "images": inventories["images"],
        "networks": inventories["networks"],
        "volumes": inventories["volumes"],
        "daemon": {
            "tcp_hosts": extract_tcp_hosts(
                daemon_data["process_arguments"],
                daemon_data["daemon_config"],
            ),
            "tls_enabled": daemon_tls_enabled(
                daemon_data["process_arguments"],
                daemon_data["daemon_config"],
            ),
            "config_status": daemon_data["config_status"],
            "config_access": daemon_data["config_access"],
        },
        "findings": findings,
        "commands": build_command_context(command_results),
        "errors": errors,
    }

    result["exit_code"] = 0
    result["status"] = "ok"
    result["detected"] = True
    result["stdout"] = "\n\n".join(
        [
            build_summary(
                presence=presence,
                engine_info=engine_info,
                inventories=inventories,
                findings=findings,
            ),
            format_command_status(command_results),
            format_findings(findings),
        ]
    )
    result["stderr"] = "\n".join(errors)

    return result
