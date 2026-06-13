from datetime import datetime
from pathlib import Path
from bitrixprobe.modules.sanitise_filename import safe_filename
import re


ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def build_audit_text_report(results, ssh_config, audit_config) -> str:
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ssh_host = ssh_config.get("ssh_host")
    ssh_port = ssh_config.get("ssh_port")
    ssh_user = ssh_config.get("ssh_user") or ssh_config.get("user")

    webroot = audit_config.get("webroot", "not specified")

    total_checks = len(results)

    failed_checks = []
    for result in results:
        if result["exit_code"] != 0:
            failed_checks.append(result)

    passed_checks = total_checks - len(failed_checks)

    lines = []

    lines.append("BitrixProbe Audit Report")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Created at: {created_at}")
    lines.append(f"SSH target: {ssh_user}@{ssh_host}:{ssh_port}")
    lines.append(f"Webroot: {webroot}")
    lines.append("")
    lines.append("Summary")
    lines.append("-" * 80)
    lines.append(f"Total checks: {total_checks}")
    lines.append(f"Successful checks: {passed_checks}")
    lines.append(f"Failed checks: {len(failed_checks)}")
    lines.append("")

    lines.append("Audit Results")
    lines.append("=" * 80)
    lines.append("")

    for index, result in enumerate(results, start=1):
        check_name = result.get("check_name", "Unknown check")
        exit_code = result.get("exit_code", "unknown")
        detect_status = result.get("detected")
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")

        if detect_status and exit_code == 0:
            status = "SUCCESS" if exit_code == 0 else "FAILED"
            #detected = "True" if detect_status else "False"

            lines.append(f"{index}. {check_name}")
            lines.append("-" * 80)
            lines.append(f"Verification Status: {status}")
            lines.append(f"Detection Result: {detect_status}")
            #lines.append(f"Exit code: {exit_code}")
            lines.append("")

            if stdout:
                lines.append("RESULT:")
                #lines.append(stdout.strip())
                lines.append(clean_report_text(stdout).strip())
                lines.append("")

            if stderr:
                lines.append("ERROR:")
                #lines.append(stderr.strip())
                lines.append(clean_report_text(stderr).strip())
                lines.append("")

            lines.append("")

    return "\n".join(lines)


def save_audit_report(results, ssh_config, audit_config) -> Path:
    output_dir = Path(audit_config.get("output_dir", "reports"))
    output_dir.mkdir(parents=True, exist_ok=True)

    ssh_host = ssh_config.get("ssh_host", "unknown_host")
    safe_host = safe_filename(ssh_host)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_path = output_dir / f"audit_report_{safe_host}_{timestamp}.txt"

    report_text = build_audit_text_report(
        results=results,
        ssh_config=ssh_config,
        audit_config=audit_config,
    )

    report_path.write_text(report_text, encoding="utf-8")

    return report_path


def clean_report_text(text) -> str:
    """
    Remove terminal ANSI escape codes from text before saving it to a report.
    """

    if text is None:
        return ""

    text = str(text)

    return ANSI_ESCAPE_RE.sub("", text)

def get_check_status_label(result) -> str:
    """
    Build a human-readable status label for a check result.
    """

    status = result.get("status", "error")
    exit_code = result.get("exit_code", 1)
    detected = result.get("detected", False)

    if status == "skipped":
        return "SKIPPED"

    if status != "ok" or exit_code != 0:
        return "FAILED"

    if detected:
        return "DETECTED"

    return "NOT DETECTED"


def format_report_key(key) -> str:
    """
    Convert dictionary key into a readable report label.
    """

    return str(key).replace("_", " ").strip().capitalize()


def format_report_value(value) -> str:
    """
    Convert a scalar value into a readable report value.
    """

    if value is None:
        return "-"

    if value == "":
        return "-"

    if isinstance(value, bool):
        return "yes" if value else "no"

    return str(value)


def is_scalar_report_value(value) -> bool:
    """
    Check whether value can be printed on one report line.
    """

    return isinstance(value, (str, int, float, bool)) or value is None


def append_report_data(lines, data, indent=0, ignored_keys=None, max_list_items=20) -> None:
    """
    Append nested dictionaries and lists to the text report.
    """

    if ignored_keys is None:
        ignored_keys = set()

    prefix = " " * indent

    if isinstance(data, dict):
        if not data:
            lines.append(f"{prefix}-")
            return

        for key, value in data.items():
            if key in ignored_keys:
                continue

            label = format_report_key(key)

            if is_scalar_report_value(value):
                lines.append(f"{prefix}{label}: {format_report_value(value)}")
            else:
                lines.append(f"{prefix}{label}:")
                append_report_data(
                    lines=lines,
                    data=value,
                    indent=indent + 2,
                    ignored_keys=ignored_keys,
                    max_list_items=max_list_items,
                )

        return

    if isinstance(data, list):
        if not data:
            lines.append(f"{prefix}-")
            return

        visible_items = data[:max_list_items]

        for index, item in enumerate(visible_items, start=1):
            if is_scalar_report_value(item):
                lines.append(f"{prefix}- {format_report_value(item)}")
            else:
                lines.append(f"{prefix}- Item {index}:")
                append_report_data(
                    lines=lines,
                    data=item,
                    indent=indent + 2,
                    ignored_keys=ignored_keys,
                    max_list_items=max_list_items,
                )

        hidden_items_count = len(data) - len(visible_items)

        if hidden_items_count > 0:
            lines.append(f"{prefix}- ... and {hidden_items_count} more items")

        return

    lines.append(f"{prefix}{format_report_value(data)}")


def build_pentest_text_report(target_url, results, context, pentest_config) -> str:
    """
    Build a text report for pentest mode results.
    """

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total_checks = len(results)

    failed_checks = []
    skipped_checks = []
    detected_checks = []
    not_detected_checks = []

    for result in results:
        status_label = get_check_status_label(result)

        if status_label == "FAILED":
            failed_checks.append(result)
        elif status_label == "SKIPPED":
            skipped_checks.append(result)
        elif status_label == "DETECTED":
            detected_checks.append(result)
        else:
            not_detected_checks.append(result)

    lines = []

    lines.append("BitrixProbe Report for Pentest")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Created at: {created_at}")
    lines.append(f"Target URL: {target_url}")
    lines.append("")

    lines.append("Summary")
    lines.append("-" * 80)
    lines.append(f"Total checks: {total_checks}")
    lines.append(f"Detected checks: {len(detected_checks)}")
    lines.append(f"Not detected checks: {len(not_detected_checks)}")
    lines.append(f"Skipped checks: {len(skipped_checks)}")
    lines.append(f"Failed checks: {len(failed_checks)}")
    lines.append("")

    lines.append("Scan Results")
    lines.append("=" * 80)
    lines.append("")

    for index, result in enumerate(results, start=1):
        check_name = result.get("check_name", "Unknown check")
        #check_id = result.get("check_id", "unknown")
        #exit_code = result.get("exit_code", "unknown")
        detected = result.get("detected", False)
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")

        status_label = get_check_status_label(result)

        lines.append(f"{index}. {check_name}")
        lines.append("-" * 80)
        #lines.append(f"Check ID: {check_id}")
        lines.append(f"Status: {status_label}")
        #lines.append(f"Detection Result: {detected}")
        #lines.append(f"Exit code: {exit_code}")
        lines.append("")

        if stdout:
            lines.append("RESULT:")
            lines.append(clean_report_text(stdout).strip())
            lines.append("")

        if stderr:
            lines.append("ERROR:")
            lines.append(clean_report_text(stderr).strip())
            lines.append("")

        lines.append("")

    '''lines.append("Structured Findings")
    lines.append("=" * 80)
    lines.append("")

    append_pentest_context_sections(
        lines=lines,
        context=context,
        pentest_config=pentest_config,
    )'''

    return "\n".join(lines)


def save_pentest_report(target_url, results, context, pentest_config) -> Path:
    """
    Save a text report for pentest mode results.
    """

    output_dir = Path(pentest_config.get("output_dir", "reports"))
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_target = safe_filename(target_url)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_path = output_dir / f"pentest_report_{safe_target}_{timestamp}.txt"

    report_text = build_pentest_text_report(
        target_url=target_url,
        results=results,
        context=context,
        pentest_config=pentest_config,
    )

    report_path.write_text(report_text, encoding="utf-8")

    return report_path