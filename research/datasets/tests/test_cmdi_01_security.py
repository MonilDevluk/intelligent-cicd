import sys
from pathlib import Path

BENCHMARK_DIR = (
    Path(__file__).resolve().parents[3]
    / "experiments"
    / "vulns"
)

if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

import os

from cmdi_01 import (
    ping_host,
    list_files,
    get_file_info,
)


MARKER = "/tmp/contextguard_cmdi_pwned"


def remove_marker():
    try:
        os.remove(MARKER)
    except FileNotFoundError:
        pass


def assert_marker_not_created():
    assert not os.path.exists(MARKER), (
        "Command injection succeeded: attacker-controlled input "
        "executed an additional shell command."
    )


def test_ping_host_blocks_command_injection():
    remove_marker()

    malicious_input = f"127.0.0.1; touch {MARKER}"

    ping_host(malicious_input)

    assert_marker_not_created()


def test_list_files_blocks_command_injection():
    remove_marker()

    malicious_input = f".; touch {MARKER}"

    try:
        list_files(malicious_input)
    except Exception:
        pass

    assert_marker_not_created()


def test_get_file_info_blocks_command_injection():
    remove_marker()

    malicious_input = f"/etc/hosts; touch {MARKER}"

    try:
        get_file_info(malicious_input)
    except Exception:
        pass

    assert_marker_not_created()
