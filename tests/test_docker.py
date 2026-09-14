import subprocess

import pytest


@pytest.mark.integration
def test_compose_configuration_is_valid():
    result = subprocess.run(
        ["docker", "compose", "config", "--quiet"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
