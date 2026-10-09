"""Security boundaries for repository automation and browser mutations."""
import importlib.util
from pathlib import Path
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("configure_github", ROOT / "Tools/configure_github.py")
github = importlib.util.module_from_spec(spec)
spec.loader.exec_module(github)

@pytest.mark.parametrize("path", ["--hostname=attacker.invalid", "repos/owner/repo/../../users", "repos/owner/repo?redirect=bad", "https://attacker.invalid", "repos/owner/repo\n--hostname=bad"])
def test_api_rejects_injected_endpoints_before_running_gh(path):
    with patch.object(github.subprocess, "run") as run:
        with pytest.raises(ValueError):
            github.api(path)
        run.assert_not_called()

def test_api_keeps_payload_on_stdin_and_endpoint_after_delimiter():
    with patch.object(github.subprocess, "run") as run:
        run.return_value.stdout = "{}"
        github.api("repos/owner/repo", "PATCH", {"description": "--hostname=bad"})
        command = run.call_args.args[0]
        assert command[-2:] == ["--", "repos/owner/repo"]
        assert "--hostname=bad" not in command
        assert run.call_args.kwargs["input"] == '{"description": "--hostname=bad"}'
