import importlib.util
import sys
from pathlib import Path

import pytest

# The functions under test live in the Lambda layer source tree, not an
# installed package - add it to sys.path rather than packaging/installing
# remediation_common just to test it.
COMMON_LAYER_ROOT = Path(__file__).parent.parent / "terraform" / "lambda" / "common" / "python"
sys.path.insert(0, str(COMMON_LAYER_ROOT))


REPO_ROOT = Path(__file__).parent.parent


@pytest.fixture
def load_module(monkeypatch):
    """Load a Lambda handler or SSM script by file path, as a fresh module
    per test, so settings read from the environment at import time can
    differ between tests. boto3 clients made at import make no calls until
    used; tests swap them for MagicMock objects, so nothing reaches AWS.
    """
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")

    def _load(relative_path, **env):
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        path = REPO_ROOT / relative_path
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    return _load
