import sys
from pathlib import Path

# The functions under test live in the Lambda layer source tree, not an
# installed package - add it to sys.path rather than packaging/installing
# remediation_common just to test it.
COMMON_LAYER_ROOT = Path(__file__).parent.parent / "terraform" / "lambda" / "common" / "python"
sys.path.insert(0, str(COMMON_LAYER_ROOT))
