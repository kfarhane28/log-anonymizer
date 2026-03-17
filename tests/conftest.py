from __future__ import annotations

import sys
from pathlib import Path

# Allow `import log_anonymizer.*` without requiring an editable install.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

