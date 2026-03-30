from __future__ import annotations

# Kept for local development convenience so `streamlit run app.py` still works.
# The installable UI entry point is `log-anonymizer-ui`.

import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parent
_src = _repo_root / "src"
if _src.exists() and str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from log_anonymizer.ui_app import main


if __name__ == "__main__":
    main()
