import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Make the application package importable for unit tests.
sys.path.insert(0, str(ROOT / "app"))
