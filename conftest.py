import os
import sys

# Make the `pogcm` package importable when running pytest from the repo root.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
