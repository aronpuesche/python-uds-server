"""Sphinx configuration for python-uds-server."""

from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

project = "python-uds-server"
copyright = "2026, aronpuesche"
author = "aronpuesche"
release = "0.1.0"

extensions = ["sphinx.ext.autodoc", "sphinx.ext.napoleon"]
templates_path = ["_templates"]
exclude_patterns = ["_build"]
html_theme = "alabaster"
