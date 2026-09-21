"""Sphinx configuration for python-uds-server."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

project = "python-uds-server"
copyright = "2026, aronpuesche"
author = "aronpuesche"
release = "0.1.0"

extensions = ["sphinx.ext.autodoc", "sphinx.ext.napoleon"]
templates_path = ["_templates"]
exclude_patterns = ["_build"]
html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "vcs_pageview_mode": "edit",
}

# Render a source link in the page header.  It intentionally targets ``main``:
# released documentation is immutable, whereas the corresponding source page
# on the development branch is where a documentation correction can be made.
html_context = {
    "display_github": True,
    "github_user": "aronpuesche",
    "github_repo": "python-uds-server",
    "github_version": "main/",
    "conf_py_path": "/docs/",
}
