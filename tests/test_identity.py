"""Project identity must stay consistent across the packaged metadata."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

AUTHOR = "vulnquest"
GITHUB_USER = "vulnquest58"
GITHUB_URL = f"https://github.com/{GITHUB_USER}"
REPO_URL = f"{GITHUB_URL}/HashVault"


def test_banner_module_is_the_single_source_of_identity():
    from hashvault.ui import banner

    assert banner.PROJECT_NAME == AUTHOR
    assert banner.GITHUB_USER == GITHUB_USER
    assert banner.GITHUB_URL == GITHUB_URL
    assert f"{banner.GITHUB_URL}/{banner.REPOSITORY_NAME}" == REPO_URL


def test_pyproject_declares_the_author_and_urls():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert AUTHOR in text
    assert GITHUB_URL in text
    assert "[project.urls]" in text


def test_readme_credits_the_author_and_repository():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert AUTHOR in text
    assert GITHUB_URL in text
    assert REPO_URL in text


def test_readme_banner_svg_exists_and_is_valid_svg():
    svg = ROOT / "docs" / "banner.svg"
    assert svg.is_file(), "README references docs/banner.svg"
    content = svg.read_text(encoding="utf-8")
    assert content.lstrip().startswith("<svg")
    assert content.rstrip().endswith("</svg>")
    assert AUTHOR in content


def test_readme_banner_path_matches_the_file_on_disk():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    for referenced in re.findall(r'src="([^"]+)"', text):
        if referenced.startswith("http"):
            continue
        assert (ROOT / referenced).is_file(), f"missing README asset: {referenced}"
