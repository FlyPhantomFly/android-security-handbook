#!/usr/bin/env python3
# 76-CheatSheets/scripts/github_slug.py
#
# PURPOSE
#   Give the MkDocs site build the same heading slugs GitHub uses. The corpus's
#   ~7,700 heading-anchor links were verified against GitHub's rules by
#   check-anchors.py; python-markdown's `toc` extension would otherwise mint
#   its own (different) slugs and break a fraction of them on the website.
#
#   This module exposes check-anchors.py's slug function under the callable
#   signature `toc` expects:  slugify(value, separator) -> str
#
# WIRING
#   mkdocs.yml:            toc.slugify: !!python/name:github_slug.slugify
#   build environment:     PYTHONPATH must include this directory (set in
#                          .github/workflows/deploy-pages.yml and locally:
#                          PYTHONPATH=76-CheatSheets/scripts mkdocs build ...)
#
# NOTE
#   check-anchors.py has a hyphen in its filename, so it cannot be imported by
#   name; it is loaded here by file path instead.

import importlib.util
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "check_anchors_mod", os.path.join(_HERE, "check-anchors.py")
)
_ca = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_ca)


def slugify(value, separator="-"):
    """Slugify a heading exactly the way GitHub does (check-anchors.py rules)."""
    return _ca.slug(value)
