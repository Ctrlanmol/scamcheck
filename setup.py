"""Shim so pip works (editable installs) with the old setuptools that ships
with Apple's command-line Python. All metadata lives in pyproject.toml."""

from setuptools import setup

setup()
