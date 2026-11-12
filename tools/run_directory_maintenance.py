#!/usr/bin/env python3
"""Run the installed directory workflow with the project's existing launcher."""
from pathlib import Path
import subprocess
import sys


def main():
    launcher = Path(__file__).resolve().parents[1] / 'bin' / 'fifan-maintain'
    # No shell expansion, global interpreter switch, or duplicated workflow.
    return subprocess.call([str(launcher), 'directory', 'workflow', *sys.argv[1:]])


if __name__ == '__main__':
    raise SystemExit(main())
