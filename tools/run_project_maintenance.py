#!/usr/bin/env python3
"""Run the fixed maintenance workflow through the existing project launcher."""
from pathlib import Path
import subprocess
import sys


def main():
    launcher = Path(__file__).resolve().parents[1] / 'bin' / 'fifan-maintain'
    return subprocess.call([str(launcher), 'maintenance', 'workflow', *sys.argv[1:]])


if __name__ == '__main__':
    raise SystemExit(main())
