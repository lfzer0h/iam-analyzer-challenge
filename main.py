#!/usr/bin/env python3
"""Executable entry point for the IAM contextual risk analyzer.

Usage:
    python main.py --input fixtures/account-export-example.json --output reports
"""

import sys

from analyzer.cli import main

if __name__ == "__main__":
    sys.exit(main())
