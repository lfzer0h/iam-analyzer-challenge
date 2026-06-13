"""Support ``python -m analyzer`` as an alternative entry point.

Usage:
    python -m analyzer --input fixtures/account-export-example.json --output reports/
"""

import sys
from .cli import main

sys.exit(main())
