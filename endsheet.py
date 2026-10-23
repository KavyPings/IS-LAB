#!/usr/bin/env python3
"""
endsheet.py (alias) - so `python endsheet.py` works from the IS Lab folder.

The real end-sem wizard is Wizards/Endsem_Wizard/endsheet.py. This file just
forwards to it, with every flag passed through unchanged, so all three of
these do exactly the same thing from here:

    python endsheet.py --check
    python wizard.py --check
    python Wizards/Endsem_Wizard/endsheet.py --check
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import wizard                                              # noqa: E402

if __name__ == "__main__":
    wizard.main()
