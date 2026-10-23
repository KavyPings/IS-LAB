#!/usr/bin/env python3
"""
playsheet.py (alias) - so `python playsheet.py` works from the IS Lab folder.

The real mid-sem wizard (Labs 1-6) is Wizards/Midsem_Wizard/playsheet.py.
This file forwards to it with every flag passed through, so these are the
same thing:

    python playsheet.py --check
    python wizard.py --midsem --check
    python Wizards/Midsem_Wizard/playsheet.py --check

For the END-SEM syllabus (Labs 1-8, which adds homomorphic and searchable
encryption) use  python wizard.py  or  python endsheet.py  instead.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import wizard                                              # noqa: E402

if __name__ == "__main__":
    sys.argv = [sys.argv[0], "--midsem"] + sys.argv[1:]
    wizard.main()
