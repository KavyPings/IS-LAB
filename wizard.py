#!/usr/bin/env python3
r"""
================================================================================
 wizard.py - ONE entry point for both answer writers
================================================================================

The problem this file solves: the wizards live two folders deep, so
"python endsheet.py" only works if you happen to be standing in exactly the
right directory. This file sits in the IS Lab folder and finds them itself,
so the path can never be wrong.

USE  (from the IS Lab folder, or with the full path from anywhere)

    python wizard.py --check            is the environment ready
    python wizard.py                    run the end-sem wizard (same as --wizard)
    python wizard.py --wizard           the same thing, spelled out
    python wizard.py --build evoting    build a preset without the questions
    python wizard.py --presets          list the ready-made scenarios
    python wizard.py --options          every value each setting accepts
    python wizard.py --selftest         build and run 40 configurations

    python wizard.py --midsem --check   the same flags, but for Lab 1-6
    python wizard.py --midsem --wizard

Anything after the flag is passed straight through to the real wizard, so
every option in Wizards/Endsem_Wizard/INSTRUCTIONS.md works here too.

WHERE THE OUTPUT GOES
    answer.py and answer_clean.py are written into the IS Lab folder - the
    folder this file is in - no matter which directory you started from.
    Then:   python answer.py demo      full run, no typing
            python answer.py           the interactive menu
================================================================================
"""

import os
import runpy
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ENDSEM = os.path.join(HERE, "Wizards", "Endsem_Wizard", "endsheet.py")
MIDSEM = os.path.join(HERE, "Wizards", "Midsem_Wizard", "playsheet.py")


def main():
    args = sys.argv[1:]

    if args and args[0] in ("-h", "--help", "help"):
        print(__doc__)
        return

    # --midsem (or just "midsem") picks the Lab 1-6 wizard instead
    use_midsem = False
    if args and args[0].lower().lstrip("-") == "midsem":
        use_midsem = True
        args = args[1:]

    target = MIDSEM if use_midsem else ENDSEM
    name = "playsheet.py" if use_midsem else "endsheet.py"

    if not os.path.exists(target):
        print("cannot find", name)
        print("expected it at:", target)
        print()
        print("This file has to sit in the IS Lab folder, next to the Wizards")
        print("folder. If you moved it, move it back, or run the wizard directly:")
        print("   python", os.path.join("Wizards", "Endsem_Wizard", "endsheet.py"),
              "--wizard")
        raise SystemExit(1)

    # no arguments is almost always "write me an answer"
    if not args:
        args = ["--wizard"]

    # keep the output beside this file, whichever directory we were started from
    if os.getcwd() != HERE:
        os.chdir(HERE)
        print("working folder:", HERE)

    # load the pure-Python crypto fallback if this machine blocks
    # pycryptodome's compiled modules; a no-op when they load fine
    try:
        sys.path.insert(0, os.path.join(HERE, "pylib"))
        import islab_compat
        if islab_compat.MODE == "pure":
            print("note:", islab_compat.status())
    except Exception:
        pass

    # one friendly check before handing over, except for --check which reports
    # on the environment itself
    if args[0] != "--check":
        try:
            import Crypto                                    # noqa: F401
        except ImportError:
            print("pycryptodome is not installed in this Python.")
            print("   python -m venv .venv")
            print("   .venv\\Scripts\\activate          (Windows)")
            print("   source .venv/bin/activate        (macOS / Linux)")
            print("   pip install pycryptodome")
            print()
            print("Then:  python wizard.py --check")
            raise SystemExit(1)

    sys.argv = [target] + args
    runpy.run_path(target, run_name="__main__")


if __name__ == "__main__":
    main()
