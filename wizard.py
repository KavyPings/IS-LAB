#!/usr/bin/env python3
r"""
wizard.py - the launcher. Run it from the IS Lab folder.

    python wizard.py --check            is this machine ready
    python wizard.py                    the questions, then write the answer
    python wizard.py --build evoting    build a preset, no questions
    python wizard.py --presets          the ready-made scenarios
    python wizard.py --options          every value every setting accepts
    python wizard.py --selftest         build and run every option
    python wizard.py --help             the full exam guide

    python wizard.py --midsem --check   the same flags for the Lab 1-6 wizard
    python wizard.py --midsem

The wizards themselves live two folders down, in Wizards/. This file finds
them, so the path can never be wrong, and it writes its output into the IS
Lab folder whichever directory you started from. endsheet.py and
playsheet.py beside it are the same launcher under the wizards' own names.

Everything after the flag is passed straight through. The exam guide below
comes from the end-sem wizard itself; the long form is in
Wizards/Endsem_Wizard/INSTRUCTIONS.md.
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
        # then the exam guide, read straight out of the end-sem wizard so the
        # two can never drift apart
        try:
            text = open(ENDSEM, encoding="utf-8").read()
            begin = text.index('r"""') + 4
            print(text[begin:text.index('"""', begin)])
        except Exception:
            pass
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
