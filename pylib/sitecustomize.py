"""
Auto-loaded by Python when this pylib folder is on PYTHONPATH.

That makes the pure-Python crypto fallback apply to EVERY python process
without editing a single answer file - useful for running the per-lab
question files straight out of their own folders.

Set it up once (Windows PowerShell):

    setx PYTHONPATH "C:\\Users\\kavyk\\OneDrive\\Desktop\\Projects\\IS Lab\\pylib"

then open a new terminal. On macOS / Linux put this in ~/.bashrc:

    export PYTHONPATH="$HOME/.../IS Lab/pylib"

It does nothing at all on a machine where pycryptodome works normally, and it
can never stop Python from starting: every failure is swallowed.
"""

try:
    import islab_compat                                     # noqa: F401
except Exception:
    pass
