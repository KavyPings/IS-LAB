"""
islab - one line that makes an answer file run on a locked-down machine.

    import islab        # put this ABOVE the "from Crypto..." imports

Some Windows machines run an Application Control policy (WDAC, or Smart App
Control) that refuses to load pycryptodome's compiled .pyd files, and the
import dies with:

    OSError: Cannot load native module 'Crypto.Hash._SHA1': ... error 0x11c7

There is nothing to install that fixes it - the operating system is blocking
the binary, not Python. This module loads the pure-Python replacements from
the pylib folder instead, registered under the usual Crypto.* names, so the
rest of the file does not change at all.

On a machine where pycryptodome works, importing this does nothing.

    python islab.py         prints which backend is in use
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "pylib"))

import islab_compat                                         # noqa: E402

MODE = islab_compat.MODE
status = islab_compat.status
ensure = islab_compat.ensure

if __name__ == "__main__":
    print(islab_compat.status())
