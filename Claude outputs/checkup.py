#!/usr/bin/env python3
r"""
checkup.py - test everything in this folder, or tidy it up.

    python checkup.py            run the full test and write checkup_report.txt
    python checkup.py tidy       move the leftover junk into _to_delete\
    python checkup.py quick      the fast subset (skips the two self-tests)

The test covers: the environment, the crypto backend, known-answer vectors
for the pure-Python fallback, both wizards, all six presets built and run,
the menus, the TCP client/server, every per-lab question file, and both
wizard self-tests. Everything it finds goes into checkup_report.txt, and a
summary is printed at the end.

`tidy` never deletes anything. It moves leftovers into a dated _to_delete
folder so you can look before you throw them away.
"""

import os
import shutil
import subprocess
import sys
import time
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(ROOT, "checkup_report.txt")
PY = sys.executable

lines = []
results = []

# Every child process needs to be able to find islab.py and pylib/, so the
# fallback applies even to the per-lab question files, which have no import
# line of their own. Setting PYTHONPATH permanently (see the hint printed by
# test_environment) does the same thing for runs started by hand.
CHILD_ENV = dict(os.environ)
CHILD_ENV["PYTHONPATH"] = os.pathsep.join(
    [p for p in (ROOT, os.path.join(ROOT, "pylib"),
                 CHILD_ENV.get("PYTHONPATH", "")) if p])


def say(text=""):
    print(text)
    lines.append(text)


def record(label, ok, detail=""):
    results.append((label, ok, detail))
    say("  %-4s %-46s %s" % ("ok" if ok else "FAIL", label, detail))


def run(label, args, cwd=None, stdin_text="", expect=None, timeout=1800,
        forbid_traceback=True):
    """Run python with args and judge the outcome."""
    started = time.time()
    try:
        done = subprocess.run([PY] + args, cwd=cwd or ROOT, input=stdin_text,
                              capture_output=True, text=True, timeout=timeout,
                              errors="replace", env=CHILD_ENV)
    except subprocess.TimeoutExpired:
        record(label, False, "timed out after %ds" % timeout)
        return ""
    output = (done.stdout or "") + (done.stderr or "")
    elapsed = time.time() - started

    problem = ""
    if done.returncode != 0:
        problem = "exit code %d" % done.returncode
    elif forbid_traceback and "Traceback" in output:
        problem = "traceback in output"
    elif expect and expect not in output:
        problem = "missing %r" % expect

    record(label, not problem, problem or "%.1fs" % elapsed)
    lines.append("      $ python " + " ".join(args))
    for line in output.strip().split("\n")[-6:]:
        if line.strip():
            lines.append("      | " + line[:150])
    return output


# ---------------------------------------------------------------------------
# A  environment and backend
# ---------------------------------------------------------------------------

def test_environment():
    say("=" * 78)
    say(" A. ENVIRONMENT")
    say("=" * 78)
    say("  python      : %s" % sys.version.split()[0])
    say("  executable  : %s" % PY)
    say("  folder      : %s" % ROOT)
    say("  in a venv   : %s" % (sys.prefix != getattr(sys, "base_prefix", sys.prefix)))
    say()

    try:
        import Crypto
        say("  pycryptodome: %s" % Crypto.__version__)
    except Exception as exc:
        record("pycryptodome is installed", False, repr(exc))
        return False

    sys.path.insert(0, ROOT)
    try:
        import islab
        say("  backend     : %s" % islab.status())
        say("  mode        : %s" % islab.MODE)
        record("crypto backend available", True, islab.MODE)
        pure = islab.MODE == "pure"
    except Exception as exc:
        record("crypto backend available", False, repr(exc))
        return False
    say()

    # Running a per-lab question file BY HAND, from its own folder, only works
    # if PYTHONPATH points at pylib. This test passes PYTHONPATH to its own
    # child processes either way, so say plainly whether the permanent setup
    # is there.
    pylib = os.path.join(ROOT, "pylib")
    on_path = any(os.path.normcase(part.rstrip(os.sep)) == os.path.normcase(pylib)
                  for part in os.environ.get("PYTHONPATH", "").split(os.pathsep)
                  if part)
    if not pure:
        record("PYTHONPATH set up for direct runs", True, "not needed, native modules load")
    else:
        record("PYTHONPATH set up for direct runs", on_path,
               "" if on_path else "see the command below")
        if not on_path:
            say()
            say("  The fallback is in use, so running a question file straight out of")
            say("  its own folder needs this once (then open a new terminal):")
            say()
            say('     setx PYTHONPATH "%s"' % pylib)
            say()
            say("  Without it, python wizard.py and the answer files still work -")
            say("  only the per-lab question files need it. This test supplies it to")
            say("  its own child processes, so the results below are unaffected.")
    say()
    return True


# ---------------------------------------------------------------------------
# B  known-answer vectors - does the crypto on THIS machine give right answers
# ---------------------------------------------------------------------------

def test_vectors():
    say("=" * 78)
    say(" B. KNOWN-ANSWER VECTORS (proves the crypto is correct on this machine)")
    say("=" * 78)
    from Crypto.Cipher import AES, DES
    from Crypto.Hash import SHA512
    from Crypto.PublicKey import ECC, RSA
    from Crypto.Signature import DSS, pkcs1_15
    from Crypto.Util.Padding import pad, unpad

    # FIPS-197 AES
    for key_hex, plain_hex, want in [
        ("000102030405060708090a0b0c0d0e0f",
         "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617",
         "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
    ]:
        got = AES.new(bytes.fromhex(key_hex), AES.MODE_ECB).encrypt(
            bytes.fromhex(plain_hex)).hex()
        record("AES-%d FIPS-197 vector" % (len(key_hex) * 4), got == want,
               "" if got == want else got)

    # the classic DES worked example
    got = DES.new(bytes.fromhex("133457799BBCDFF1"), DES.MODE_ECB).encrypt(
        bytes.fromhex("0123456789ABCDEF")).hex().upper()
    record("DES standard vector", got == "85E813540F0AB405", "" if got ==
           "85E813540F0AB405" else got)

    # RFC 4493 AES-CMAC
    try:
        from Crypto.Hash import CMAC
        got = CMAC.new(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
                       b"", ciphermod=AES).hexdigest()
        record("CMAC RFC 4493 vector", got == "bb1d6929e95937287fa37d129b756746",
               "" if got == "bb1d6929e95937287fa37d129b756746" else got)
    except Exception as exc:
        record("CMAC RFC 4493 vector", False, repr(exc))

    # the SHA-512 the end-sem sample paper prints for ballot B001
    ballot = b"CandidateID=1;ConstituencyID=101"
    want = ("a2152f5e30dee0d9be483e7ed69a634eaba168e7757fd9d46f8ba7a1236a8712"
            "5d12b4e6c824a2c7f777dd929e295296854fff55ed4c71b9d84c6b69e0c54ed4")
    got = SHA512.new(ballot).hexdigest()
    record("SHA-512 matches the sample paper", got == want, "" if got == want else got[:32])

    # every mode round-trips
    key = os.urandom(32)
    data = b"the house is being sold tonight at 2200 hours"
    for name, mode, needs_pad in [("ECB", AES.MODE_ECB, True), ("CBC", AES.MODE_CBC, True),
                                  ("CFB", AES.MODE_CFB, False), ("OFB", AES.MODE_OFB, False),
                                  ("CTR", AES.MODE_CTR, False)]:
        try:
            body = pad(data, 16) if needs_pad else data
            enc = AES.new(key, mode) if mode == AES.MODE_ECB else AES.new(key, mode)
            iv = getattr(enc, "iv", None) or getattr(enc, "nonce", None)
            ct = enc.encrypt(body)
            kwargs = {}
            if mode in (AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB):
                kwargs["iv"] = iv
            elif mode == AES.MODE_CTR:
                kwargs["nonce"] = iv
            dec = AES.new(key, mode, **kwargs).decrypt(ct)
            if needs_pad:
                dec = unpad(dec, 16)
            record("AES-256-%s round trip" % name, dec == data)
        except Exception as exc:
            record("AES-256-%s round trip" % name, False, repr(exc))

    for name, mode in [("GCM", AES.MODE_GCM), ("EAX", AES.MODE_EAX)]:
        try:
            enc = AES.new(key, mode)
            body, tag = enc.encrypt_and_digest(data)
            back = AES.new(key, mode, nonce=enc.nonce).decrypt_and_verify(body, tag)
            record("AES-256-%s round trip + tag" % name, back == data)
        except Exception as exc:
            record("AES-256-%s round trip + tag" % name, False, repr(exc))

    # RSA: keygen, PEM, signature
    try:
        rsa = RSA.generate(2048)
        again = RSA.import_key(rsa.export_key())
        sig = pkcs1_15.new(rsa).sign(SHA512.new(ballot))
        pkcs1_15.new(again.publickey()).verify(SHA512.new(ballot), sig)
        bad = False
        try:
            pkcs1_15.new(again.publickey()).verify(SHA512.new(b"tampered"), sig)
            bad = True
        except ValueError:
            pass
        record("RSA-2048 keygen, PEM, sign, verify", again.n == rsa.n and not bad)
    except Exception as exc:
        record("RSA-2048 keygen, PEM, sign, verify", False, repr(exc))

    # ECDSA on P-256
    try:
        ecc = ECC.generate(curve="P-256")
        sig = DSS.new(ecc, "fips-186-3").sign(SHA512.new(ballot))
        pub = ECC.import_key(ecc.public_key().export_key(format="PEM"))
        DSS.new(pub, "fips-186-3").verify(SHA512.new(ballot), sig)
        record("ECDSA P-256 keygen, PEM, sign, verify", True)
    except Exception as exc:
        record("ECDSA P-256 keygen, PEM, sign, verify", False, repr(exc))

    # Paillier, the Lab 7 core
    try:
        sys.path.insert(0, os.path.join(ROOT, "IS_Lab_Codebase", "Concepts"))
        import c14_homomorphic_encryption as c14
        pub, secret = c14.paillier_keygen(512)
        total = c14.paillier_add(c14.paillier_encrypt(15, pub),
                                 c14.paillier_encrypt(25, pub), pub)
        record("Paillier E(15)+E(25) decrypts to 40",
               c14.paillier_decrypt(total, pub, secret) == 40)
    except Exception as exc:
        record("Paillier E(15)+E(25) decrypts to 40", False, repr(exc))
    say()


# ---------------------------------------------------------------------------
# C  the wizards
# ---------------------------------------------------------------------------

PRESETS = ["evoting", "trade", "medical", "banking", "documents",
           "healthcare", "drm", "enterprise", "everything", "minimal"]

# Every keystroke the menu test feeds in, menu by menu. This has to stay in
# step with block_menu() in endsheet.py - if a menu gains an entry, the test
# notices, which is the point.
MENU_SCRIPT = (
    # MAIN -> client: submit one record, view my records, back
    "1\n"
    "1\nalice\nB001\n1\n101\n"
    "2\nalice\n"
    "3\n"
    # MAIN -> server: verify, search by tag, list all, tamper, verify again, back
    "2\n"
    "1\nB001\n"
    "2\n1\n101\n"
    "3\n"
    "4\nB001\n"
    "1\nB001\n"
    "5\n"
    # MAIN -> analyst: aggregate, reveal, one share alone, back
    "3\n"
    "1\n2\n3\n4\n"
    # MAIN -> auditor: hashes, audit log, access control policy, back
    "4\n"
    "1\n2\n3\n4\n"
    # MAIN -> exit
    "5\n"
)


def test_wizards(quick):
    say("=" * 78)
    say(" C. THE WIZARDS")
    say("=" * 78)
    run("wizard.py --check", ["wizard.py", "--check"], expect="ENVIRONMENT READY")
    run("endsheet.py --check (alias)", ["endsheet.py", "--check"],
        expect="ENVIRONMENT READY")
    run("playsheet.py --check (mid-sem alias)", ["playsheet.py", "--check"],
        expect="READY")
    run("wizard.py --presets", ["wizard.py", "--presets"], expect="evoting")
    run("wizard.py --options", ["wizard.py", "--options"], expect="cipher")
    say()

    say("=" * 78)
    say(" D. EVERY PRESET: BUILD, RUN THE DEMO, RUN THE CLEAN TWIN")
    say("=" * 78)
    for preset in PRESETS:
        run("build preset %-10s" % preset, ["wizard.py", "--build", preset],
            expect="written:")
        run("  answer.py demo       (%s)" % preset, ["answer.py", "demo"],
            expect="demonstration finished")
        run("  answer_clean.py demo (%s)" % preset, ["answer_clean.py", "demo"],
            expect="demonstration finished")
        run("  answer.py reset      (%s)" % preset, ["answer.py", "reset"])
    say()

    say("=" * 78)
    say(" E. THE MENU AND THE CLIENT/SERVER PATH (on the evoting build)")
    say("=" * 78)
    run("rebuild evoting", ["wizard.py", "--build", "evoting"], expect="written:")
    run("answer.py menu, every item driven", ["answer.py"], stdin_text=MENU_SCRIPT,
        expect="MAIN MENU")
    run("answer.py netdemo (real TCP)", ["answer.py", "netdemo"],
        expect="accepted", timeout=300)
    run("answer.py reset", ["answer.py", "reset"])
    test_split_files()
    say()


def test_split_files():
    """Start answer_server.py as its own process, then submit with
    answer_client.py - the two-terminal demonstration, done for real."""
    server = os.path.join(ROOT, "answer_server.py")
    client = os.path.join(ROOT, "answer_client.py")
    if not (os.path.exists(server) and os.path.exists(client)):
        record("separate client and server files written", False, "not found")
        return
    record("separate client and server files written", True)

    handle = subprocess.Popen([PY, server], cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, env=CHILD_ENV)
    try:
        time.sleep(4)
        ok = True
        for user, rid, value, tag in (("alice", "S001", "1", "101"),
                                      ("bob", "S002", "2", "102")):
            done = subprocess.run([PY, client, user, rid, value, tag], cwd=ROOT,
                                  capture_output=True, text=True, timeout=300,
                                  errors="replace", env=CHILD_ENV)
            text = (done.stdout or "") + (done.stderr or "")
            good = done.returncode == 0 and "'accepted': True" in text
            record("  client sends %s, server accepts it" % rid, good,
                   "" if good else text.strip().split("\n")[-1][:70])
            ok &= good
    finally:
        handle.terminate()
        try:
            output = handle.communicate(timeout=10)[0] or ""
        except subprocess.TimeoutExpired:
            handle.kill()
            output = ""
    served = output.count("received from")
    record("  the server process handled both", served >= 2,
           "handled %d" % served)
    for line in output.strip().split("\n")[:8]:
        if line.strip():
            lines.append("      | " + line[:140])
    run("answer.py reset after the split test", ["answer.py", "reset"])


# ---------------------------------------------------------------------------
# F  every per-lab file
# ---------------------------------------------------------------------------

LAB_FILES = [
    ("IS_Lab_Codebase/Concepts", "c14_homomorphic_encryption.py", "", None),
    ("IS_Lab_Codebase/Concepts", "c15_searchable_encryption.py", "", None),
    ("IS_Lab_Codebase/Concepts", "c16_threshold_secret_sharing.py", "", None),
    ("IS_Lab_Codebase/Concepts", "c17_text_and_data_utilities.py", "", None),
    ("IS_Lab_Codebase/Concepts", "ALL_CONCEPTS_TOOLKIT.py", "", "Toolkit loaded OK"),
    ("IS_Lab_Codebase/Lab7_Homomorphic_Encryption", "exercise_questions/q1.py", "", None),
    ("IS_Lab_Codebase/Lab7_Homomorphic_Encryption", "exercise_questions/q2.py", "", None),
    ("IS_Lab_Codebase/Lab7_Homomorphic_Encryption", "additional_questions/q1.py", "", None),
    ("IS_Lab_Codebase/Lab7_Homomorphic_Encryption", "additional_questions/q2.py", "", None),
    ("IS_Lab_Codebase/Lab7_Homomorphic_Encryption", "additional_questions/q3.py", "", None),
    ("IS_Lab_Codebase/Lab7_Homomorphic_Encryption", "additional_questions/q4.py", "", None),
    ("IS_Lab_Codebase/Lab7_Homomorphic_Encryption", "additional_questions/q5.py", "", None),
    ("IS_Lab_Codebase/Lab8_Searchable_Encryption", "exercise_questions/q1.py", "data\n\n", None),
    ("IS_Lab_Codebase/Lab8_Searchable_Encryption", "exercise_questions/q2.py", "python\n\n", None),
    ("IS_Lab_Codebase/Lab8_Searchable_Encryption", "additional_questions/q1.py", "", None),
    ("IS_Lab_Codebase/Lab8_Searchable_Encryption", "additional_questions/q2.py", "", None),
    ("IS_Lab_Codebase/Lab8_Searchable_Encryption", "additional_questions/q3.py", "", None),
]

DEMOS = [
    ("IS_Lab_Codebase/Lab7_Homomorphic_Encryption", "sample_questions/q1.py"),
    ("IS_Lab_Codebase/Lab8_Searchable_Encryption", "sample_questions/q1.py"),
    ("IS_Lab_Codebase/Endsem_Sample_Question_Answer", "evoting.py"),
]


def test_lab_files():
    say("=" * 78)
    say(" F. EVERY PER-LAB QUESTION FILE")
    say("=" * 78)
    for folder, script, stdin_text, expect in LAB_FILES:
        run("%s / %s" % (folder.split("/")[-1][:28], script), [script],
            cwd=os.path.join(ROOT, *folder.split("/")), stdin_text=stdin_text,
            expect=expect, timeout=600)
    for folder, script in DEMOS:
        where = os.path.join(ROOT, *folder.split("/"))
        run("%s / %s demo" % (folder.split("/")[-1][:24], script), [script, "demo"],
            cwd=where, expect="demonstration finished" if "evoting" in script
            else None, timeout=900)
        run("  reset", [script, "reset"], cwd=where)
    say()


def test_selftests():
    say("=" * 78)
    say(" G. THE TWO WIZARD SELF-TESTS (the slow ones)")
    say("=" * 78)
    # the wizard's own self-test exits non-zero if any configuration fails,
    # so the return code is the check - no brittle count to keep in step
    run("endsheet --selftest : every option, built and run",
        ["wizard.py", "--selftest"], expect="passed", timeout=7200)
    run("playsheet --selftest : the mid-sem checks",
        ["playsheet.py", "--selftest"], timeout=5400)
    say()


# ---------------------------------------------------------------------------
# tidy
# ---------------------------------------------------------------------------

JUNK = ["_st_keys", "keys", os.path.join("lab answers", "key_management.log")]
RUN_ARTIFACTS = ["records.json", "ballots.json", "index.json", "numbers.json",
                 "keys.json", "he_key.json", "pkse_key.json", "paillier_key.json",
                 "server_private.pem", "server_public.pem",
                 "ec_private.pem", "ec_public.pem", "audit.log"]


def tidy():
    print("=" * 78)
    print(" TIDYING  %s" % ROOT)
    print("=" * 78)
    print(" Nothing is deleted. Leftovers are MOVED into _to_delete so you can")
    print(" look before throwing them away.")
    print()

    if os.path.exists(os.path.join(ROOT, "answer.py")):
        print(" clearing the run files the answer created ...")
        subprocess.run([PY, "answer.py", "reset"], cwd=ROOT,
                       capture_output=True, text=True)

    for name in RUN_ARTIFACTS:
        path = os.path.join(ROOT, name)
        if os.path.exists(path):
            try:
                os.remove(path)
                print("   cleared  %s" % name)
            except OSError as exc:
                print("   left     %s  (%s)" % (name, exc))

    cache = os.path.join(ROOT, "__pycache__")
    if os.path.isdir(cache):
        shutil.rmtree(cache, ignore_errors=True)
        print("   cleared  __pycache__")

    target = os.path.join(ROOT, "_to_delete",
                          datetime.now().strftime("%Y-%m-%d_%H%M"))
    moved = []
    for name in JUNK:
        source = os.path.join(ROOT, name)
        if not os.path.exists(source):
            print("   already gone  %s" % name)
            continue
        os.makedirs(target, exist_ok=True)
        destination = os.path.join(target, os.path.basename(name))
        try:
            shutil.move(source, destination)
            moved.append(name)
            print("   moved    %s  ->  _to_delete/" % name)
        except Exception as exc:
            print("   COULD NOT MOVE %s : %s" % (name, exc))

    print()
    if moved:
        print(" %d item(s) are now in:" % len(moved))
        print("   %s" % target)
        print(" Look inside, then delete that folder in File Explorer.")
    else:
        print(" nothing left to move - the folder is already tidy")
    print()
    print(" kept: wizard.py, endsheet.py, playsheet.py, islab.py, checkup.py,")
    print("       pylib/, Wizards/, IS_Lab_Codebase/, Manuals/,")
    print("       'Sample questions'/, 'lab answers'/, .venv/, .git/, the .md files")
    print()
    print(" Still yours to decide: .idea/ is PyCharm's project settings.")


# ---------------------------------------------------------------------------

def main():
    argument = (sys.argv[1] if len(sys.argv) > 1 else "").lower()
    if argument == "tidy":
        tidy()
        return
    quick = argument == "quick"

    started = time.time()
    say("#" * 78)
    say("# IS LAB CHECKUP      %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    say("#" * 78)
    say()

    if test_environment():
        test_vectors()
        test_wizards(quick)
        test_lab_files()
        if not quick:
            test_selftests()
        else:
            say("  (quick mode: the two wizard self-tests were skipped)")
            say()

    failed = [r for r in results if not r[1]]
    say("=" * 78)
    say(" SUMMARY")
    say("=" * 78)
    say("  checks run : %d" % len(results))
    say("  passed     : %d" % (len(results) - len(failed)))
    say("  failed     : %d" % len(failed))
    say("  time taken : %.0f seconds" % (time.time() - started))
    if failed:
        say()
        say("  WHAT FAILED")
        for label, _ok, detail in failed:
            say("    %-48s %s" % (label, detail))
    say()
    say("  EVERYTHING PASSED" if not failed else "  SOME CHECKS FAILED - see above")

    with open(REPORT, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    print()
    print("full report written to: %s" % REPORT)


if __name__ == "__main__":
    main()
