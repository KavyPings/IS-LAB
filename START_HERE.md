# IS Lab — start here

Everything for ICT 3141 Information Security Lab, **Lab 1 to Lab 8**.
If you read one file, read this one.

---

## 1. The folder

```
IS Lab/
├── START_HERE.md                 <- you are here
├── wizard.py                     the one command you need: python wizard.py
├── endsheet.py                   same thing under the wizard's own name
├── playsheet.py                  the mid-sem wizard (Labs 1-6)
├── islab.py                      one-line crypto fallback loader
├── checkup.py                    tests the whole folder, and tidies it
├── pylib/                        the fallback itself - see pylib/README.md
├── ENDSEM_EXAM_PLAN.md           the end-sem plan, phase by phase
├── CLEANUP.md                    files left over from earlier work, safe to delete
│
├── Wizards/                      THE ANSWER WRITERS
│   ├── README_WIZARDS.md         which wizard, and why
│   ├── Endsem_Wizard/            endsheet.py  + INSTRUCTIONS.md   (Lab 1-8)
│   └── Midsem_Wizard/            playsheet.py + INSTRUCTIONS.md   (Lab 1-6)
│                                 and MIDSEM_EXAM_PLAN.md
│
├── IS_Lab_Codebase/              THE CODEBASE
│   ├── KEY_FILE_concepts_and_index.txt    which code for which question
│   ├── PYTHON_BASICS_CHEATSHEET.txt       the small one-liners
│   ├── Concepts/                 c01..c17, one file per concept,
│   │                             + ALL_CONCEPTS_TOOLKIT.py (all of them in one)
│   ├── Lab1_Classical_Ciphers/   ┐
│   ├── Lab2_Symmetric_DES_AES/   │  each lab folder has
│   ├── Lab3_Asymmetric_.../      │    sample_questions/
│   ├── Lab4_Advanced_.../        │    exercise_questions/
│   ├── Lab5_Hashing/             │    additional_questions/
│   ├── Lab6_Digital_Signature/   │    LabN_explanation.txt
│   ├── Lab7_Homomorphic_Encryption/   ┘
│   ├── Lab8_Searchable_Encryption/
│   ├── Sample_Question_Answer/            the MID-SEM sample paper answered
│   └── Endsem_Sample_Question_Answer/     the END-SEM sample paper answered
│
├── Manuals/                      the lab manuals, 1-4, 5-6, 7-8
├── Sample questions/             the sample papers
└── lab answers/                  your own hand-written answers
```

---

## 2. Setup — do this once, before the exam

**Everything below is run from inside this folder.** That is the one mistake
worth avoiding — `python wizard.py` from anywhere else gives
`No such file or directory`. So start with the `cd`:

```
cd "C:\Users\kavyk\OneDrive\Desktop\Projects\IS Lab"
python -m venv .venv
.venv\Scripts\activate                  # Windows
source .venv/bin/activate               # macOS / Linux
pip install pycryptodome
python wizard.py --check
```

The last line must print **ENVIRONMENT READY**. `pycryptodome` is the only
library anything here needs. Nothing needs the network.

`wizard.py` is just a launcher — it finds the real wizards inside `Wizards/`
and passes your flags straight through, so the path can never be wrong.
`endsheet.py` at this level is the same launcher under the wizard's own name,
so all three of these are identical and you can type whichever you remember:

```
python wizard.py --check
python endsheet.py --check
python Wizards\Endsem_Wizard\endsheet.py --check
```

If you give the launcher a full path from somewhere else, it still works and
tells you which folder it is writing into:

```
python "C:\Users\kavyk\OneDrive\Desktop\Projects\IS Lab\wizard.py" --check
```

Then prove the whole thing works while there is no time pressure:

```
python wizard.py --build evoting
python answer.py demo
python answer.py                        # click through every menu item once
python answer.py reset
```

Or test the whole folder in one go — environment, crypto backend,
known-answer vectors, both wizards, all six presets, the menus, the TCP path,
every per-lab question file and both wizard self-tests:

```
python checkup.py              # the lot, writes checkup_report.txt
python checkup.py quick        # same minus the two slow self-tests
```

It ends with a pass/fail summary, so one command tells you whether this
machine is ready.

### If pycryptodome will not load at all

On a machine with an Application Control policy (WDAC or Smart App Control)
the install succeeds but the import dies:

```
OSError: Cannot load native module 'Crypto.Hash._SHA1': ... error 0x11c7
```

Nothing can be installed to fix that — Windows is refusing an unsigned
binary, not missing a package. `pylib/` contains pure-Python replacements for
the parts that are compiled, and `python wizard.py` loads them by itself; an
answer built on such a machine gets one `import islab` line at the top and
runs normally. `python islab.py` says which backend is in use.
`pylib/README.md` has the detail, including the one `setx PYTHONPATH` command
that makes the per-lab question files run from their own folders.

---

## 3. In the exam — the three routes

### Route A — the wizard (default, fastest)

The question is a scenario with a marking table. Read it, note which
primitives it names, then:

```
python wizard.py
python answer.py demo
python answer.py
```

`python wizard.py` with no arguments means "write me an answer" — it is the
same as `python wizard.py --wizard`.

Press Enter through the questions you do not need to change. It writes
`answer.py` (with comments, for the viva) and `answer_clean.py` (comments
stripped, for the output listing). Full detail in
`Wizards/Endsem_Wizard/INSTRUCTIONS.md`.

### Route B — adapt a worked answer

The question is clearly the shape of a sample paper:

* end-sem shaped → `IS_Lab_Codebase/Endsem_Sample_Question_Answer/evoting.py`
* mid-sem shaped → `IS_Lab_Codebase/Sample_Question_Answer/edusecure.py`

Copy it, change the `SETTINGS` block at the top, swap the one function the
question wants different. Each has an explanation file beside it.

### Route C — build it from the concepts

The question is nothing like the papers — a single algorithm, an attack, a
comparison, a manual exercise reworded.

1. Open `IS_Lab_Codebase/KEY_FILE_concepts_and_index.txt` and use the
   60-second decision table: it maps the words in the question to a concept
   file and a worked lab question.
2. Copy `IS_Lab_Codebase/Concepts/ALL_CONCEPTS_TOOLKIT.py` next to your answer
   and `from ALL_CONCEPTS_TOOLKIT import *`. Every concept in Labs 1-8 is in
   there as a standalone function.
3. The matching `LabN/*/qN.py` file is a full worked answer with the output
   the manual asks for.

Routes B and C are what make the codebase worth having: the wizard handles the
shape of the paper, the codebase handles anything else.

---

## 4. What is new for the end-sem

| | Lab 7 | Lab 8 |
| --- | --- | --- |
| topic | partial homomorphic encryption | searchable encryption |
| the idea | compute on data you cannot read | find a record you cannot read |
| schemes | Paillier (adds), ElGamal and raw RSA (multiply) | SSE (one shared key), PKSE (public key) |
| the trick | multiply ciphertexts, and the plaintexts add | the index key must be deterministic, the values randomised |
| also in scope | threshold decryption (Shamir t-of-n) | tag / time-range / prefix search, leakage |
| code | `Concepts/c14`, `c16`, `Lab7_*/` | `Concepts/c15`, `Lab8_*/` |

The end-sem sample paper combines them with everything from Labs 1-6:
AES-256-CBC, RSA key wrapping, SHA-512, ElGamal signatures, a Paillier tally,
a searchable index, threshold decryption, timestamps, roles, and a TCP client
and server — all in one menu-driven program. That program is
`Endsem_Sample_Question_Answer/evoting.py`, and `python wizard.py --build evoting`
regenerates an equivalent one.

---

## 5. The two sentences that matter most

**The program must be menu driven.** The end-sem paper says that if it is not,
the total marks are halved. Get the menu running before anything clever.

**Run `demo` before the examiner arrives.** Every answer here takes a `demo`
argument that runs the whole flow with no typing. It is the fastest way to
find out that something is broken, and the fastest way to show every mark on
the rubric.

---

Next: `ENDSEM_EXAM_PLAN.md`.
