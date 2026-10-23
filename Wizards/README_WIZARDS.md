# Wizards

Two answer writers live here. Both do the same job: you describe the exam
question, they write a complete runnable Python answer. They cover different
syllabuses, so pick by which exam you are sitting.

The quickest way to reach either of them is the launcher one folder up:

```
cd "C:\Users\kavyk\OneDrive\Desktop\Projects\IS Lab"
python wizard.py --check            # end-sem wizard
python wizard.py --midsem --check   # mid-sem wizard
```

`wizard.py` resolves these paths itself, so you never have to be standing in
the right subfolder. Everything below also works if you call the files
directly.

```
Wizards/
├── README_WIZARDS.md          <- this file
├── Midsem_Wizard/
│   ├── playsheet.py           Labs 1-6   (mid-sem syllabus)
│   ├── MIDSEM_EXAM_PLAN.md    the full mid-sem strategy and trimming guide
│   └── INSTRUCTIONS.md        how to drive playsheet.py
├── MANUAL_COVERAGE.md         all three manuals audited against the options
└── Endsem_Wizard/
    ├── endsheet.py            Labs 1-8   (end-sem syllabus)
    ├── READING_THE_QUESTION.md  how to decode a question into settings,
    │                            with the sample paper as the worked example
    └── INSTRUCTIONS.md        setup from nothing, then the five exam steps
```

**On a machine that has never run this folder**, start at
`Endsem_Wizard/INSTRUCTIONS.md` **Step 0** — Python, the venv, the one
library (`pycryptodome`), and `python checkup.py` to prove it all works.

## Which one

| The question mentions | Use |
| --- | --- |
| classical ciphers, DES/AES, RSA/ECC/ElGamal, hashing, signatures, key management, access control | either; `playsheet.py` is the smaller output |
| homomorphic encryption, Paillier, encrypted totals or tallies | `endsheet.py` |
| searchable encryption, an encrypted index, "search without revealing" | `endsheet.py` |
| threshold decryption, "no single authority" | `endsheet.py` |
| a trusted timestamp or a submission deadline | `endsheet.py` |
| a five-component marking table (Client-Server / ED / DSS / Hash / Search) | `endsheet.py` |

For the end-sem exam the answer is almost always `endsheet.py`. `playsheet.py`
is kept because it is tested, it is smaller, and for a question that is purely
Labs 1-6 a smaller answer is easier to explain.

## Both of them, in three commands

```
cd "C:\Users\kavyk\OneDrive\Desktop\Projects\IS Lab"
python -m venv .venv
.venv\Scripts\activate            # Windows   (source .venv/bin/activate elsewhere)
pip install pycryptodome
```

```
python wizard.py --check         # is the environment ready
python wizard.py                 # answer the questions
python answer.py demo            # full run, no typing
python answer.py                 # the interactive menu  <- this is marked
```

Each wizard writes **two** files:

* `answer.py` — with the teaching comments. Read this one, it is how you
  explain the code in the viva.
* `answer_clean.py` — the same program with the comments stripped and the
  section banners kept. Show this one as the output listing.

Both files are parsed before they are written, so a file that exists runs.

## If a wizard is not what the question wants

1. Build the closest preset anyway (`python wizard.py --build evoting`,
   `--presets` to list).
2. Edit the `SETTINGS` block at the top of `answer.py`. Nothing below it needs
   to change for a different cipher size, role set, deadline or threshold.
3. For something the wizard does not cover at all, paste the function out of
   `../IS_Lab_Codebase/Concepts/ALL_CONCEPTS_TOOLKIT.py` — every concept in
   Labs 1-8 is in there as a standalone function.

That three-step fallback is the point of keeping the codebase and the wizard
in the same folder: the wizard handles the shape of the paper, the codebase
handles anything else the examiner asks for.
