# Cleaning the folder base

## The short version

```
python checkup.py tidy
```

That clears the run files and moves the leftovers into a dated `_to_delete`
folder. It never deletes anything, so you can look inside before throwing it
away in File Explorer. The rest of this file is what it does and why.

`python checkup.py` on its own runs a full test of everything in the folder
and writes `checkup_report.txt`.

---

Checked against the folder on 2026-10-22, after the launcher was added.

Three of the files that were on this list have been **replaced in place**
rather than left for you to delete:

| file | was | is now |
| --- | --- | --- |
| `playsheet.py` | a 177 KB duplicate of the mid-sem wizard | a 25-line alias that forwards to `Wizards\Midsem_Wizard\playsheet.py`, so `python playsheet.py` still works |
| `EXAM_PLAN.md` | a 29 KB duplicate of the mid-sem plan | a short pointer to the two current plans |
| `endsheet.py` | did not exist, which is why `python endsheet.py` failed | a 20-line alias, so that command works from the IS Lab folder |

So the delete list is down to four things.

## What `checkup.py tidy` moves for you

| path | what it is |
| --- | --- |
| `_st_keys\` | a self-test scratch folder that was never cleaned up |
| `keys\` | `keystore.json` left behind by an old key-management demo |
| `lab answers\key_management.log` | an audit log a demo wrote into your answers folder |
| `.idea\` | PyCharm project settings — only if you don't open this folder in PyCharm |

`checkup.py tidy` moves the first three into `_to_delete`; delete that folder
when you have looked at it. `.idea` is left alone because it is your editor's
own configuration - remove it by hand if you do not use PyCharm.

`answer.py` and `answer_clean.py` at the top level are stale output from an
old run, but they are harmless: the next `python wizard.py` overwrites both.
No need to touch them.

## Comes back whenever a program runs — clear any time

Every answer file writes its working data into the folder you run it from,
and each one has a `reset` command that clears it:

```
records.json   ballots.json   index.json   numbers.json
keys.json      he_key.json    pkse_key.json   paillier_key.json
securedocs.json  securedocs_index.json  securedocs_keys.json
securepoll.json  poll_key.json
server_private.pem   server_public.pem
ec_private.pem       ec_public.pem
audit.log      securedocs.log
pgp_keys\      sealed.json
```

`python answer.py reset` is the tidy way. Same for `evoting.py reset` and the
two scenario files in `Lab7_*` and `Lab8_*`.

## Keep

* `wizard.py` — the launcher. `python wizard.py` is the whole workflow.
* `checkup.py` — `python checkup.py` tests the whole folder, `tidy` cleans it.
* `endsheet.py`, `playsheet.py` — aliases of it, kept because they are the
  names on the wizards themselves.
* `islab.py` and `pylib/` — the pure-Python crypto fallback, needed on a
  machine whose Application Control policy blocks pycryptodome's compiled
  modules. Harmless on a machine where they load. See `pylib/README.md`.
* `START_HERE.md`, `ENDSEM_EXAM_PLAN.md`, `EXAM_PLAN.md`, this file.
* `Wizards\` and `IS_Lab_Codebase\` — everything in both.
* `Manuals\`, `Sample questions\`, `lab answers\` — your source material.
* `.venv\` — the virtual environment. Deleting it means reinstalling
  pycryptodome.
* `.git\` — if you are versioning the folder.

## What a tidy folder looks like

```
IS Lab\
├── wizard.py          python wizard.py        <- the one command
├── endsheet.py        python endsheet.py      <- same, end-sem (Labs 1-8)
├── playsheet.py       python playsheet.py     <- same, mid-sem (Labs 1-6)
├── islab.py           python islab.py         <- which crypto backend is live
├── checkup.py         python checkup.py       <- test everything / tidy
├── pylib/             the pure-Python crypto fallback
├── START_HERE.md
├── ENDSEM_EXAM_PLAN.md
├── EXAM_PLAN.md
├── CLEANUP.md
├── Wizards\
├── IS_Lab_Codebase\
├── Manuals\
├── Sample questions\
├── lab answers\
└── .venv\
```

Anything else at the top level is output from a run.
