# Security review: password strength estimate and password report, November 2026

Reviewed state: commit `a0532b8` (0.7.1 plus the benchmark), 2026-11-27.
Scope: the open decision in `PLAN.md` section 14 on how a report over all
entries gets the passwords to the strength estimator, and the estimator
itself as it is already used in 0.7.0 and 0.7.1 (zxcvbn-c 2.7 in
`third_party/zxcvbn`, `src/passwordstrength.cpp`, the two dialogs).

Rule for the decision: no option may weaken a protection the app has
today. An option that needs a new safeguard to keep that level is only
acceptable together with the safeguard.

Method:

- The data flows were read in the code: `core/src/ffi`, `Field::value`,
  `src/corebridge.h`, `src/passwordstrength.cpp`, the dialogs.
- An independent reviewer, who did not know the options or any earlier
  assessment, read `zxcvbn.c` and `zxcvbn.h` for memory safety, undefined
  behaviour, stack and heap use, residue, global state and run time, and
  confirmed its points with test programs.
- The estimator was fuzzed with libFuzzer under AddressSanitizer and
  UndefinedBehaviorSanitizer, called as the app calls it.
- What a call leaves in memory was measured on the host and on the Jolla
  Phone, with positive controls.
- Run time was measured on the Jolla Phone.
- Two safeguards were built as prototypes and measured.

Result: one finding concerns the code of 0.7.0 and 0.7.1 and has to be
fixed before either is released (F1). For the report, option 3 in a
stricter form is the best way, on five conditions (C1 to C5). Without
them every option, option 3 included, would weaken the app.

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 2 |
| Informational | 2 |

## What must stay true

These are the protections the options are measured against. They are the
ones the threat model and `CLAUDE.md` state today.

| | Protection |
|---|---|
| P1 | Decrypted data is zeroized when the database locks; what the user never showed, copied or edited leaves no trace outside zeroized memory |
| P2 | A field value leaves the core only when the user shows, copies or edits it |
| P3 | Untrusted input (a database, an import) is handled with bounds and cannot cause undefined behaviour; `unsafe` is limited to the C API |
| P4 | A crafted database cannot hang or crash the app beyond the stated resource limits, and cannot delay a lock |
| P5 | Few, pinned dependencies with permissive licenses; reproducible builds |

Core and bridge run in one process. The boundary between them does not
stop an attacker who can read the process memory; such an attacker is
out of scope while the database is unlocked. What the boundary limits is
how many copies exist, where they are, and whether they are gone after a
lock. That is what the options differ in.

## Findings

### F1 (Medium, in 0.7.0 and 0.7.1): the estimate can block the UI for seconds

`SpatialMatch` in zxcvbn-c takes time with the fifth power of the length
for keys that are neighbours on the number pad and change direction at
every step. The length is capped at 100 characters, the estimator's own
limit.

| Password on the Jolla Phone | 40 chars | 64 | 80 | 100 and more |
|---|---|---|---|---|
| `12` repeated | 23 ms | 216 ms | 668 ms | 2097 ms |
| `1232` repeated | 13 ms | 109 ms | 322 ms | 982 ms |
| `+-` repeated | 9 ms | 86 ms | 267 ms | 838 ms |
| `a` repeated | 1 ms | 2 ms | 3 ms | 5 ms |

Typical passwords take 0.05 ms. The benchmark of 2026-11-27 (1000
passwords in 50 ms) did not contain this pattern, so its conclusion in
`PLAN.md`, "a report needs no worker thread", was wrong.

Effect today: both dialogs rate the password on the UI thread at every
change. Typing or pasting such a password freezes the dialog for up to
two seconds per character. An entry with such a password, which can
arrive with a shared database or an import, freezes the entry dialog
when it is opened for editing. The auto-lock check runs on the same
thread and is delayed for as long. No data is exposed or lost.

Fix: rate off the UI thread, the newest text wins, and the dialog shows
the result when it arrives. This is condition C3 below and is needed for
0.7.x whatever is decided about the report.

Lowering the estimator's limit (`ZXCVBN_DETAIL_LEN`) from 100 to 64
would cut the worst case to 216 ms, but 502 of 504 sample passwords
longer than 64 characters then get other bits than in KeePassXC (the
quality level stayed the same in all 504). It is not recommended: the
values would no longer match KeePassXC.

### F2 (Medium, for a report; informational for 0.7.x): the estimator leaves password fragments in memory

The estimator wipes nothing. Measured on the Jolla Phone: after rating
`Xk9#mQ2$vL7!pR4zWq8&nB3`, the 7 bytes `Wq8&nB3` were still on the dead
stack; four other passwords left no fragment of 5 bytes or more. On the
host none did. So it depends on the compiler and the input.

By reading: the stack frames keep single characters, which letter each
leet symbol stood for, the digits of a date and the possible next
characters of a dictionary prefix. Freed heap blocks keep position,
length and entropy of each matched part; for a dictionary word the
entropy is the logarithm of its rank, so the word can be narrowed to a
few candidates. No complete copy of the password stays anywhere; the
reversed copy the estimator makes is overwritten before it is freed.

In the two dialogs this adds nothing: the password is a Qt string there,
which cannot be wiped either (a known limit in the threat model). In a
report it would matter: fragments of passwords the user never opened
would stay in memory after a lock. That breaks P1, with every option.

Fix, built and measured as a prototype (conditions C1 and C2):

- The estimator runs on a stack of its own, which is overwritten when the
  work is done. It used 7.5 KB of it at most.
- zxcvbn-c is compiled with `-Dmalloc=... -Dfree=...`, so its blocks go
  through a wrapper that overwrites each block when it is freed. The
  vendored files stay unchanged. Peak use was 240 KB in up to 45000
  blocks for a 1024 byte password; nothing stayed allocated.

With both, the measurement found no fragment on the caller's stack, on
the private stack after the wipe, or on the heap.

### F3 (Low): no allocation result is checked

`malloc` returning null leads to a null pointer dereference in three
places (confirmed by injecting failures). The blocks are small, so this
needs real memory exhaustion, and the result is a crash, not memory
corruption. The Rust core also aborts when memory runs out. The wrapper
of C2 can end the process cleanly at that point instead.

### F4 (Low): the dictionary tables are trusted without a check

`PossChars` has 49 bytes and the largest entry of the generated
dictionary needs exactly 49. The code has no bound of its own; it relies
on the generator. An exhaustive walk of all 468110 trie nodes found
every table index in range for the vendored dictionary. A regenerated
dictionary needs that walk again (condition C5).

### F5 (Informational): memory safety of zxcvbn-c

No out-of-bounds access, use after free, double free, leak or undefined
behaviour was found:

- by reading, with the bound `Begin + Length <= min(length, 100)`
  followed through every matcher;
- by the exhaustive table walk of F4;
- by 160000 random and structured inputs under AddressSanitizer,
  UndefinedBehaviorSanitizer and LeakSanitizer, with signed and unsigned
  `char` and a German locale;
- by the libFuzzer run of this review: four workers for ten minutes,
  1.64 million inputs of up to 1024 bytes under AddressSanitizer and
  UndefinedBehaviorSanitizer, without a report and without a negative or
  undefined result. Coverage stopped growing after the first minutes.

Recursion is at most 23 levels deep, there are no variable-length
arrays, and the largest stack use measured was 7.5 KB. With the
dictionary compiled in there is no mutable global or static data, so
calls from several threads are safe (eight threads under ThreadSanitizer
without a report).

Not covered: a build for armv7hl, where struct sizes differ, and
single-byte locales, where bytes from 0x80 on could count as letters and
change a rating.

### F6 (Informational): a report feeds every password to C code

Today the estimator sees the passwords the user types or opens for
editing. A report hands it every password of the database, also those
that came with a shared database, a merge or an import, at one tap. That
is a wider exposure of 1800 lines of C to untrusted bytes, the same one
KeePassXC has. After F5 no defect is known; an unknown one would be
memory corruption in a process that holds the decrypted database. This
is the residual risk of having a report at all, with every option. C4
and C5 keep it small.

## The options

Option 0 is added as the baseline: no report.

| | 0. No report | 1. Copy into the bridge | 2. Estimator in the core | 3. Core lends each password |
|---|---|---|---|---|
| P1 residue after lock | none | estimator residue, plus one bridge copy per password that C++ code has to wipe | estimator residue | estimator residue |
| P1 with C1 and C2 | - | kept, if every copy is wiped | kept | kept |
| P2 values leaving the core | none | every password, as a copy | none | none as a copy; a pointer for the length of one call |
| P3 untrusted bytes in C | as today | every password | every password | every password |
| P3 `unsafe` in the core | as today | as today | a call into C inside the core | a call through a function pointer in the C API |
| P4 run time and lock | as today | needs C3 | needs C3 | needs C3 |
| P5 dependencies | none | none | cargo has to compile C: a build dependency whose build script runs at build time, or a hand-written build script; not tried in the SDK | none |
| Can go wrong later | - | a change that turns the copy into a Qt string; Qt's implicit sharing | the build | code that keeps the pointer |

### Option 1: copy every password into the bridge

Each password is copied twice on its way (the C API string and the
bridge's buffer). Both can be wiped, and the bridge has `secureWipe` for
it, but the threat model already names the weakness: Qt's implicit
sharing can leave copies that are freed without zeroing, and one later
change that passes the value on as `QString` makes every password of the
database unwipeable. It also gives up P2 by design. With the same
safeguards it reaches at best what options 2 and 3 have without the
copies. Rejected.

### Option 2: move the estimator into the core

No C++ code sees a password, and all estimates would go through one
place. In memory it leaves exactly what option 3 leaves: the estimator is
the same C code with the same stack and heap, whoever calls it. The price
is in P5 and P3: the core stops being pure Rust, cargo has to compile C
for the target inside the SDK (untested, and the SDK's cargo 1.75 has
already rejected dependencies once), and the core gets a call into C
outside its C API. A private stack needs a thread or `mmap`, which the
core may not use (its only system call is `getrandom`), so the bridge
would have to provide it anyway. It adds risk without removing any that
option 3 leaves. Not recommended.

### Option 3: the core lends each password to the estimator

The core walks the entries and calls a function it was given, once per
password, with a pointer to its own zeroized buffer. As proposed before,
that function was to be "a callback of the bridge", which would let C++
code read every password. The review tightens this:

- The function pointer the core receives points directly at a small C
  function next to the estimator, which only calls `ZxcvbnMatch`. No C++
  or Qt code is on the path. The password is read by the core and by the
  estimator, exactly as in option 2.
- The core cuts the password to 256 characters at a character boundary
  and appends the terminating zero, in a zeroized buffer, before it lends
  it. So the bound on what the C code gets is enforced in Rust (P3).
- The estimator must not call back into the core, keep the pointer or
  throw. It is plain C, so it cannot throw, and it takes no handle.
- Reuse is found inside the core by comparing the zeroized values; no
  hashes and no copies.
- What comes back is the entry id, the bits and whether the password is
  used elsewhere. The bridge keeps this in memory only and drops it on
  lock.

Host tests give the core a stand-in estimator, so `cargo test` covers the
walk, the cut, the exclusions and the reuse; the real estimator stays
covered by `tools/check-password-strength.sh` against KeePassXC.

## Assessment

Options 2 and 3 are equal in what an attacker can find in memory, during
and after a report. Option 3 in the form above reaches that without a new
dependency, without C inside the core and without a build that is not
tried yet. Option 1 is weaker than both. Option 0 adds nothing, but it
also leaves weak and reused passwords unnoticed, which is the larger
risk for most users.

Recommended: option 3 as tightened above, with all of these conditions.
Each one closes a gap that would otherwise weaken a protection.

| | Condition | Protects |
|---|---|---|
| C1 | The whole report call runs on a thread of the bridge whose stack the bridge allocated and overwrites when the thread has ended | P1 |
| C2 | zxcvbn-c is built with the wiping allocation wrapper | P1 |
| C3 | No estimate on the UI thread: the dialogs rate on a worker and show the newest result; the report is cancelled between two entries, and a lock cancels it and waits for at most one estimate | P4 |
| C4 | The core, not the caller, bounds what the estimator gets: at most 256 characters, no zero byte inside, zero-terminated, in zeroized memory | P3 |
| C5 | The fuzz target and the table walk become tools in `tools/`, and both run whenever the vendored estimator or its dictionary changes | P3 |

C1 also covers the Rust frames of the walk, since they run on the same
stack. C3 leaves one limit: a lock can be delayed by the one estimate
that is running, 2.1 seconds at worst for a crafted entry. Whoever can
plant such an entry can already change the database.

To verify on the device before a report is released: the residue
measurement of F2 with C1 and C2 in the real build (as a tool, like the
benchmarks), and the time a lock takes while a report runs over crafted
entries.

## What stays as a known limit

- An unknown memory error in zxcvbn-c would be reachable by a crafted
  password (F6). Audit and fuzzing found none.
- In the dialogs the password is a Qt string, as before.
- CPU registers and caches are not wiped.
- The estimator rates English words only.

## Follow-up

| | Action | When |
|---|---|---|
| F1 | Rate off the UI thread (C3 for the dialogs) | done in 0.7.2 (`a81e93d`), verified on the device |
| F2 | C1 and C2 | C2 done in 0.7.2 (`fa36683`); C1 with the report |
| F3 | End cleanly on a failed allocation, in the wrapper of C2 | done in 0.7.2 (`fa36683`) |
| F4, F5 | C5 | before the report |
| - | Correct the benchmark's conclusion in `PLAN.md` | done |
| - | Add the report, its safeguards and F6 to the threat model | with the report |
