# Coverage-based Fuzzing

Status: **implemented** — Phase 0 & 1 complete, Phase 2 complete *with deviations*,
Phase 3 partial, Phase 4 not started. The proposal below is kept verbatim as the
rationale; the section immediately following records where the shipped code differs.

## Implementation status (2026-07)

### Phase 0 — coverage measurement (online in plugin): **DONE**

- Static `edge.txt`: `binja_scripts/bn_utils.py::get_func_edges` +
  `pre_analysis_single_func_non_struct.py` (writes `edge.txt` beside `bb.txt`).
- Plugin: `parse_edge_file`, `bb_index_of`, `dump_edge_coverage` live in **`virtual.h`**
  (not a separate file); the `bb_hit` / `edge_exec` / `edge_rec` bitmaps are in
  `virtual.h`; the special-value table + injector are in `coverage.h`.
- `logbbstart` marks `bb_hit`/`edge_exec` **before** the watchdog return
  (`virtual.c:~993`); `have_last_bb` is reset in `randargs` (`virtual.c:179`); the
  recorded set `edge_rec` is marked from `current_path[]` for committed samples only
  (`virtual.c:~214`).
- `coverage.json` emits `blocks_hit/blocks_total/edges_executed/edges_recorded/
  uncovered_edges`; `run_data_collection.sh` passes `,edge=${ws_dir}/edge.txt`.
- Both coverage sets are tracked as designed, **but** the Phase-2 loop currently keys
  only on the executed side (`uncovered_edges`). The executed-vs-recorded gap is
  emitted but not yet used to gate widening (a planned refinement).
- Widening is driven by **edge** coverage only. That is sufficient (full edge coverage
  implies full block coverage: entry is always hit, every other block has an incoming
  edge) and strictly stronger than block-driven; block coverage is measured but not a
  separate gate. A branchless (0-edge) function trivially reports "full" at round 1.

### Phase 1 — special-value injection: **DONE, table trimmed**

- `randargs` injects a special value ~1/`COVERAGE_SPECIAL_ODDS` (12) of the time via
  `coverage_pick_special_float` (`coverage.h`), gated by `coverage_special_fuzz`.
- **Deviation:** the table is `{0, ±FLT_EPSILON, ±1, NaN}` — `±FLT_MAX`, `±Inf`, and
  `lo/hi` were **removed** from the proposal's set. Rationale: extreme finite values
  (`±FLT_MAX`) propagate through *computed* thresholds and yield **fake coverage** — an
  edge counted as hit via a garbage magnitude rather than a genuine input regime — which
  then feeds ill-conditioned samples into recovery.
- **Consequence:** the `abs(x) > FLT_MAX` / `isinf` magnitude-guard edges the proposal
  planned to close with `±Inf` are no longer reachable (NaN still trips the
  unordered-compare guards, but not the magnitude ones). `update_all` reaches **14/16**
  edges, not the proposal's 16/16 target (§Validation).

### Phase 2 — expansion loop: **DONE** (Python-driven `phase2_coverage_fuzz.py`), deviations + additions

Deviations from the pseudocode:
- **No patience counter.** Widen geometrically (×4) to a hard `CAP_SCALE` (`1<<24`);
  exit early only on *full* edge coverage. Coverage plateaus for several rounds then
  jumps once a product-of-fields threshold unlocks, so patience quits before the unlock.
- **Keep the WIDEST samples, not the narrowest.** The proposal (Phase 2/3) said keep the
  clean narrow-range data. The code does the opposite: for a path seen in several rounds
  it keeps the widest-range samples (better-conditioned for SR), guarded by the per-path
  log size (replace only when the new round filled the 100-sample log). This is a
  deliberate reversal — see the open tension noted under Phase 3.
- Ranges reach the collector as a **positional arg** (6th arg of
  `run_data_collection.sh`), not env vars; the loop stays a Python process-per-round
  (the in-plugin online variant remains just a note).

Additions beyond the proposal (all in `phase2_coverage_fuzz.py`):
- **Cross-round path accumulation** into a content-addressed store keyed by
  `sha1(bb_seq)` — the block sequence is the stable path identity, since `path_id_N` is
  unstable discovery order — merged back with deterministic numbering and
  `path_provenance.json` (per path: first-seen vs sampled run, 3-axis ranges, observed
  trigger ranges, concrete witness).
- **Calling-interface union** across rounds (`merge_interface` / `arg_identity`) so a
  field discovered only in some rounds isn't lost when the last round's
  `calling_interface_input.json` overwrites the file.
- **Consistency guard** (`check_path_interface_consistency`) that aborts if a path log's
  argN naming diverges from the merged interface — fires on loop-over-buffer functions
  whose field-discovery order is run-dependent.

### Phase 3 — per-path focused recovery: **PARTIAL**

- DONE: `pysr_script/run_pysr.py` drops non-finite / out-of-range rows (`ABS_LIMIT=1e18`)
  so polluted wide-range samples don't raise the loss.
- NOT DONE: focused per-path re-collection in the narrowest well-conditioned range,
  minimum valid-sample enforcement, and AFL-style mutation around the concrete trigger
  inputs. **Open tension:** Phase 2's "keep widest" choice conflicts with this phase's
  "recover from clean narrow data" intent; not yet reconciled.

### Phase 4 — static assist: **NOT started**

Uncovered-branch back-slicing / directed seeding is unimplemented. Loop termination
relies on the magnitude cap, not Phase-4 feasibility analysis.

### Known gap — loop functions

Buffer-loop functions (RunningAverage `get*InBuffer` / `*Last`) explode into hundreds of
per-iteration paths. Edge coverage stays bounded (as the design predicts), but the
per-path multistage recovery cannot process that many paths in reasonable time — not
addressed.

---

*(original proposal follows)*

## Problem

Function-level (e2e) recovery only discovers the paths that the random argument
seeding happens to execute. `randargs` samples each input uniformly from the
`value_range` in `rand_setting.json`, and the default float range is all-positive
and modest (`[0.1, 5.0]` / `[0.5, 5.0]`). Any branch gated on a value that range
never produces is silently never explored — the path simply does not appear in the
collected data, and the semantics on it are never recovered.

This is not hypothetical. It is exactly what hid `AC_PID_Basic::update_all`'s
derivative term until the `function_ends` fix, and even *after* that fix the
function is still only partially covered.

### Ground truth: `AC_PID_Basic::update_all` @ `0x8154e78`

After the `function_ends` fix (physical end, so the out-of-line filter/D blocks are
instrumented), the two recovered paths give:

```
blocks: 10 / 11 covered      uncovered: 0x8154f3a
edges:  10 / 16 covered
```

The six uncovered edges split into **two distinct classes**, and the gating
constants are what make the design decision:

| Uncovered edge(s) | Gate | Constant | Reachable by widening the range? |
| --- | --- | --- | --- |
| `0x8154f52 -> 0x8154ede` (filter, skip-D) | `_dt < eps` | **1.19e-7** (`FLT_EPSILON`) | **yes** — needs `_dt ~ 0` / negative |
| `0x8154e78/e90/ea4/eb6 -> 0x8154f3a`, `f3a -> f4c` | `abs(s0), abs(s1) > K` or `NaN` | **3.4028e38** (`FLT_MAX`) | **no** — needs `NaN` / `+-Inf` |

The second class is the important one. The comparison is against `FLT_MAX`, so **no
finite input can ever take that branch**. Those four edges are an `isnan`/`isinf`
input-validation guard; they are reachable *only* by injecting `NaN` or `+-Inf`.
Widening a finite range — by any factor, forever — will never cover them.

Conclusion: coverage-guided **range expansion is necessary but not sufficient**.
It must be paired with **special-value injection**.

## Design

### Phase 0 — Coverage measurement, **online in the plugin**

Coverage is tracked **during** the fuzzing run, in `logbbstart`, not post-processed
out of `bb_seqs.txt`. The edge is trivially available: it is just
`(last_bb, current_bb)`.

Note this does **not** replace path recording. The two are complementary:

- `current_path[]` / `bb_seqs.txt` -> the **distinct paths**, which remain the unit of
  formula recovery (one PySR fit per path).
- BB/edge bitmaps -> the **fuzzing feedback signal** that drives the loop below.

#### Why online, not post-processed

Deriving edges from `bb_seqs.txt` after the fact is strictly worse, for three
reasons that are properties of the existing code, not hypotheticals:

1. **Path recording is bounded; edge coverage is not.** `logbbstart` appends to a
   fixed `current_path[]` and bails out via `trigger_inf_exe_watchdog` once
   `current_path_len >= WATCHDOG_PATH_THRESHOLD`. A loopy function (every
   RunningAverage buffer function) can exhaust that budget, and every block after the
   bail-out never reaches `bb_seqs.txt`. Edge coverage is bounded by `|E|`: a loop
   that runs 10,000 times adds *zero* new edges after the second iteration while
   adding 10,000 entries to `current_path[]`. Marking a bitmap is O(1) per block and
   is immune to the watchdog that truncates path recording.
2. **Invalidated runs are erased.** `clear_all_path_logs()` wipes `current_path` when
   a sample is invalidated (`is_logging_valid = false`). Any edge exercised *only* by
   runs that were later invalidated is invisible in `bb_seqs.txt`, even though
   execution genuinely reached it. Post-processing therefore systematically
   **undercounts** coverage.
3. **The adaptive loop needs the signal in-flight.** Any in-plugin online variant of
   Phase 2 (widen range / inject special values across iterations *within* one QEMU
   session, avoiding a process spawn per round) is impossible if coverage only exists
   after the process exits.

#### Sketch

`logbbstart`'s `udata` is already `&bb_starts[j]`, so the block index is free — no
lookup:

```c
static int  last_bb_idx;              /* reset at function entry */
static bool have_last_bb;
static uint8_t bb_hit[MAX_BBS];
static uint8_t edge_hit[MAX_BBS][MAX_BBS];   /* |B| is small; a dense bitmap is fine */

static void logbbstart(unsigned int cpu_index, void *udata) {
    uint64_t pc  = *(uint64_t *)udata;
    int      idx = (uint64_t *)udata - bb_starts;    /* O(1), free */

    /* ---- coverage: O(1), loop-safe, and recorded even if this sample is
       later invalidated. MUST be before the watchdog early-return below,
       so a truncated path still contributes its coverage. ---- */
    bb_hit[idx] = 1;
    if (have_last_bb) edge_hit[last_bb_idx][idx] = 1;
    last_bb_idx = idx;
    have_last_bb = true;

    /* ---- existing path recording (bounded) ---- */
    if (current_path_len >= WATCHDOG_PATH_THRESHOLD) {
        trigger_inf_exe_watchdog("basic-block budget exceeded (runaway loop)", false);
        return;
    }
    current_path[current_path_len++] = pc;
}
```

Two correctness requirements:

- **Reset `have_last_bb = false` at function entry** — i.e. in `randargs`, which fires
  at `func_start` on every run *including the invalidation retry*. Without this, the
  PC-reset-to-`func_start` restart would fabricate a spurious edge
  `(last_bb_of_aborted_run -> func_start)` that does not exist in the CFG.
- **Mark coverage before the watchdog `return`**, as above, or a runaway loop silently
  drops the coverage of the very blocks it was executing.

#### Two coverage sets, and why the gap is useful

Track both:

- `edges_executed` — marked in `logbbstart`, unconditionally (includes runs that are
  later invalidated).
- `edges_recorded` — only for committed/valid samples (mark from `current_path[]` at
  `record_trace_values` time).

The **gap between them is diagnostic**, and it is what stops the Phase 2 loop from
widening forever:

- edge in neither -> genuinely never reached -> *widening / special values may help*.
- edge in `executed` but not in `recorded` -> the fuzzer **already reaches it**, but the
  sample is always thrown away (invalidation, re-typing, watchdog). Widening the range
  will **not** help; the fix is in the seeding/invalidation logic. Without this
  distinction the loop would keep expanding the range chasing an edge it is already
  hitting.

#### Output

Dump both bitmaps at run end (e.g. `coverage.json`: `bb_hit`, `edges_executed`,
`edges_recorded`) alongside the existing per-path dirs. The Python-driven Phase 2 loop
reads that file; an in-plugin online loop uses the bitmaps directly in memory. Compare
against the static CFG (blocks already in `bb.txt`; edge list from Binary Ninja) to get
`uncovered_edges`.

Prerequisite: this is only meaningful once `function_ends.txt` carries the function's
**physical end** rather than its return address. `logbbstart` registration is gated by
the same `[func_start, largest_func_end]` check in `vcpu_tb_trans` as the memory
callbacks, so out-of-line blocks past the epilogue would otherwise never fire the
callback and would report as "uncovered" when they in fact executed untracked.

(A pure post-processing pass over `bb_seqs.txt` remains usable as a zero-plugin-change
stopgap for a quick offline prototype, but it is subject to the undercounting in (1)
and (2) above and cannot drive an online loop.)

#### Wiring: the static edge set (`edge.txt`) into the plugin

The plugin can mark *which* edges it hit on its own (`edge_hit`), but it cannot compute
a coverage *fraction*, decide when the loop is "done", or flag an unexpected edge
without the static **denominator** — the full CFG edge set. That set is `edge.txt`,
produced by the static analysis; the plugin reads it exactly as it already reads
`bb.txt`.

**Static side (already implemented).**

- `binja_scripts/bn_utils.py :: get_func_edges(func)` — sorted, deduped
  `(src_bb_start, dst_bb_start)` pairs from each block's `outgoing_edges`.
- `binja_scripts/pre_analysis_single_func_non_struct.py` — computes `func_edges`, puts
  it in `func_result["edges"]`, and `dump_fastdyn_config` writes `edge.txt` next to
  `bb.txt`, one `"<src>, <dst>"` (hex) per line.

**Plugin side (to change).**

1. **`Morpheus/fastdyn_script/run_data_collection.sh`** (the e2e collector) — add one
   line to the `--plugin` arg string, right after `basicblocks=${ws_dir}/bb.txt`
   (currently line 32):

   ```
   ,edge=${ws_dir}/edge.txt\
   ```

   Scope note: only the e2e collector needs this. `logbbstart` (and thus edge
   tracking) is registered under `if (!is_sub_semantics_mode)` in `vcpu_tb_trans`
   (`virtual.c:2005`), so `run_data_collection_sub_semantic.sh` does **not** need the
   edge arg — edge coverage is a function-level concept.

2. **`qemu/tests/tcg/plugins/virtual.h`** — new globals + parser, mirroring
   `bb_starts[]` / `bb_count` / `parse_basic_block_file` (`virtual.h:282-315`):

   ```c
   #define MAX_EDGES 4096
   unsigned long cfg_edge_src[MAX_EDGES];   /* resolved to bb-index at parse time */
   unsigned long cfg_edge_dst[MAX_EDGES];
   int edge_count = 0;
   void parse_edge_file(const char *filename);   /* format: "<src_hex>, <dst_hex>\n" */
   ```

   `parse_edge_file` is a near-copy of `parse_basic_block_file`: `fgets` each line,
   `strtoull(line, &end, 0)` for the source, skip the `", "`, `strtoull` for the
   destination. Resolve each address to its `bb_starts[]` index (small linear scan;
   `bb_count` is tiny) and store the index pair. Storing indices — not raw addresses —
   is what lets `logbbstart` mark coverage with an O(1) array write.

3. **`qemu/tests/tcg/plugins/virtual.c :: qemu_plugin_install`** — parse it right after
   the basic-block file (currently `virtual.c:2216-2217`), and it **must come after**
   `parse_basic_block_file` so `bb_starts[]` is populated for the address→index
   resolution in step 2:

   ```c
   filename = get_arg("edge", argc, argv);
   parse_edge_file(filename);
   ```

4. **`qemu/tests/tcg/plugins/virtual.c :: logbbstart`** (`virtual.c:1009`) — the
   online marking from Phase 0's sketch: `bb_hit[idx]=1;` and, when `have_last_bb`,
   `edge_hit[last_bb_idx][idx]=1;` — placed **before** the `WATCHDOG_PATH_THRESHOLD`
   early-return so a truncated loop still contributes coverage. `idx` is free:
   `(uint64_t*)udata - bb_starts`.

5. **`qemu/tests/tcg/plugins/virtual.c :: randargs`** (`virtual.c:219`) — reset
   `have_last_bb = false` at function entry (randargs fires at `func_start` on every
   run, including the invalidation retry), so the PC-reset restart cannot fabricate a
   spurious `(last_bb_of_aborted_run -> func_start)` edge.

6. **`qemu/tests/tcg/plugins/virtual.c`, commit point** (`record_trace_values`,
   `virtual.c:255`) — mark the *recorded* edge set from `current_path[]` only for
   committed/valid samples, giving the `edges_executed` vs `edges_recorded` split.

7. **New `dump_edge_coverage()`**, called at run end alongside the per-path dump —
   iterate `cfg_edge_src/dst[0..edge_count)`, read `edge_hit[src][dst]`, and write
   `coverage.json` (`bb_hit`, `edges_executed`, `edges_recorded`, and the derived
   `uncovered` list = static edges with no exec hit). `edge.txt` is what makes the
   denominator and the uncovered list possible. Also flag any runtime edge **not** in
   the static set (unresolved indirect branch Binary Ninja missed, or a bug like a
   missing `have_last_bb` reset).

Summary of changes: **1 shell line** (`run_data_collection.sh`), **1 new parser +
globals** (`virtual.h`), and **4 touch points in `virtual.c`** (`qemu_plugin_install`
wiring, `logbbstart` marking, `randargs` reset, `record_trace_values` recorded-set +
the new `dump_edge_coverage`). No change to the static side — `edge.txt` already exists.

### Phase 1 — Seed corpus = range samples + special values

The per-input corpus is **not** just uniform over `[lo, hi]`. On every round, also
draw from a fixed special-value table:

```
{ 0, +-FLT_EPSILON, +-1, +-FLT_MAX, +-Inf, NaN, lo, hi }
```

This single addition is what actually trips:

- threshold-at-zero guards (`_dt < FLT_EPSILON`) — uniform sampling of a wide range
  hits `abs(x) < 1e-7` with vanishing probability, even when the range *contains* it;
- `FLT_MAX` / `isnan` / `isinf` input-validation guards — unreachable by any finite
  range.

Both patterns are extremely common in real firmware input validation, so this is not
a corner case.

Plugin-side, the minimal change is in `randargs`: with probability `p`, emit a value
from the special table instead of sampling uniformly from `value_range`.

### Phase 2 — Coverage-guided expansion loop

```
range    = [-0.5, 5.0]        # start signed and modest
patience = P                  # e.g. 2-3
paths    = {}                 # accumulate across ALL rounds

loop:
    collect(range, inject_special_values=True)
    cov = coverage()                       # Phase 0 (edges_executed / edges_recorded)
    paths |= discovered_paths()
    if cov.edges_executed gained anything new:
        patience = P
        range = widen(range)               # geometric, k ~ 2-4
    else:
        patience -= 1
        if patience == 0: break
    if magnitude(range) > MAG_CAP: break   # ~1e6; beyond that only Inf matters,
                                           # and that is already injected
```

The widening decision is driven by **`edges_executed`**, not `edges_recorded`. An edge
that is executed but never recorded is already being reached — widening the range
cannot help it, and treating it as "still uncovered" would make the loop expand
forever. Such edges are reported separately as an invalidation/seeding problem
(see Phase 0).

Three details that matter:

- **Patience, not first-miss.** Stop after `P` consecutive dry rounds, not the first
  one. A single widening step can step *over* a branch that a further step catches.
- **Accumulate the union of paths across rounds.** Do not keep only the widest
  round's data — a path that was cleanly exercised at a narrow range may become
  polluted (NaN/Inf) at a wide one.
- **Hard magnitude cap.** Without it, the loop will keep doubling forever chasing
  branches (like the `FLT_MAX` guards) that widening can never reach.

### Phase 3 — Per-path focused recovery

**Coverage != recoverability.** Covering an edge is necessary but not sufficient for
PySR to recover a formula on it. Two failure modes:

1. A newly-discovered rare path may have too few samples for PySR.
2. Wide ranges *pollute already-clean paths*: negatives make `sqrt(x)` NaN,
   near-zero divisors make results Inf. These either trip the plugin's sample
   invalidation (`is_logging_valid = false`) — reducing valid sample count — or, worse,
   survive as ill-conditioned samples that raise the recovered loss.

So **decouple discovery from recovery**:

- *Discovery*: wide range + special values, optimize for coverage.
- *Recovery*: for each discovered path, re-collect focused data in the narrowest
  range that reaches it **and** keeps its arithmetic well-conditioned; require a
  minimum valid-sample count per path.
- To reach a rare path reliably, record the concrete inputs that first hit the new
  edge and mutate around them (AFL-style corpus), rather than hoping uniform
  sampling re-hits it.

### Phase 4 — Static assist (optional, high leverage)

When coverage plateaus, back-slice each uncovered branch condition (Binary Ninja
MLIL-SSA) to the input(s) that gate it and the constant it is compared against. This
converts blind widening into **directed seeding**:

- `_dt < 1.19e-7` -> force `_dt` below `FLT_EPSILON`.
- `abs(s0) > 3.4e38` -> recognize an `isnan`/`isinf` guard -> inject `NaN` / `Inf` for `s0`.

This reaches precisely the branches widening never will, and it lets guard paths be
**labelled** ("input validation guard") instead of being handed to PySR to fit a
formula to a constant-returning error handler.

## Trade-offs and risks

- **Cost.** Each round is a full QEMU process spawn. If that dominates, move the
  adaptation *online* into the plugin — it already loops N fuzz iterations per run,
  so it can widen the range / inject special values across iterations within a single
  session. More invasive, much faster. Recommend prototyping the Python-driven loop
  first (it only edits `value_range` + a special-value flag in the arg setting and
  re-runs data collection), then pushing it into the plugin if warranted.
- **Invalidation pressure.** Wider ranges produce more NaN/Inf, which drives more
  `is_logging_valid = false` discards. Iteration counts must rise to keep per-path
  valid-sample counts up.
- **Semantic value differs by path class.** The skip-D path is a genuine runtime path
  worth recovering. The NaN-guard path just calls a handler and returns a constant —
  it is worth *detecting and labelling*, not worth fitting a formula to.
- **Coverage ceiling.** Some edges are infeasible under the seeding model (fields the
  plugin cannot independently set, dead code). Accept coverage < 100%; the patience
  counter and magnitude cap are what make the loop terminate rather than chase them.
- **Semantically nonsensical inputs are fine for coverage.** A negative `_dt` or a
  negative buffer count is not physically meaningful, but it is a legitimate way to
  reach a branch. Just do not let those samples pollute the *recovery* data of the
  normal path (see Phase 3).

## Validation target

`AC_PID_Basic::update_all` @ `0x8154e78` is a good first proof:

- Start `[-0.5, 5.0]`, inject `{0, FLT_EPSILON, +Inf, NaN}`.
- `_dt ~ 0` / negative should close `0x8154f52 -> 0x8154ede` (the filter-E-only,
  D-skipped path).
- `NaN` / `Inf` on `s0` / `s1` should close the four guard edges plus `f3a -> f4c`.
- Expected result: **10/16 -> 16/16 edges, 11/11 blocks.**

If that holds, generalize; the coverage numbers make the win measurable rather than
anecdotal.

> **Actual (2026-07):** `update_all` reaches **14/16** edges — not 16/16. The two
> still-uncovered edges are the `abs(x) > FLT_MAX` magnitude guards, which the proposal
> planned to close with `±Inf`; those were removed from the special-value table
> (§Phase 1 above), so they are no longer reachable. NaN (still in the table) closes the
> unordered-compare guard edges. Fine-grained recovery on the covered paths: 68 stage
> outputs EXACT, returned value EXACT on all 3 paths.

## Prior art / framing

This is a **coverage-guided fuzzing** layer on top of the symbolic-regression data
collection. The closest analogue is AFL-style corpus expansion, but keyed on
*range and special-value schedules* rather than byte-level mutation, because the
inputs here are typed scalars / struct fields rather than an opaque byte buffer.
