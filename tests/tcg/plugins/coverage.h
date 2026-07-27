#ifndef COVERAGE_H
#define COVERAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <math.h>    // INFINITY, NAN
#include <float.h>   // FLT_MAX, FLT_EPSILON
#include "rand_util.h"   // get_random_word

// ---------------------------------------------------------------
// coverage-guided special-value fuzzing (DESIGN.md Phase 1)
// ---------------------------------------------------------------
// Uniform sampling of a float arg over [lo, hi] can never reach the inputs that trip
// isnan/isinf input-validation guards (compared against FLT_MAX) or threshold-at-extreme
// branches (e.g. dt < FLT_EPSILON). With a small probability we instead seed a
// boundary/special value from the table below, so those branches -- and the paths
// behind them -- actually get exercised. This is what turns the coverage *measurement*
// (edge.txt / coverage.json) into new *paths*.
//
// A special value that trips a guard sends the run down that branch, i.e. a DIFFERENT
// path, so it feeds that path's dataset rather than polluting the normal one. A special
// value in a non-branch-gating arg (e.g. a gain) can still push NaN/Inf into its own
// path's output; downstream recovery drops non-finite output rows to stay clean
// (DESIGN.md Phase 3).

// Master switch for special-value injection (function-level / e2e only). Default on.
bool coverage_special_fuzz = true;

// ~1 in COVERAGE_SPECIAL_ODDS float samples becomes a special value.
#define COVERAGE_SPECIAL_ODDS 12

// static const float coverage_special_floats[] = {
//     0.0f, FLT_EPSILON, -FLT_EPSILON, 1.0f, -1.0f,
//     FLT_MAX, -FLT_MAX, INFINITY, -INFINITY, NAN,
// };

static const float coverage_special_floats[] = {
    0.0f, FLT_EPSILON, -FLT_EPSILON, 1.0f, -1.0f, NAN,
};

// With ~1/COVERAGE_SPECIAL_ODDS probability, set *out to a random special value and
// return true; otherwise return false and the caller keeps its uniform [lo,hi] sample.
bool coverage_pick_special_float(float *out);
bool coverage_pick_special_float(float *out) {
    if (!coverage_special_fuzz) return false;
    if (get_random_word() % COVERAGE_SPECIAL_ODDS != 0) return false;
    const int n = (int)(sizeof(coverage_special_floats) / sizeof(coverage_special_floats[0]));
    *out = coverage_special_floats[get_random_word() % n];
    return true;
}

#endif // COVERAGE_H
