#ifndef PATH_LOGGER_H
#define PATH_LOGGER_H

#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "uthash.h"
#include "json_parse.h"


/* ---------- log buffers ---------- */
#define MAX_PER_ARG 1000
typedef struct {
    size_t count;
    union { float f[MAX_PER_ARG]; uint32_t u32[MAX_PER_ARG]; } data;
} ArgValueLogs;
typedef ArgValueLogs RetValueLogs;

/* ---------- uthash entry ---------- */
typedef struct Entry {
    uint64_t      *key;            /* trace sequence */
    size_t         len;
    ArgValueLogs   args[MAX_ARGS]; /* inputs */
    RetValueLogs   rets[MAX_ARGS]; /* outputs */
    UT_hash_handle hh;
} Entry;

Entry *g_map = NULL;

/* ---------- helpers ---------- */
size_t kaddrbytes(size_t n);  // convert number of addresses to bytes
size_t kaddrbytes(size_t n) { return n * sizeof(uint64_t); }

Entry *trace_find(const uint64_t *seq, size_t len);
Entry *trace_find(const uint64_t *seq, size_t len)
{
    Entry *e = NULL;
    HASH_FIND(hh, g_map, seq, kaddrbytes(len), e);
    return e;
}

Entry *trace_create(const uint64_t *seq, size_t len);
Entry *trace_create(const uint64_t *seq, size_t len)
{
    // Entry *e = calloc(1, sizeof *e);
    Entry *e = (Entry *)calloc(1, sizeof *e);
    if (!e) { perror("calloc"); exit(1); }
    // e->key = malloc(kaddrbytes(len));
    e->key = (uint64_t *)malloc(kaddrbytes(len));
    if (!e->key) { perror("malloc key"); exit(1); }
    memcpy(e->key, seq, kaddrbytes(len));
    e->len = len;
    HASH_ADD_KEYPTR(hh, g_map, e->key, kaddrbytes(len), e);
    return e;
}

/* ---------- API: record + query ---------- */
void record_trace_values(const uint64_t *seq, size_t len,
                         const ValueUnion *arg_vals,
                         const ValueUnion *ret_vals);
// Record values for a trace sequence
void record_trace_values(const uint64_t *seq, size_t len,
                                const ValueUnion *arg_vals,
                                const ValueUnion *ret_vals)
{
    Entry *e = trace_find(seq, len);
    if (!e) e = trace_create(seq, len);

    for (size_t i = 0; i < arg_count; ++i) {
        ArgValueLogs *L = &e->args[i];
        if (L->count >= MAX_PER_ARG) continue;
        if (arg_settings[i].vtype == TYPE_FLOAT)
            L->data.f[L->count++] = arg_vals[i].f;
        else
            L->data.u32[L->count++] = arg_vals[i].u32;
    }
    for (size_t i = 0; i < ret_count; ++i) {
        RetValueLogs *L = &e->rets[i];
        if (L->count >= MAX_PER_ARG) continue;
        if (ret_settings[i].vtype == TYPE_FLOAT)
            L->data.f[L->count++] = ret_vals[i].f;
        else
            L->data.u32[L->count++] = ret_vals[i].u32;
    }
}

/* ---------- NEW: expose a readonly handle ---------- */
const Entry *get_trace_series(const uint64_t *seq, size_t len);
// Get a read-only handle to the trace series
const Entry *get_trace_series(const uint64_t *seq, size_t len)
{
    return trace_find(seq, len);
}

/* ---------- demo helpers ---------- */
void dump_all_path_logs(void);
void dump_all_path_logs(void)
{
    Entry *e, *tmp;
    HASH_ITER(hh, g_map, e, tmp) {
        printf("Trace len=%zu:", e->len);
        for (size_t i = 0; i < e->len; ++i)
            printf(" 0x%016" PRIx64, e->key[i]);
        putchar('\n');

        for (size_t i = 0; i < arg_count; ++i) {
            printf("  IN  %-4s N=%zu\n", arg_settings[i].name, e->args[i].count);
            for (size_t j = 0; j < e->args[i].count; ++j) {
                if (arg_settings[i].vtype == TYPE_FLOAT)
                    printf("       %g\n", e->args[i].data.f[j]);
                else
                    printf("       %u\n", e->args[i].data.u32[j]);
            }
        }

        for (size_t i = 0; i < ret_count; ++i) {
            printf("  OUT %-4s N=%zu\n", ret_settings[i].name, e->rets[i].count);
            for (size_t j = 0; j < e->rets[i].count; ++j) {
                if (ret_settings[i].vtype == TYPE_FLOAT)
                    printf("       %g\n", e->rets[i].data.f[j]);
                else
                    printf("       %u\n", e->rets[i].data.u32[j]);
            }
        }
    }
}
void clear_all_path_logs(void);
void clear_all_path_logs(void)
{
    Entry *e, *tmp;
    HASH_ITER(hh, g_map, e, tmp) { HASH_DEL(g_map, e); free(e->key); free(e); }
}

/* ---------- current path ---------- */
#define MAX_PATH_LENGTH 1024
uint64_t current_path[MAX_PATH_LENGTH];
size_t current_path_len = 0;
ValueUnion logged_in_values[MAX_ARGS], logged_out_values[MAX_ARGS];
bool is_logging_valid = true;


#endif // PATH_LOGGER_H