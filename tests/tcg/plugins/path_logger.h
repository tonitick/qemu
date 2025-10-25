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

/* ---------- current path ---------- */
#define MAX_PATH_LENGTH 1024
uint64_t current_path[MAX_PATH_LENGTH];
size_t current_path_len = 0;
ValueUnion logged_in_values[MAX_ARGS], logged_out_values[MAX_ARGS]; // a single input-output record
bool is_logging_valid = true;

/* ---------- log buffers ---------- */
#define MAX_PER_PATH_LOG_SIZE 100
typedef struct {
    size_t count;
    // union { float f[MAX_PER_PATH_LOG_SIZE]; uint32_t u32[MAX_PER_PATH_LOG_SIZE]; double d[MAX_PER_PATH_LOG_SIZE]; } data;
    ValueUnion data[MAX_PER_PATH_LOG_SIZE];
} ArgValueLogs;
typedef ArgValueLogs RetValueLogs;

/* ---------- uthash entry ---------- */
typedef struct Entry {
    uint64_t      *key; // trace sequence, as key buffer
    size_t         len; // length of the trace sequence, #basic_blocks_visited * sizeof(uint64_t)
    ArgValueLogs   args[MAX_ARGS]; /* inputs */
    RetValueLogs   rets[MAX_ARGS]; /* outputs */
    UT_hash_handle hh;
} Entry;

Entry *g_map = NULL;

/* ---------- helpers ---------- */
size_t kaddrbytes(size_t n);  // convert number of addresses to bytes
size_t kaddrbytes(size_t n) { return n * sizeof(uint64_t); }

Entry *trace_find(const uint64_t *seq, size_t len); // key: uint64_t *key (seq) + size_t len
Entry *trace_find(const uint64_t *seq, size_t len)
{
    Entry *e = NULL;
    HASH_FIND(hh, g_map, seq, kaddrbytes(len), e);
    return e;
}

Entry *trace_create(const uint64_t *seq, size_t len);
Entry *trace_create(const uint64_t *seq, size_t len)
{
    Entry *e = (Entry *)calloc(1, sizeof *e);
    if (!e) { perror("calloc"); exit(1); }
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
        if (L->count >= MAX_PER_PATH_LOG_SIZE) continue;
        if (arg_settings[i].vtype == TYPE_FLOAT)
            L->data[L->count++].f = arg_vals[i].f;
        else if (arg_settings[i].vtype == TYPE_DOUBLE)
            L->data[L->count++].d = arg_vals[i].d;
        else if (arg_settings[i].vtype == TYPE_UINT32)
            L->data[L->count++].u32 = arg_vals[i].u32;
        else if (arg_settings[i].vtype == TYPE_UINT16)
            L->data[L->count++].u32 = arg_vals[i].u32;
        else if (arg_settings[i].vtype == TYPE_UINT8)
            L->data[L->count++].u32 = arg_vals[i].u32;
        else {
            fprintf(stderr, "Unsupported arg type in record_trace_values for arg '%s'\n", arg_settings[i].name);
            exit(EXIT_FAILURE);
        }
    }
    for (size_t i = 0; i < ret_count; ++i) {
        RetValueLogs *L = &e->rets[i];
        if (L->count >= MAX_PER_PATH_LOG_SIZE) continue;
        if (ret_settings[i].vtype == TYPE_FLOAT)
            L->data[L->count++].f = ret_vals[i].f;
        else if (ret_settings[i].vtype == TYPE_DOUBLE)
            L->data[L->count++].d = ret_vals[i].d;
        else if (ret_settings[i].vtype == TYPE_UINT32)
            L->data[L->count++].u32 = ret_vals[i].u32;
        else {
            fprintf(stderr, "Unsupported ret type in record_trace_values for ret '%s'\n", ret_settings[i].name);
            exit(EXIT_FAILURE);
        }
    }
}

// ===============================================================================================================================
// Utilities
// ===============================================================================================================================
void clear_all_path_logs(void);
void clear_all_path_logs(void)
{
    Entry *e, *tmp;
    HASH_ITER(hh, g_map, e, tmp) { HASH_DEL(g_map, e); free(e->key); free(e); }
}

/* ---------- Get a read-only handle to the trace series ---------- */
const Entry *get_trace_series(const uint64_t *seq, size_t len);
const Entry *get_trace_series(const uint64_t *seq, size_t len)
{
    return trace_find(seq, len);
}

/* ---------- Dump in-out pairs ---------- */
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
                if (arg_settings[i].vtype == TYPE_FLOAT) {
                    printf("       %g\n", e->args[i].data[j].f);
                } else if (arg_settings[i].vtype == TYPE_DOUBLE) {
                    printf("       %g\n", e->args[i].data[j].d);
                } else {
                    printf("       %u\n", e->args[i].data[j].u32);
                }
            }
        }

        for (size_t i = 0; i < ret_count; ++i) {
            printf("  OUT %-4s N=%zu\n", ret_settings[i].name, e->rets[i].count);
            for (size_t j = 0; j < e->rets[i].count; ++j) {
                if (ret_settings[i].vtype == TYPE_FLOAT) {
                    printf("       %g\n", e->rets[i].data[j].f);
                } else if (ret_settings[i].vtype == TYPE_DOUBLE) {
                    printf("       %g\n", e->rets[i].data[j].d);
                } else {
                    printf("       %u\n", e->rets[i].data[j].u32);
                }
            }
        }
    }
}

// #define MAX_PER_PATH_LOG_SIZE 100
int check_path_log_size_and_dump(char* dump_dir); // TODO: dump all path logs
int check_path_log_size_and_dump(char* dump_dir) { // TODO: dump all path logs
    // if all path log size reach MAX_PER_PATH_LOG_SIZE, dump the related path logs
    Entry *e, *tmp;

    // FILE *f = fopen(dump_path, "w");
    // if (!f) {
    //     perror("fopen dump_path");
    //     exit(1);
    // }

    int num_path_log_ready = 0;
    int total_paths = 0;
    HASH_ITER(hh, g_map, e, tmp) {
        total_paths++;
        // bool need_dump = false;
        for (size_t i = 0; i < arg_count; ++i) {
            if (e->args[i].count >= MAX_PER_PATH_LOG_SIZE) {
                // need_dump = true;
                num_path_log_ready++;
                break;
            }
        }
    }
    if (num_path_log_ready && (num_path_log_ready == total_paths)) {
        // dump all path logs
        int path_id = 0;
        HASH_ITER(hh, g_map, e, tmp) {
            char filepath[256];
            snprintf(filepath, sizeof(filepath), "%s/path_id_%d_len_%zu.txt", dump_dir, path_id++, e->len);
            FILE *f = fopen(filepath, "w");
            if (!f) {
                perror("fopen");
                continue;
            }

            // dump the entry
            printf("Dumping path log for trace len=%zu:", e->len);
            for (size_t i = 0; i < e->len; ++i)
                printf(" 0x%08" PRIx64, e->key[i]);
            putchar('\n');

            for (size_t i = 0; i < arg_count; ++i) {
                if (arg_settings[i].vtype == TYPE_FLOAT) {
                    printf("  IN (FLOAT)  %-4s N=%zu\n", arg_settings[i].name, e->args[i].count);
                    fprintf(f, "[IN] %s: ", arg_settings[i].name);
                    for (size_t j = 0; j < e->args[i].count; ++j) {
                        printf("       %g\n", e->args[i].data[j].f);
                        fprintf(f, "%.10f ", e->args[i].data[j].f);
                    }
                    fprintf(f, "\n");
                }
                else if (arg_settings[i].vtype == TYPE_DOUBLE) {
                    printf("  IN (DOUBLE)  %-4s N=%zu\n", arg_settings[i].name, e->args[i].count);
                    fprintf(f, "[IN] %s: ", arg_settings[i].name);
                    for (size_t j = 0; j < e->args[i].count; ++j) {
                        printf("       %g\n", e->args[i].data[j].d);
                        fprintf(f, "%.10g ", e->args[i].data[j].d);
                    }
                    fprintf(f, "\n");
                }
            }

            for (size_t i = 0; i < ret_count; ++i) {
                if (ret_settings[i].vtype == TYPE_FLOAT) {
                    printf("  OUT %-4s N=%zu\n", ret_settings[i].name, e->rets[i].count);
                    fprintf(f, "[OUT] %s: ", ret_settings[i].name);
                    for (size_t j = 0; j < e->rets[i].count; ++j) {
                        printf("       %g\n", e->rets[i].data[j].f);
                        fprintf(f, "%.10f ", e->rets[i].data[j].f);
                    }
                    fprintf(f, "\n");
                }
                else if (ret_settings[i].vtype == TYPE_DOUBLE) {
                    printf("  OUT %-4s N=%zu\n", ret_settings[i].name, e->rets[i].count);
                    fprintf(f, "[OUT] %s: ", ret_settings[i].name);
                    for (size_t j = 0; j < e->rets[i].count; ++j) {
                        printf("       %g\n", e->rets[i].data[j].d);
                        fprintf(f, "%.10g ", e->rets[i].data[j].d);
                    }
                    fprintf(f, "\n");
                }
            }
        }
        return 1; // success
    }

    return 0; // not enough path logs
}

void dump_existing_path_logs(char* dump_dir);
void dump_existing_path_logs(char* dump_dir) {
    // dump all existing path logs with size > MAX_PER_PATH_LOG_SIZE / 2
    Entry *e, *tmp;
    int path_id = 0;
    HASH_ITER(hh, g_map, e, tmp) {
        bool need_dump = false;
        for (size_t i = 0; i < arg_count; ++i) {
            if (e->args[i].count >= MAX_PER_PATH_LOG_SIZE / 2) {
                need_dump = true;
                break;
            }
        }
        if (need_dump) {
            char filepath[256];
            snprintf(filepath, sizeof(filepath), "%s/path_id_%d_len_%zu.txt", dump_dir, path_id++, e->len);
            FILE *f = fopen(filepath, "w");
            if (!f) {
                perror("fopen");
                continue;
            }

            // dump the entry
            printf("Dumping path log for trace len=%zu:", e->len);
            for (size_t i = 0; i < e->len; ++i)
                printf(" 0x%08" PRIx64, e->key[i]);
            putchar('\n');

            for (size_t i = 0; i < arg_count; ++i) {
                if (arg_settings[i].vtype == TYPE_FLOAT) {
                    printf("  IN  %-4s N=%zu\n", arg_settings[i].name, e->args[i].count);
                    fprintf(f, "[IN] %s: ", arg_settings[i].name);
                    for (size_t j = 0; j < e->args[i].count; ++j) {
                        printf("       %g\n", e->args[i].data[j].f);
                        fprintf(f, "%.10f ", e->args[i].data[j].f);
                    }
                    fprintf(f, "\n");
                }
                else if (arg_settings[i].vtype == TYPE_DOUBLE) {
                    printf("  IN  %-4s N=%zu\n", arg_settings[i].name, e->args[i].count);
                    fprintf(f, "[IN] %s: ", arg_settings[i].name);
                    for (size_t j = 0; j < e->args[i].count; ++j) {
                        printf("       %g\n", e->args[i].data[j].d);
                        fprintf(f, "%.10g ", e->args[i].data[j].d);
                    }
                    fprintf(f, "\n");
                }
            }

            for (size_t i = 0; i < ret_count; ++i) {
                if (ret_settings[i].vtype == TYPE_FLOAT) {
                    printf("  OUT %-4s N=%zu\n", ret_settings[i].name, e->rets[i].count);
                    fprintf(f, "[OUT] %s: ", ret_settings[i].name);
                    for (size_t j = 0; j < e->rets[i].count; ++j) {
                        printf("       %g\n", e->rets[i].data[j].f);
                        fprintf(f, "%.10f ", e->rets[i].data[j].f);
                    }
                    fprintf(f, "\n");
                }
                else if (ret_settings[i].vtype == TYPE_DOUBLE) {
                    printf("  OUT %-4s N=%zu\n", ret_settings[i].name, e->rets[i].count);
                    fprintf(f, "[OUT] %s: ", ret_settings[i].name);
                    for (size_t j = 0; j < e->rets[i].count; ++j) {
                        printf("       %g\n", e->rets[i].data[j].d);
                        fprintf(f, "%.10g ", e->rets[i].data[j].d);
                    }
                    fprintf(f, "\n");
                }
            }
        }
    }
}

/* ---------- Dump concrete input that trigger the path ---------- */


#endif // PATH_LOGGER_H