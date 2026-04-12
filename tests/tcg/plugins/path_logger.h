#ifndef PATH_LOGGER_H
#define PATH_LOGGER_H

#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include "uthash.h"
#include "variable.h"

#define NON_PTR_ITER_MAX 50

// ===============================================================================================================================
// globals
// ===============================================================================================================================
//TODO: move to virtual.h?
// current path, current log status
#define MAX_PATH_LENGTH 1024
uint64_t current_path[MAX_PATH_LENGTH];
size_t current_path_len = 0;
bool is_logging_valid = true;

// ===============================================================================================================================
// log strcuts
// ===============================================================================================================================
// log values buffer, for each variable, indexed by ArgSetting[]/RetSetting[] index
#define MAX_PER_PATH_LOG_SIZE 100
typedef struct {
    size_t count; // number of data points currently stored
    // union { float f[MAX_PER_PATH_LOG_SIZE]; uint32_t u32[MAX_PER_PATH_LOG_SIZE]; double d[MAX_PER_PATH_LOG_SIZE]; } data;
    ValueUnion data[MAX_PER_PATH_LOG_SIZE];
} ArgValueLogs;
typedef ArgValueLogs RetValueLogs;


// utitlity: log #acount arg values from ArgSetting[] to ArgValueLogs[], indexed by ArgSetting[] index
//   requires: ArgSetting[] adn ArgValueLogs[] correspond to same input variables, logs acount elements have same log count
//   ensures: ArgValueLogs acount elements have same log count
void append_log_from_arg_settings(ArgValueLogs* logs, const ArgSetting *asettings, size_t acount);
void append_log_from_arg_settings(ArgValueLogs* logs, const ArgSetting *asettings, size_t acount) {
    for (size_t i = 0; i < acount; ++i) {
        if (logs[i].count >= MAX_PER_PATH_LOG_SIZE) continue;
        if (asettings[i].vtype == TYPE_FLOAT)
            logs[i].data[logs[i].count++] = (ValueUnion){ .f = asettings[i].concrete_value.f };
        else if (asettings[i].vtype == TYPE_DOUBLE)
            logs[i].data[logs[i].count++] = (ValueUnion){ .d = asettings[i].concrete_value.d };
        else if (asettings[i].vtype == TYPE_UINT32)
            logs[i].data[logs[i].count++] = (ValueUnion){ .u32 = asettings[i].concrete_value.u32 };
        else if (asettings[i].vtype == TYPE_UINT16)
            logs[i].data[logs[i].count++] = (ValueUnion){ .u32 = asettings[i].concrete_value.u32 };
        else if (asettings[i].vtype == TYPE_UINT8)
            logs[i].data[logs[i].count++] = (ValueUnion){ .u32 = asettings[i].concrete_value.u32 };
        else {
            fprintf(stderr, "Unsupported arg type in log_from_arg_settings for arg '%s'\n", asettings[i].name);
            exit(EXIT_FAILURE);
        }
    }
}

// utility: log #rcount ret values from RetSetting[] to RetValueLogs[], indexed by RetSetting[] index
//   requires: RetSetting[] to RetValueLogs[] corresponds to same output variables, logs rcount elements have same log count
//   ensures: logs rcount elements have same log count
void append_log_from_ret_settings(RetValueLogs* logs, const RetSetting *rsettings, size_t rcount);
void append_log_from_ret_settings(RetValueLogs* logs, const RetSetting *rsettings, size_t rcount) {
    for (size_t i = 0; i < rcount; ++i) {
        if (logs[i].count >= MAX_PER_PATH_LOG_SIZE) continue;
        if (rsettings[i].vtype == TYPE_FLOAT)
            logs[i].data[logs[i].count++] = (ValueUnion){ .f = rsettings[i].concrete_value.f };
        else if (rsettings[i].vtype == TYPE_DOUBLE)
            logs[i].data[logs[i].count++] = (ValueUnion){ .d = rsettings[i].concrete_value.d };
        else if (rsettings[i].vtype == TYPE_UINT32)
            logs[i].data[logs[i].count++] = (ValueUnion){ .u32 = rsettings[i].concrete_value.u32 };
        else if (rsettings[i].vtype == TYPE_UINT16)
            logs[i].data[logs[i].count++] = (ValueUnion){ .u32 = rsettings[i].concrete_value.u32 };
        else if (rsettings[i].vtype == TYPE_UINT8)
            logs[i].data[logs[i].count++] = (ValueUnion){ .u32 = rsettings[i].concrete_value.u32 };
        else {
            fprintf(stderr, "Unsupported ret type in log_from_ret_settings for ret '%s'\n", rsettings[i].name);
            exit(EXIT_FAILURE);
        }
    }
}

// ===============================================================================================================================
// path log, for function level analysis
// ===============================================================================================================================

// path log entry
typedef struct {
    uint64_t      *key; // trace sequence, as key buffer
    size_t         len; // length of the trace sequence, #basic_blocks_visited * sizeof(uint64_t)
    ArgValueLogs   args[MAX_ARGS]; // inputs, indexed by ArgSetting[] (sub-semantic) index
    RetValueLogs   rets[MAX_ARGS]; // outputs, indexed by RetSetting[] (sub-semantic) index
    ValueUnion     concrete_inputs[MAX_ARGS]; // concrete inputs that trigger the path, indexed by ArgSetting[] (function inputs) index
    UT_hash_handle hh;
} PathLogEntry;

// global path log map
PathLogEntry *g_map = NULL;

// helper: convert n addresses to bytes for uthash key
size_t kaddrbytes(size_t n);  // convert number of addresses to bytes
size_t kaddrbytes(size_t n) { return n * sizeof(uint64_t); }

// utility: find entry given a trace sequence as key in hash table
PathLogEntry *trace_find(const uint64_t *seq, size_t len); // key: uint64_t *key (seq) + size_t len
PathLogEntry *trace_find(const uint64_t *seq, size_t len)
{
    PathLogEntry *e = NULL;
    HASH_FIND(hh, g_map, seq, kaddrbytes(len), e);
    return e;
}

// utility: create an entry for given trace sequence in hash table
PathLogEntry *trace_create(const uint64_t *seq, size_t len);
PathLogEntry *trace_create(const uint64_t *seq, size_t len)
{
    PathLogEntry *e = (PathLogEntry *)calloc(1, sizeof *e);
    if (!e) { perror("calloc"); exit(1); }
    e->key = (uint64_t *)malloc(kaddrbytes(len));
    if (!e->key) { perror("malloc key"); exit(1); }
    memcpy(e->key, seq, kaddrbytes(len));
    e->len = len;
    HASH_ADD_KEYPTR(hh, g_map, e->key, kaddrbytes(len), e);
    return e;
}

// utility: append concrete input values from ArgSetting[] to path log entry e, e->concrete_inputs indexed by ArgSetting[] index
void append_concrete_inputs_to_path_log(PathLogEntry *e, const ArgSetting *asettings, size_t acount);
void append_concrete_inputs_to_path_log(PathLogEntry *e, const ArgSetting *asettings, size_t acount) {
    for (size_t i = 0; i < acount; ++i) {
        if (asettings[i].vtype == TYPE_FLOAT)
            e->concrete_inputs[i] = (ValueUnion){ .f = asettings[i].concrete_value.f };
        else if (asettings[i].vtype == TYPE_DOUBLE)
            e->concrete_inputs[i] = (ValueUnion){ .d = asettings[i].concrete_value.d };
        else if (asettings[i].vtype == TYPE_UINT32)
            e->concrete_inputs[i] = (ValueUnion){ .u32 = asettings[i].concrete_value.u32 };
        else if (asettings[i].vtype == TYPE_UINT16)
            e->concrete_inputs[i] = (ValueUnion){ .u32 = asettings[i].concrete_value.u32 };
        else if (asettings[i].vtype == TYPE_UINT8)
            e->concrete_inputs[i] = (ValueUnion){ .u32 = asettings[i].concrete_value.u32 };
        else {
            fprintf(stderr, "Unsupported arg type in append_concrete_inputs_to_path_log for arg '%s'\n", asettings[i].name);
            exit(EXIT_FAILURE);
        }
    }
}

// utility: clear all path logs
void clear_all_path_logs(void);
void clear_all_path_logs(void)
{
    PathLogEntry *e, *tmp;
    HASH_ITER(hh, g_map, e, tmp) { HASH_DEL(g_map, e); free(e->key); free(e); }
}

// utility: print all path logs to stdout for debugging
void print_all_path_logs(void); // only to stdout for debugging
void print_all_path_logs(void)
{
    PathLogEntry *e, *tmp;
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

// utility: check if all path logs are ready for dump (i.e., all path log entries have #arg logs reach MAX_PER_PATH_LOG_SIZE)
// return:
//   if yes, dump the path logs to files under dump_dir and return 1, otherwise return 0
int is_path_log_ready_for_dump(size_t acount);
int is_path_log_ready_for_dump(size_t acount) {
    PathLogEntry *e, *tmp;

    int num_path_log_ready = 0;
    int total_paths = 0;
    HASH_ITER(hh, g_map, e, tmp) {
        total_paths++;
        // bool need_dump = false;
        for (size_t i = 0; i < acount; ++i) {
            if (e->args[i].count >= MAX_PER_PATH_LOG_SIZE) {
                // need_dump = true;
                num_path_log_ready++;
                break;
            }
        }
    }
    return num_path_log_ready && (num_path_log_ready == total_paths);
}

// ===============================================================================================================================
// value log, for sub-semantic analysis
// ===============================================================================================================================
ArgValueLogs   arglog_subsem[MAX_ARGS]; // inputs
RetValueLogs   retlog_subsem[MAX_ARGS]; // outputs

// utility: check if all sub-semantic log size reach MAX_PER_PATH_LOG_SIZE
// return:
//   1 if all sub-semantic log size reach MAX_PER_PATH_LOG_SIZE, otherwise 0
int is_sub_semantic_log_ready_for_dump(size_t acount);
int is_sub_semantic_log_ready_for_dump(size_t acount) {
    for (size_t i = 0; i < acount; ++i) {
        if (arglog_subsem[i].count < MAX_PER_PATH_LOG_SIZE) {
            return 0;
        }
    }
    return 1;
}

void clear_all_sub_semantic_logs(void);
void clear_all_sub_semantic_logs(void) {
    for (size_t i = 0; i < arg_count; ++i) {
        arglog_subsem[i].count = 0;
    }
    for (size_t i = 0; i < ret_count; ++i) {
        retlog_subsem[i].count = 0;
    }
}
#endif // PATH_LOGGER_H