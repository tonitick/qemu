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
#include "json_parse.h"

// ===============================================================================================================================
// End-to-end recovery, with path identification
// ===============================================================================================================================

/* ---------- current path ---------- */
#define MAX_PATH_LENGTH 1024
uint64_t current_path[MAX_PATH_LENGTH];
size_t current_path_len = 0;
// ValueUnion logged_in_values[MAX_ARGS], logged_out_values[MAX_ARGS]; // a single input-output record
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
    ArgValueLogs   args[MAX_ARGS]; // inputs
    RetValueLogs   rets[MAX_ARGS]; // outputs
    ValueUnion     concrete_inputs[MAX_ARGS]; // concrete inputs that trigger the path
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
void record_trace_values(const uint64_t *seq, size_t len);
                        //  const ValueUnion *arg_vals,
                        //  const ValueUnion *ret_vals);
// Record values for a trace sequence
void record_trace_values(const uint64_t *seq, size_t len)
                                // const ValueUnion *arg_vals,
                                // const ValueUnion *ret_vals)
{
    Entry *e = trace_find(seq, len);
    if (!e) e = trace_create(seq, len);

    // input/ouput pairs
    for (size_t i = 0; i < arg_count; ++i) {
        ArgValueLogs *L = &e->args[i];
        if (L->count >= MAX_PER_PATH_LOG_SIZE) continue;
        if (arg_settings[i].vtype == TYPE_FLOAT)
            L->data[L->count++].f = arg_settings[i].concrete_value.f;
        else if (arg_settings[i].vtype == TYPE_DOUBLE)
            L->data[L->count++].d = arg_settings[i].concrete_value.d;
        else if (arg_settings[i].vtype == TYPE_UINT32)
            L->data[L->count++].u32 = arg_settings[i].concrete_value.u32;
        else if (arg_settings[i].vtype == TYPE_UINT16)
            L->data[L->count++].u32 = arg_settings[i].concrete_value.u32;
        else if (arg_settings[i].vtype == TYPE_UINT8)
            L->data[L->count++].u32 = arg_settings[i].concrete_value.u32;
        else {
            fprintf(stderr, "Unsupported arg type in record_trace_values for arg '%s'\n", arg_settings[i].name);
            exit(EXIT_FAILURE);
        }
    }
    for (size_t i = 0; i < ret_count; ++i) {
        RetValueLogs *L = &e->rets[i];
        if (L->count >= MAX_PER_PATH_LOG_SIZE) continue;
        if (ret_settings[i].vtype == TYPE_FLOAT)
            L->data[L->count++].f = ret_settings[i].concrete_value.f;
        else if (ret_settings[i].vtype == TYPE_DOUBLE)
            L->data[L->count++].d = ret_settings[i].concrete_value.d;
        else if (ret_settings[i].vtype == TYPE_UINT32)
            L->data[L->count++].u32 = ret_settings[i].concrete_value.u32;
        else if (ret_settings[i].vtype == TYPE_UINT16)
            L->data[L->count++].u32 = ret_settings[i].concrete_value.u32;
        else if (ret_settings[i].vtype == TYPE_UINT8)
            L->data[L->count++].u32 = ret_settings[i].concrete_value.u32;
        else {
            fprintf(stderr, "Unsupported ret type in record_trace_values for ret '%s'\n", ret_settings[i].name);
            exit(EXIT_FAILURE);
        }
    }

    // concrete path inputs
    for (size_t i = 0; i < arg_count; ++i) {
        if (arg_settings[i].vtype == TYPE_FLOAT)
            e->concrete_inputs[i].f = arg_settings[i].concrete_value.f;
        else if (arg_settings[i].vtype == TYPE_DOUBLE)
            e->concrete_inputs[i].d = arg_settings[i].concrete_value.d;
        else if (arg_settings[i].vtype == TYPE_UINT32)
            e->concrete_inputs[i].u32 = arg_settings[i].concrete_value.u32;
        else if (arg_settings[i].vtype == TYPE_UINT16)
            e->concrete_inputs[i].u32 = arg_settings[i].concrete_value.u32;
        else if (arg_settings[i].vtype == TYPE_UINT8)
            e->concrete_inputs[i].u32 = arg_settings[i].concrete_value.u32;
        else {
            fprintf(stderr, "Unsupported arg type in record_trace_values for arg '%s'\n", arg_settings[i].name);
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
void dump_all_path_logs(void); // only to stdout for debugging
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

int check_path_log_size_and_dump(char* dump_dir);
int check_path_log_size_and_dump(char* dump_dir) {
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
            /* 1. input-output pairs */
            char path_dir[256] = {0};
            snprintf(path_dir, sizeof(path_dir), "%s/path_id_%d_len_%zu", dump_dir, path_id++, e->len);
            // create dir
            if (mkdir(path_dir, 0755) == -1) {
                if (errno != EEXIST) {
                    printf("Failed to create directory %s: %s\n", path_dir, strerror(errno));
                    exit(EXIT_FAILURE);
                }
            }
            char filepath[256] = {0};
            // snprintf(filepath, sizeof(filepath), "%s/path_id_%d_len_%zu.txt", dump_dir, path_id++, e->len);
            snprintf(filepath, sizeof(filepath), "%s/in_outs.txt", path_dir);
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
            fclose(f);

            /* 2. basic block trace sequences */
            char trace_filepath[256] = {0};
            snprintf(trace_filepath, sizeof(trace_filepath), "%s/bb_seqs.txt", path_dir);
            FILE *trace_f = fopen(trace_filepath, "w");
            if (!trace_f) {
                perror("fopen");
                continue;
            }
            for (size_t i = 0; i < e->len; ++i) {
                fprintf(trace_f, "0x%08" PRIx64 "\n", e->key[i]);
            }
            fclose(trace_f);

            /* 3. concrete input values in json*/
            cJSON *root = cJSON_CreateObject();
            if (root == NULL) {
                fprintf(stderr, "Failed to create cJSON root object\n");
                continue;
            }
            for (size_t i = 0; i < arg_count; ++i) {
                // replace arg_settings concrete_value with e->concrete_inputs
                arg_settings[i].concrete_value = e->concrete_inputs[i];
                cJSON *arg_item = arg_setting_to_json(&arg_settings[i]);
                if (arg_item == NULL) {
                    fprintf(stderr, "Failed to convert arg_setting to JSON for arg '%s'\n", arg_settings[i].name);
                    continue;
                }
                cJSON_AddItemToObject(root, arg_settings[i].name, arg_item);
            }
            char concrete_input_filepath[256] = {0};
            snprintf(concrete_input_filepath, sizeof(concrete_input_filepath), "%s/concrete_inputs.json", path_dir);
            char *json_str = cJSON_Print(root);
            if (json_str == NULL) {
                fprintf(stderr, "Failed to print cJSON to string\n");
                cJSON_Delete(root);
                continue;
            }
            FILE *json_f = fopen(concrete_input_filepath, "w");
            if (!json_f) {
                perror("fopen");
                cJSON_Delete(root);
                fclose(f);
                continue;
            }
            fprintf(json_f, "%s\n", json_str);
            fclose(json_f);
            cJSON_free(json_str);
        }

        // dump calling interface in json
        // input
        cJSON *ci_input_root = cJSON_CreateObject();
        if (ci_input_root == NULL) {
            fprintf(stderr, "Failed to create cJSON root object for calling interface\n");
            return 0;
        }
        for (size_t i = 0; i < arg_count; ++i) {
            cJSON *arg_item = arg_setting_to_call_interface_json(&arg_settings[i]);
            if (arg_item == NULL) {
                fprintf(stderr, "Failed to convert arg_setting to JSON for calling interface arg '%s'\n", arg_settings[i].name);
                continue;
            }
            cJSON_AddItemToObject(ci_input_root, arg_settings[i].name, arg_item);
        }
        char calling_interface_input_filepath[256] = {0};
        snprintf(calling_interface_input_filepath, sizeof(calling_interface_input_filepath), "%s/calling_interface_input.json", dump_dir);
        char *ci_input_json_str = cJSON_Print(ci_input_root);
        if (ci_input_json_str == NULL) {
            fprintf(stderr, "Failed to print cJSON to string for calling interface\n");
            cJSON_Delete(ci_input_root);
            return 0;
        }
        FILE *ci_input_json_f = fopen(calling_interface_input_filepath, "w");
        if (!ci_input_json_f) {
            perror("fopen");
            cJSON_Delete(ci_input_root);
            return 0;
        }
        fprintf(ci_input_json_f, "%s\n", ci_input_json_str);
        fclose(ci_input_json_f);
        cJSON_free(ci_input_json_str);

        // output
        cJSON *ci_output_root = cJSON_CreateObject();
        if (ci_output_root == NULL) {
            fprintf(stderr, "Failed to create cJSON root object for calling interface output\n");
            return 0;
        }
        for (size_t i = 0; i < ret_count; ++i) {
            cJSON *ret_item = ret_setting_to_call_interface_json(&ret_settings[i]);
            if (ret_item == NULL) {
                fprintf(stderr, "Failed to convert ret_setting to JSON for calling interface ret '%s'\n", ret_settings[i].name);
                continue;
            }
            cJSON_AddItemToObject(ci_output_root, ret_settings[i].name, ret_item);
        }
        char calling_interface_output_filepath[256] = {0};
        snprintf(calling_interface_output_filepath, sizeof(calling_interface_output_filepath), "%s/calling_interface_output.json", dump_dir);
        char *ci_output_json_str = cJSON_Print(ci_output_root);
        if (ci_output_json_str == NULL) {
            fprintf(stderr, "Failed to print cJSON to string for calling interface output\n");
            cJSON_Delete(ci_output_root);
            return 0;
        }
        FILE *ci_output_json_f = fopen(calling_interface_output_filepath, "w");
        if (!ci_output_json_f) {
            perror("fopen");
            cJSON_Delete(ci_output_root);
            return 0;
        }
        fprintf(ci_output_json_f, "%s\n", ci_output_json_str);
        fclose(ci_output_json_f);
        cJSON_free(ci_output_json_str);
        cJSON_Delete(ci_output_root);

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
            /* 1. input-output pairs */
            char path_dir[256] = {0};
            snprintf(path_dir, sizeof(path_dir), "%s/path_id_%d_len_%zu", dump_dir, path_id++, e->len);
            // create dir
            if (mkdir(path_dir, 0755) == -1) {
                if (errno != EEXIST) {
                    printf("Failed to create directory %s: %s\n", path_dir, strerror(errno));
                    exit(EXIT_FAILURE);
                }
            }
            char filepath[256] = {0};
            snprintf(filepath, sizeof(filepath), "%s/path_id_%d_len_%zu.txt", dump_dir, path_id++, e->len);
            snprintf(filepath, sizeof(filepath), "%s/in_outs.txt", path_dir);
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
            fclose(f);

            /* 2. basic block trace sequences */
            char trace_filepath[256] = {0};
            snprintf(trace_filepath, sizeof(trace_filepath), "%s/bb_seqs.txt", path_dir);
            FILE *trace_f = fopen(trace_filepath, "w");
            if (!trace_f) {
                perror("fopen");
                continue;
            }
            for (size_t i = 0; i < e->len; ++i) {
                fprintf(trace_f, "0x%08" PRIx64 "\n", e->key[i]);
            }
            fclose(trace_f);

            /* 3. concrete input values in json*/
            cJSON *root = cJSON_CreateObject();
            if (root == NULL) {
                fprintf(stderr, "Failed to create cJSON root object\n");
                continue;
            }
            for (size_t i = 0; i < arg_count; ++i) {
                // replace arg_settings concrete_value with e->concrete_inputs
                arg_settings[i].concrete_value = e->concrete_inputs[i];
                cJSON *arg_item = arg_setting_to_json(&arg_settings[i]);
                if (arg_item == NULL) {
                    fprintf(stderr, "Failed to convert arg_setting to JSON for arg '%s'\n", arg_settings[i].name);
                    continue;
                }
                cJSON_AddItemToObject(root, arg_settings[i].name, arg_item);
            }
            char concrete_input_filepath[256] = {0};
            snprintf(concrete_input_filepath, sizeof(concrete_input_filepath), "%s/concrete_inputs.json", path_dir);
            char *json_str = cJSON_Print(root);
            if (json_str == NULL) {
                fprintf(stderr, "Failed to print cJSON to string\n");
                cJSON_Delete(root);
                continue;
            }
            FILE *json_f = fopen(concrete_input_filepath, "w");
            if (!json_f) {
                perror("fopen");
                cJSON_Delete(root);
                fclose(f);
                continue;
            }
            fprintf(json_f, "%s\n", json_str);
            fclose(json_f);
            cJSON_free(json_str);
        }
    }
}

/* ---------- Dump concrete input that trigger the path ---------- */

// ===============================================================================================================================
// Sub-semantic Utilities
// ===============================================================================================================================
ArgValueLogs   arglog_subsem[MAX_ARGS]; // inputs
RetValueLogs   retlog_subsem[MAX_ARGS]; // outputs

int check_sub_semantic_log_size_and_dump(char* dump_dir);
int check_sub_semantic_log_size_and_dump(char* dump_dir) {
    // if all sub-semantic log size reach MAX_PER_PATH_LOG_SIZE, dump the related path logs
    int need_dump = 0;
    for (size_t i = 0; i < arg_count; ++i) {
        if (arglog_subsem[i].count >= MAX_PER_PATH_LOG_SIZE) {
            need_dump = 1;
            break;
        }
    }

    if (need_dump) {
        char filepath[256] = {0};
        snprintf(filepath, sizeof(filepath), "%s/in_outs.txt", dump_dir);
        FILE *f = fopen(filepath, "w");
        if (!f) {
            printf("Failed to open file %s for writing\n", filepath);
            exit(EXIT_FAILURE);
        }

        // dump the entry
        printf("Dumping sub-semantic log:\n");

        for (size_t i = 0; i < arg_count; ++i) {
            if (!arg_settings[i].is_sub_semantic_input) continue;
            if (arg_settings[i].vtype == TYPE_FLOAT) {
                printf("  IN  %-4s\n", arg_settings[i].name);
                fprintf(f, "[IN] %s: ", arg_settings[i].name);
                for (size_t j = 0; j < arglog_subsem[i].count; ++j) {
                    printf("       %g\n", arglog_subsem[i].data[j].f);
                    fprintf(f, "%.10f ", arglog_subsem[i].data[j].f);
                }
                fprintf(f, "\n");
            }
            else if (arg_settings[i].vtype == TYPE_DOUBLE) {
                printf("  IN  %-4s\n", arg_settings[i].name);
                fprintf(f, "[IN] %s: ", arg_settings[i].name);
                for (size_t j = 0; j < arglog_subsem[i].count; ++j) {
                    printf("       %g\n", arglog_subsem[i].data[j].d);
                    fprintf(f, "%.10g ", arglog_subsem[i].data[j].d);
                }
                fprintf(f, "\n");
            }
        }

        for (size_t i = 0; i < ret_count; ++i) {
            if (ret_settings[i].vtype == TYPE_FLOAT) {
                printf("  OUT %-4s\n", ret_settings[i].name);
                fprintf(f, "[OUT %lu] %s: ", ret_settings[i].written_time, ret_settings[i].name); // add last written time to variable name
                for (size_t j = 0; j < retlog_subsem[i].count; ++j) {
                    printf("       %g\n", retlog_subsem[i].data[j].f);
                    fprintf(f, "%.10f ", retlog_subsem[i].data[j].f);
                }
                fprintf(f, "\n");
            }
            else if (ret_settings[i].vtype == TYPE_DOUBLE) {
                printf("  OUT %-4s\n", ret_settings[i].name);
                fprintf(f, "[OUT %lu] %s: ", ret_settings[i].written_time, ret_settings[i].name); // add last written time to variable name
                for (size_t j = 0; j < retlog_subsem[i].count; ++j) {
                    printf("       %g\n", retlog_subsem[i].data[j].d);
                    fprintf(f, "%.10g ", retlog_subsem[i].data[j].d);
                }
                fprintf(f, "\n");
            }
        }
        fclose(f);

        // dump input/output information in json
        // input (only is_sub_semantic_input == true)
        cJSON *ci_input_root = cJSON_CreateObject();
        if (ci_input_root == NULL) {
            fprintf(stderr, "Failed to create cJSON root object for calling interface\n");
            return 0;
        }
        for (size_t i = 0; i < arg_count; ++i) {
            if (!arg_settings[i].is_sub_semantic_input) continue;
            cJSON *arg_item = arg_setting_to_call_interface_json(&arg_settings[i]);
            if (arg_item == NULL) {
                fprintf(stderr, "Failed to convert arg_setting to JSON for calling interface\n");
                continue;
            }
            cJSON_AddItemToObject(ci_input_root, arg_settings[i].name, arg_item);
        }
        char sub_sem_input_filepath[256] = {0};
        snprintf(sub_sem_input_filepath, sizeof(sub_sem_input_filepath), "%s/sub_sem_input.json", dump_dir);
        char *ci_input_json_str = cJSON_Print(ci_input_root);
        if (ci_input_json_str == NULL) {
            fprintf(stderr, "Failed to print cJSON to string for calling interface\n");
            cJSON_Delete(ci_input_root);
            return 0;
        }
        FILE *ci_input_json_f = fopen(sub_sem_input_filepath, "w");
        if (!ci_input_json_f) {
            perror("fopen");
            cJSON_Delete(ci_input_root);
            return 0;
        }
        fprintf(ci_input_json_f, "%s\n", ci_input_json_str);
        fclose(ci_input_json_f);
        cJSON_free(ci_input_json_str);

        // output
        cJSON *ci_output_root = cJSON_CreateObject();
        if (ci_output_root == NULL) {
            fprintf(stderr, "Failed to create cJSON root object for calling interface output\n");
            return 0;
        }
        for (size_t i = 0; i < ret_count; ++i) {
            cJSON *ret_item = ret_setting_to_call_interface_json(&ret_settings[i]);
            if (ret_item == NULL) {
                fprintf(stderr, "Failed to convert ret_setting to JSON for calling interface\n");
                continue;
            }
            cJSON_AddItemToObject(ci_output_root, ret_settings[i].name, ret_item);
        }
        char sub_sem_output_filepath[256] = {0};
        snprintf(sub_sem_output_filepath, sizeof(sub_sem_output_filepath), "%s/sub_sem_output.json", dump_dir);
        char *ci_output_json_str = cJSON_Print(ci_output_root);
        if (ci_output_json_str == NULL) {
            fprintf(stderr, "Failed to print cJSON to string for calling interface output\n");
            cJSON_Delete(ci_output_root);
            return 0;
        }
        FILE *ci_output_json_f = fopen(sub_sem_output_filepath, "w");
        if (!ci_output_json_f) {
            perror("fopen");
            cJSON_Delete(ci_output_root);
            return 0;
        }
        fprintf(ci_output_json_f, "%s\n", ci_output_json_str);
        fclose(ci_output_json_f);
        cJSON_free(ci_output_json_str);

        return 1; // success
    }
    return 0; // not enough logs
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

void record_sub_semantic_trace_values(void);
void record_sub_semantic_trace_values(void) {
    // input/ouput pairs
    for (size_t i = 0; i < arg_count; ++i) {
        ArgValueLogs *L = &arglog_subsem[i];
        if (L->count >= MAX_PER_PATH_LOG_SIZE) continue;
        if (arg_settings[i].vtype == TYPE_FLOAT)
            L->data[L->count++].f = arg_settings[i].concrete_value.f;
        else if (arg_settings[i].vtype == TYPE_DOUBLE)
            L->data[L->count++].d = arg_settings[i].concrete_value.d;
        else if (arg_settings[i].vtype == TYPE_UINT32)
            L->data[L->count++].u32 = arg_settings[i].concrete_value.u32;
        else if (arg_settings[i].vtype == TYPE_UINT16)
            L->data[L->count++].u32 = arg_settings[i].concrete_value.u32;
        else if (arg_settings[i].vtype == TYPE_UINT8)
            L->data[L->count++].u32 = arg_settings[i].concrete_value.u32;
        else {
            fprintf(stderr, "Unsupported arg type in record_sub_semantic_trace_values for arg '%s'\n", arg_settings[i].name);
            exit(EXIT_FAILURE);
        }
    }
    for (size_t i = 0; i < ret_count; ++i) {
        RetValueLogs *L = &retlog_subsem[i];
        if (L->count >= MAX_PER_PATH_LOG_SIZE) continue;
        if (ret_settings[i].vtype == TYPE_FLOAT)
            L->data[L->count++].f = ret_settings[i].concrete_value.f;
        else if (ret_settings[i].vtype == TYPE_DOUBLE)
            L->data[L->count++].d = ret_settings[i].concrete_value.d;
        else if (ret_settings[i].vtype == TYPE_UINT32)
            L->data[L->count++].u32 = ret_settings[i].concrete_value.u32;
        else if (ret_settings[i].vtype == TYPE_UINT16)
            L->data[L->count++].u32 = ret_settings[i].concrete_value.u32;
        else if (ret_settings[i].vtype == TYPE_UINT8)
            L->data[L->count++].u32 = ret_settings[i].concrete_value.u32;
        else {
            fprintf(stderr, "Unsupported ret type in record_sub_semantic_trace_values for ret '%s'\n", ret_settings[i].name);
            exit(EXIT_FAILURE);
        }
    }
}
#endif // PATH_LOGGER_H