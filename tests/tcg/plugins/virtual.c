/*
 * Copyright (C) 2018, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
int isdigit(int c);
#include <inttypes.h>
#include <assert.h>
#include <unistd.h>
#include <glib.h>

#include <qemu-plugin.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "virtual.h"
#include "capstone_util.h"
#include "struct_recovery.h"
#include "logger.h"
#include "modifier.h"
#include "detour.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

char dump_path[256] = "collected_data";
int default_int_range[2] = {0, 3};
float default_float_range[2] = {-5.0, 5.0};
double default_double_range[2] = {-5.0, 5.0};

/*
 * Non-termination watchdogs (runaway loop + fault-spin).
 *
 * A 4-byte struct field discovered at runtime is tentatively treated as an
 * unknown pointer and seeded with a pointer-arena address (~0x30000000+, i.e.
 * hundreds of millions). When such a field is actually a scalar loop bound
 * (e.g. RunningAverage::_count at [this+4] driving the average loop), that huge
 * value makes the function loop hundreds of millions of times. It never
 * returns, so randargs is never re-entered and the NON_PTR_ITER_MAX demotion
 * path (which only runs on re-entry) can never fix it; QEMU just gets killed by
 * the outer timeout with zero data collected. The loop also keeps re-entering
 * its body basic block, so current_path overflows its MAX_PATH_LENGTH buffer.
 *
 * The watchdog bounds basic-block visits per function invocation. Kept just
 * below MAX_PATH_LENGTH so it also prevents the current_path overflow. See
 * trigger_inf_exe_watchdog() for how the offending field is demoted.
 *
 * The bb-visit watchdog above only counts the *function's own* basic blocks, so
 * it only catches a runaway that keeps re-entering an in-function loop body
 * (e.g. getAverage walking _ar[i] sequentially). It is blind to a different
 * failure mode: when a misclassified scalar is used as an *array index* rather
 * than a loop bound (e.g. RunningAverage::getAverageLast computes
 * _ar + (_idx-1)*4, and a pointer-arena _idx makes that address ~0xF000xxxx on
 * the very first iteration), the load faults immediately and the CPU vectors to
 * the firmware's default fault handler -- typically a `b .` infinite loop that
 * lives outside the function range and is never instrumented. Execution never
 * re-enters the function's basic blocks, so the bb-visit watchdog never fires
 * and QEMU spins until the outer timeout with zero data collected.
 *
 * The global-execution watchdog below counts *every* translated block executed
 * since the function was last (re-)entered via randargs. A stuck fault handler
 * (or any out-of-function spin) racks up TB executions without re-entering
 * randargs, so once the count crosses GLOBAL_EXEC_WATCHDOG_THRESHOLD we run the
 * same demote-one-then-retry recovery as the bb-visit watchdog. The threshold
 * is far above the TB count of any legitimate single invocation (which returns
 * and re-enters randargs, resetting the counter) yet fires in well under a
 * second against a tight handler loop.
 */
#define WATCHDOG_PATH_THRESHOLD (MAX_PATH_LENGTH - 16)
/* Instruction budget per function invocation. Counts ALL executed instructions
 * (incl. out-of-function fault handlers that spin), reset on each function entry.
 * Catches faults/runaways that never re-enter an instrumented basic block -- e.g.
 * a wild _array[_index] access that bus-faults into a spinning default handler.
 * Generous so legitimate (small, demoted) loops never trip it. */
#define GLOBAL_EXEC_WATCHDOG_THRESHOLD 2000000UL
unsigned long iter_insn_count = 0;
/* Range for a field the watchdog demotes; avoid 0 to skip empty-loop/NaN paths. */
int demote_int_range[2] = {1, 3};

/* Visit-gated sub-semantic triggers (per-iteration loop stages).
 * randargs / logrets sit on a loop-body address that is hit `cnt` times per
 * invocation; each fires on EVERY visit but acts only on its configured visit
 * index (parsed from virtuals.txt; 0 == any/every visit, the non-loop default).
 * The counters are per-invocation and reset in setargs(). */
int randargs_target_visit = 0, logrets_target_visit = 0;
int randargs_visit_counter = 0, logrets_visit_counter = 0;

// --------------------------------------------------------------------------------------
// randargs
// --------------------------------------------------------------------------------------

// unsigned long long* parse_addresses(const char *input, size_t *count);
// unsigned long long* parse_addresses(const char *input, size_t *count) {
//     // Make a copy of input so we don't modify the original
//     char *input_copy = strdup(input);
//     if (!input_copy) return NULL;

//     size_t capacity = 8;
//     *count = 0;
//     unsigned long long *addresses = malloc(capacity * sizeof(unsigned long long));
//     if (!addresses) {
//         free(input_copy);
//         return NULL;
//     }

//     char *token = strtok(input_copy, ",");
//     while (token) {
//         // Remove leading/trailing whitespace
//         while (*token == ' ' || *token == '\t') token++;
//         char *endptr;
//         unsigned long long addr = strtoull(token, &endptr, 0);
//         if (token == endptr) {
//             // Invalid conversion
//             free(addresses);
//             free(input_copy);
//             return NULL;
//         }

//         if (*count >= capacity) {
//             capacity *= 2;
//             addresses = realloc(addresses, capacity * sizeof(unsigned long long));
//             if (!addresses) {
//                 free(input_copy);
//                 return NULL;
//             }
//         }

//         addresses[(*count)++] = addr;
//         token = strtok(NULL, ",");
//     }

//     free(input_copy);
//     return addresses;
// }
// static void randstate(unsigned int cpu_index, void *udata) {
// 	const char *input = (const char *) udata;

// 	size_t count = 0;
// 	unsigned long long *addrs = parse_addresses(input, &count);
// 	if (addrs) {
//         for (size_t i = 0; i < count; i++) {
// 			if (addrs[i] < 100) {
// 				uint32_t val = get_random_word();
// 				//PC not supported 
// 				if (addrs[i] != 15) {
// 					qemu_plugin_set_register((uint8_t *)&val,addrs[i] );
// 				}
// 			} else {
// 				uint8_t val = get_random_byte();
// 				qemu_plugin_write_memory(addrs[i], &val, 1);
// 			}
//         }
//         free(addrs);
//     } else {
//         printf("Failed to parse addresses.\n");
//     }

// }


static int cur_iteration = 0;
#define MAX_FUZZ_ITERATIONS 10000000
static void randargs(unsigned int cpu_index, void *udata) {
    // print pc for debugging
    // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15); // this is not accurate sometimes
    uint64_t pc = *(uint64_t *)udata;
    printf("[VI randargs] Current PC: 0x%08lx\n", pc);

    function_reached = true;
    function_reach_time = current_timestamp_ms();
    if (dump_start_time == 0) dump_start_time = function_reach_time;  // one-time (for dump budget)

    // New run starts here (randargs fires at func_start on every run, including the
    // invalidation/PC-reset retry). Reset the edge tracker so the restart cannot
    // fabricate a spurious (last_bb_of_aborted_run -> func_start) edge.
    have_last_bb = false;
    last_bb_idx = -1;

    // printf("randargs - results for iteration %d:\n", cur_iteration);
    if (cur_iteration >= MAX_FUZZ_ITERATIONS) {
        printf("[VI randargs] reached max fuzzing iterations %d, dump existing path logs and exiting\n", MAX_FUZZ_ITERATIONS);
        dump_existing_path_logs(dump_path);
        dump_edge_coverage(dump_path);
        unsigned long long fuzzing_end_time = current_timestamp_ms();
        printf("[VI randargs] total fuzzing time: %f sec\n", (double)(fuzzing_end_time - function_reach_time) / 1000.0);
        exit(0);
    }
    if (check_path_log_size_and_dump(dump_path)) {
        printf("[VI randargs] log finished, dump related path logs\n");
        // print_all_path_logs();
        dump_edge_coverage(dump_path);
        unsigned long long fuzzing_end_time = current_timestamp_ms();
        printf("[VI randargs] total fuzzing time: %f sec\n", (double)(fuzzing_end_time - function_reach_time) / 1000.0);
        exit(0);
    }
    if (cur_iteration == 0) {
        // clear path logs
        clear_all_path_logs();
        // set non_ptr_iters to 0 for all args
        for (size_t i = 0; i < arg_count; i++) {
            ArgSetting *setting = &arg_settings[i];
            setting->non_ptr_iters = 0;
        }
    }
    else if (is_logging_valid) {
        // log previous iteration values
        // if (is_logging_valid) {
        record_trace_values(current_path, current_path_len, arg_settings, arg_count, ret_settings, ret_count);
        // Mark the *recorded* edge set from the just-committed path: consecutive
        // blocks in current_path are executed edges from a valid sample. This is the
        // committed subset of edge_exec (may undercount vs edge_exec when a loop
        // truncated current_path, which is the intended semantics).
        for (int k = 0; k + 1 < (int)current_path_len; k++) {
            int si = bb_index_of((unsigned long)current_path[k]);
            int di = bb_index_of((unsigned long)current_path[k + 1]);
            if (si >= 0 && di >= 0) edge_rec[si][di] = 1;
        }
        // }
        // clear
        // current_path_len = 0;
    }
    else if (!is_logging_valid) {
        clear_all_path_logs(); // zz: log only when arg settings can stably generate valid logs
        // printf("[VI randargs] dump path log after clear:\n");
        // print_all_path_logs();

        // dump arg settings for debugging
        printf("[VI randargs] previous iteration logging invalid, fix arg settings\n");
        print_arg_settings(arg_settings, &arg_count);
        // fix all unknown pointer args to non-pointer integers
        // TODO: take care of the control flows, assume the same path for now
    }

    // set stack pointer
    ValueUnion sp_val;
    sp_val.u32 = stack_ptr;
    qemu_plugin_set_register((uint8_t *)&sp_val, ARM_V7M_REG_R13);
    // reset stack var write tracking
    stack_var_write_count = 0;

    // increment non_ptr_iters for all unknown pointer args
    for (size_t i = 0; i < arg_count; i++) {
        ArgSetting *setting = &arg_settings[i];
        if (setting->vtype == TYPE_UINT32 && setting->is_pointer == IS_PTR_UNKNOWN) {
            setting->non_ptr_iters++;
            printf("[VI randargs] unknown pointer arg '%s' has been tried %d times\n", setting->name, setting->non_ptr_iters);
            if (setting->non_ptr_iters > NON_PTR_ITER_MAX) {
                printf("[VI randargs] fixing unknown pointer arg '%s' to non-pointer integer after %d tries\n", setting->name, setting->non_ptr_iters);
                if (setting->location_type == TYPE_ADDR) {
                    // A struct field still IS_PTR_UNKNOWN after NON_PTR_ITER_MAX
                    // iterations was never dereferenced as a pointer AND never
                    // touched by an FP instruction (the float callback promotes
                    // genuine float fields to TYPE_FLOAT on first FP access, long
                    // before this). So it is an integer scalar -- typically a
                    // loop bound (e.g. RunningAverage::_count). Demote to a small
                    // int, NOT a float: a float bit-pattern reinterpreted as a
                    // loop count is a huge integer and would make the loop walk
                    // hundreds of millions of elements. If we ever guess wrong,
                    // the float callback re-promotes it on the next FP access.
                    setting->is_pointer = IS_PTR_FALSE;
                    setting->vtype = TYPE_UINT32;
                    setting->value_count = 2;
                    setting->value_range[0].u32 = demote_int_range[0];
                    setting->value_range[1].u32 = demote_int_range[1];

                    clear_all_path_logs();
                }
                else if (setting->location_type == TYPE_REG) { // float regs are identified statically
                    // set to float
                    setting->is_pointer = IS_PTR_FALSE;
                    setting->vtype = TYPE_UINT32;
                    setting->value_count = 2;
                    setting->value_range[0].u32 = default_int_range[0];
                    setting->value_range[1].u32 = default_int_range[1];
                    clear_all_path_logs();
                }
                print_arg_settings(arg_settings, &arg_count); // for debug
            }
        }
    }

    current_path_len = 0;
    iter_insn_count = 0; /* reset per-invocation instruction-budget watchdog */

    // main logic: rand variables and set registers/memory
    is_logging_valid = true;
    cur_iteration++;
    printf("[VI randargs] iteration %d:\n", cur_iteration);
    // iterate arg_settings
    for (size_t i = 0; i < arg_count; i++) {
        ArgSetting *setting = &arg_settings[i];
        // use range to generate random value
        ValueUnion value;
        // potential pointer types
        if (setting->vtype == TYPE_UNKNOWN) { // only for potential pointer types, size = 4
            // treat as uint32 first
            // value_count shoule be 0
            if (setting->value_count != 0) {
                fprintf(stderr, "[VI randargs] Invalid value count for unknown type in setting '%s'\n", setting->name);
                perror("randargs");
                exit(EXIT_FAILURE);
            }
            setting->vtype = TYPE_UINT32; // default to uint32

            // perror("randargs");
            // exit(EXIT_FAILURE);
            // use default [0, 2]
            setting->value_count = 2;
            setting->value_range[0].u32 = default_int_range[0];
            setting->value_range[1].u32 = default_int_range[1];
            value.u32 = setting->value_range[0].u32 + (get_random_word() % (setting->value_range[1].u32 - setting->value_range[0].u32 + 1));
        }
        // other types
        if (setting->vtype == TYPE_FLOAT) {
            // assert(setting->value_count == 2);
            if (setting->value_count == 1) {
                value.f = setting->value_range[0].f;
            }
            else if (setting->value_count == 2) {
                // Coverage-guided fuzzing (DESIGN.md Phase 1): occasionally seed a
                // special/boundary value (NaN/Inf/0/+-FLT_MAX/...) so isnan/isinf and
                // threshold guards get exercised; otherwise a uniform [lo,hi] sample.
                float sv;
                if (coverage_pick_special_float(&sv)) {
                    value.f = sv;
                } else {
                    value.f = get_random_float(setting->value_range[0].f, setting->value_range[1].f);
                }
            } else {
                fprintf(stderr, "[VI randargs] Invalid value count for float type in setting '%s'\n", setting->name);
                perror("randargs");
                exit(EXIT_FAILURE);
            }
        } else if (setting->vtype == TYPE_DOUBLE) {
            // assert(setting->value_count == 2);
            if (setting->value_count == 1) {
                value.d = setting->value_range[0].d;
            }
            else if (setting->value_count == 2) {
                // Generate a random double in the range
                value.d = get_random_double(setting->value_range[0].d, setting->value_range[1].d);
                printf("[VI randargs] generated double value %g for setting '%s'\n", value.d, setting->name);
            } else {
                fprintf(stderr, "[VI randargs] Invalid value count for double type in setting '%s'\n", setting->name);
                perror("randargs");
                exit(EXIT_FAILURE);
            }
        } else if (setting->vtype == TYPE_UINT32) {
            if (setting->value_count == 1) {
                value.u32 = setting->value_range[0].u32;
            }
            else if (setting->value_count == 2) {
                // Generate a random uint32 in the range
                value.u32 = setting->value_range[0].u32 + (get_random_word() % (setting->value_range[1].u32 - setting->value_range[0].u32 + 1));
            } else if (setting->value_count == 0 && setting->is_pointer == IS_PTR_TRUE) { // check is_pointer here
                // handle struct allocation
                setting->value_count = 1;
                setting->value_range[0].u32 = cur_ptr_addr;
                assert(setting->sz == 4); // 4 bytes addr size in arm
                struct NestedStruct* new_struct = ns_new_ptr(cur_ptr_addr, setting->sz, true);
                cur_ptr_addr += STRUCT_MEM_SIZE; // use (hopefully large enough) fixed size
                allocated_structs[allocated_struct_count++] = new_struct;
                value.u32 = setting->value_range[0].u32;
            }
            else if (setting->value_count == 0 && setting->is_pointer == IS_PTR_UNKNOWN) {
                // treat as pointer first
                // setting->is_pointer = IS_PTR_TRUE;
                // handle struct allocation
                setting->value_count = 1;
                setting->value_range[0].u32 = cur_ptr_addr;
                assert(setting->sz == 4); // 4 bytes addr size in arm
                struct NestedStruct* new_struct = ns_new_ptr(cur_ptr_addr, setting->sz, false);
                cur_ptr_addr += STRUCT_MEM_SIZE; // use (hopefully large enough) fixed size
                allocated_structs[allocated_struct_count++] = new_struct;
                value.u32 = setting->value_range[0].u32;
            } else {
                fprintf(stderr, "[VI randargs] Invalid value count for uint32 type in setting '%s'\n", setting->name);
                perror("randargs");
                exit(EXIT_FAILURE);
            }
        } else if (setting->vtype == TYPE_UINT16 || setting->vtype == TYPE_UINT8) {
            if (setting->value_count == 1) {
                value.u32 = setting->value_range[0].u32;
            }
            else if (setting->value_count == 2) {
                // Generate a random uint32 in the range
                value.u32 = setting->value_range[0].u32 + (get_random_word() % (setting->value_range[1].u32 - setting->value_range[0].u32 + 1));
            }
            else {
                fprintf(stderr, "[VI randargs] Invalid value count for uint8/16 type in setting '%s'\n", setting->name);
                perror("randargs");
                exit(EXIT_FAILURE);
            }
        } else {
            fprintf(stderr, "[VI randargs] Unsupported value type in setting '%s'\n", setting->name);
            // perror("randargs");
            exit(EXIT_FAILURE);
        }

        // set value to corresponding location
        if (setting->location_type == TYPE_REG) {
            if (setting->vtype == TYPE_FLOAT) {
                printf("[VI randargs] setting register %s to value: %g\n", setting->reg, value.f);
            } else if (setting->vtype == TYPE_DOUBLE) {
                printf("[VI randargs] setting register %s to value: %g\n", setting->reg, value.d);
            } else if (setting->vtype == TYPE_UINT32) {
                printf("[VI randargs] setting register %s to value: %u\n", setting->reg, value.u32);
            }
            else {
                fprintf(stderr, "[VI randargs] Unsupported value type for register in setting '%s'\n", setting->name);
                perror("randargs");
                exit(EXIT_FAILURE);
            }
            if (setting->vtype == TYPE_FLOAT) {
                // single-precision sN: remap to its double register + write only the
                // correct 4-byte half (preserving the sibling lane). The raw path below
                // writes the wrong double for any sN except s0 -- see qemu_set_register_32.
                qemu_set_register_32(get_reg_by_name(setting->reg), value.u32);
            } else {
                // GPR (and TYPE_DOUBLE dN -- single-precision firmware here, so dN does
                // not occur; if it ever does it needs an analogous qemu_set_register_64).
                qemu_plugin_set_register((uint8_t *)&value, get_reg_by_name(setting->reg));
            }
        } else if (setting->location_type == TYPE_ADDR) {
            if (setting->vtype == TYPE_FLOAT) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 4);
                printf("[VI randargs] writing float value %g to memory address: 0x%lx\n", value.f, setting->addr);
            } else if (setting->vtype == TYPE_DOUBLE) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 8);
                printf("[VI randargs] writing double value %g to memory address: 0x%lx\n", value.d, setting->addr);
            } else if (setting->vtype == TYPE_UINT32) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 4);
                printf("[VI randargs] writing uint32 value %u to memory address: 0x%lx\n", value.u32, setting->addr);
            }
            else if (setting->vtype == TYPE_UINT16) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 2);
                printf("[VI randargs] writing uint16 value %u to memory address: 0x%lx\n", (uint16_t)(value.u32 & 0xFFFF), setting->addr);
            }
            else if (setting->vtype == TYPE_UINT8) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 1);
                printf("[VI randargs] writing uint8 value %u to memory address: 0x%lx\n", (uint8_t)(value.u32 & 0xFF), setting->addr);
            }
            else {
                fprintf(stderr, "[VI randargs] Unsupported value type for memory in setting '%s'\n", setting->name);
                perror("randargs");
                exit(EXIT_FAILURE);
            }
            // qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 4);
        } else {
            fprintf(stderr, "[VI randargs] Unsupported location type in setting '%s'\n", setting->name);
            perror("randargs");
            exit(EXIT_FAILURE);
        }

        // log values
        // logged_in_values[i] = value;
        setting->concrete_value = value; // use a field in ArgSetting to store concrete input value instead
    }
}

// set args at func start to trigger specific execution paths, used for sub-semantics recovery to set specific args for different sub-semantics
static void setargs(unsigned int cpu_index, void *udata) {
    uint64_t pc = *(uint64_t *)udata;
    printf("[VI setargs] Current PC: 0x%08lx\n", pc);

    // New function invocation: reset the per-invocation visit counters used to
    // gate the loop-iteration sub-semantic triggers.
    randargs_visit_counter = 0;
    logrets_visit_counter = 0;

    // set stack pointer
    ValueUnion sp_val;
    sp_val.u32 = stack_ptr;
    qemu_plugin_set_register((uint8_t *)&sp_val, ARM_V7M_REG_R13);

    for (size_t i = 0; i < func_start_arg_count; i++) {
        ArgSetting *setting = &func_start_arg_settings[i];
        // use range to generate random value
        ValueUnion value = setting->concrete_value;
        // set value to corresponding location
        if (setting->location_type == TYPE_REG) {
            if (setting->vtype == TYPE_FLOAT) {
                printf("[VI setargs] setting register %s to value: %g\n", setting->reg, value.f);
            } else if (setting->vtype == TYPE_DOUBLE) {
                printf("[VI setargs] setting register %s to value: %g\n", setting->reg, value.d);
            } else if (setting->vtype == TYPE_UINT32) {
                printf("[VI setargs] setting register %s to value: %u\n", setting->reg, value.u32);
            }
            else {
                fprintf(stderr, "[VI setargs] Unsupported value type for register in setting '%s'\n", setting->name);
                exit(EXIT_FAILURE);
            }
            if (setting->vtype == TYPE_FLOAT) {
                // single-precision sN: remap to its double register + write only the
                // correct 4-byte half (preserving the sibling lane). The raw path below
                // writes the wrong double for any sN except s0 -- see qemu_set_register_32.
                qemu_set_register_32(get_reg_by_name(setting->reg), value.u32);
            } else {
                // GPR (and TYPE_DOUBLE dN -- single-precision firmware here, so dN does
                // not occur; if it ever does it needs an analogous qemu_set_register_64).
                qemu_plugin_set_register((uint8_t *)&value, get_reg_by_name(setting->reg));
            }
        } else if (setting->location_type == TYPE_ADDR) {
            if (setting->vtype == TYPE_FLOAT) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 4);
                printf("[VI setargs] writing float value %g to memory address: 0x%lx\n", value.f, setting->addr);
            } else if (setting->vtype == TYPE_DOUBLE) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 8);
                printf("[VI setargs] writing double value %g to memory address: 0x%lx\n", value.d, setting->addr);
            } else if (setting->vtype == TYPE_UINT32) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 4);
                printf("[VI setargs] writing uint32 value %u to memory address: 0x%lx\n", value.u32, setting->addr);
            }
            else if (setting->vtype == TYPE_UINT16) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 2);
                printf("[VI setargs] writing uint16 value %u to memory address: 0x%lx\n", (uint16_t)(value.u32 & 0xFFFF), setting->addr);
            }
            else if (setting->vtype == TYPE_UINT8) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 1);
                printf("[VI setargs] writing uint8 value %u to memory address: 0x%lx\n", (uint8_t)(value.u32 & 0xFF), setting->addr);
            }
            else {
                fprintf(stderr, "[VI setargs] Unsupported value type for memory in setting '%s'\n", setting->name);
                exit(EXIT_FAILURE);
            }
            // qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 4);
        } else {
            fprintf(stderr, "[VI setargs] Unsupported location type in setting '%s'\n", setting->name);
            exit(EXIT_FAILURE);
        }

        // log values
        // logged_in_values[i] = value;
        setting->concrete_value = value; // use a field in ArgSetting to store concrete input value instead
    }
}

static int sub_semantic_cur_iteration = 0;

static void randargs_sub_semantics(unsigned int cpu_index, void *udata) {
    // print pc for debugging
    // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15); // this is not accurate sometimes
    uint64_t pc = *(uint64_t *)udata;

    // Visit gate: this address may be a loop body hit multiple times; only
    // (re-)randomize on the configured visit. Count every visit, act on one.
    randargs_visit_counter++;
    if (randargs_target_visit != 0 && randargs_visit_counter != randargs_target_visit) {
        return;
    }
    printf("[VI randargs_sub_semantics] Current PC: 0x%08lx (visit %d)\n", pc, randargs_visit_counter);

    sub_semantic_reached = true;
    sub_semantic_reach_time = current_timestamp_ms();

    if (sub_semantic_cur_iteration >= MAX_FUZZ_ITERATIONS) {
        printf("[VI randargs_sub_semantics] reached max fuzzing iterations %d, dump existing path logs and exiting\n", MAX_FUZZ_ITERATIONS);
        exit(0);
    }
    if (check_sub_semantic_log_size_and_dump(dump_path)) {
        printf("[VI randargs_sub_semantics] log finished, dump related path logs\n");
        unsigned long long fuzzing_end_time = current_timestamp_ms();
        printf("[VI randargs_sub_semantics] total fuzzing time: %f sec\n", (double)(fuzzing_end_time - sub_semantic_reach_time) / 1000.0);
        exit(0);
    }
    if (sub_semantic_cur_iteration == 0) {
        clear_all_sub_semantic_logs();
        // // heristic: set all register args as sub_semantic inputs
        // for (size_t i = 0; i < arg_count; i++) {
        //     ArgSetting *setting = &arg_settings[i];
        //     if (setting->location_type == TYPE_REG) {
        //         setting->is_sub_semantic_input = true;
        //     }
        // }
        for (size_t i = 0; i < ret_count; i++) {
            RetSetting *setting = &ret_settings[i];
            setting->written_time = 10000 + i;
        }
        cur_timestamp = 0;
    }
    else if (sub_semantic_cur_iteration == 1) {
        // clear sub_semantic logs, mem callbacks may change the setting in the first iteration (sub_semantic_cur_iteration == 0)
        clear_all_sub_semantic_logs();
    }
    else {
        record_sub_semantic_trace_values();
    }

    // set stack pointer
    // ValueUnion sp_val;
    // sp_val.u32 = stack_ptr;
    // qemu_plugin_set_register((uint8_t *)&sp_val, ARM_V7M_REG_R13);
    // reset stack var write tracking
    stack_var_write_count = 0;

    // // increment non_ptr_iters for all unknown pointer args
    // for (size_t i = 0; i < arg_count; i++) {
    //     ArgSetting *setting = &arg_settings[i];
    //     if (setting->vtype == TYPE_UINT32 && setting->is_pointer == IS_PTR_UNKNOWN) {
    //         setting->non_ptr_iters++;
    //         printf("[VI randargs] unknown pointer arg '%s' has been tried %d times\n", setting->name, setting->non_ptr_iters);
    //         if (setting->non_ptr_iters > NON_PTR_ITER_MAX) {
    //             printf("[VI randargs] fixing unknown pointer arg '%s' to non-pointer integer after %d tries\n", setting->name, setting->non_ptr_iters);
    //             if (setting->location_type == TYPE_ADDR) { // heuristic: all 4 bytes struct are floats (todo: improve)
    //                 // set to float
    //                 setting->is_pointer = IS_PTR_FALSE;
    //                 setting->vtype = TYPE_FLOAT;
    //                 setting->value_count = 2;
    //                 setting->value_range[0].f = default_float_range[0];
    //                 setting->value_range[1].f = default_float_range[1];

    //                 clear_all_path_logs();
    //             }
    //             else if (setting->location_type == TYPE_REG) { // float regs are identified statically
    //                 // set to float
    //                 setting->is_pointer = IS_PTR_FALSE;
    //                 setting->vtype = TYPE_UINT32;
    //                 setting->value_count = 2;
    //                 setting->value_range[0].u32 = default_int_range[0];
    //                 setting->value_range[1].u32 = default_int_range[1];
    //                 clear_all_path_logs();
    //             }
    //             print_arg_settings(); // for debug
    //         }
    //     }
    // }

    // current_path_len = 0;

    // main logic: rand variables and set registers/memory
    // is_logging_valid = true;
    sub_semantic_cur_iteration++;
    printf("[VI randargs_sub_semantics] iteration %d: arg_count = %zu, ret_count = %zu\n", sub_semantic_cur_iteration, arg_count, ret_count);
    // iterate arg_settings
    for (size_t i = 0; i < arg_count; i++) {
        ArgSetting *setting = &arg_settings[i];
        // use range to generate random value
        ValueUnion value;
        // potential pointer types
        if (setting->vtype == TYPE_UNKNOWN) { // only for potential pointer types, size = 4
            // error
            fprintf(stderr, "[VI randargs_sub_semantics] Encountered unknown type in setting '%s', which is unsupported in sub_semantic fuzzing\n", setting->name);
            exit(EXIT_FAILURE);
        }
        // other types
        if (setting->vtype == TYPE_FLOAT) {
            // assert(setting->value_count == 2);
            if (setting->value_count == 1) {
                value.f = setting->value_range[0].f;
            }
            else if (setting->value_count == 2) {
                // Generate a random float in the range
                value.f = get_random_float(setting->value_range[0].f, setting->value_range[1].f);
            } else {
                // fprintf(stderr, "[VI randargs_sub_semantics] Invalid value count for float type in setting '%s'\n", setting->name);
                // exit(EXIT_FAILURE);
                // default to [0.5, 5.0] for imtermedate flaot input vars
                setting->value_count = 2;
                setting->value_range[0].f = default_float_range[0];
                setting->value_range[1].f = default_float_range[1];
                value.f = get_random_float(setting->value_range[0].f, setting->value_range[1].f);
            }
        } else if (setting->vtype == TYPE_DOUBLE) {
            // assert(setting->value_count == 2);
            if (setting->value_count == 1) {
                value.d = setting->value_range[0].d;
            }
            else if (setting->value_count == 2) {
                // Generate a random double in the range
                value.d = get_random_double(setting->value_range[0].d, setting->value_range[1].d);
                printf("[VI randargs_sub_semantics] generated double value %g for setting '%s'\n", value.d, setting->name);
            } else {
                // fprintf(stderr, "[VI randargs_sub_semantics] Invalid value count for double type in setting '%s'\n", setting->name);
                // exit(EXIT_FAILURE);
                // default to [0.5, 5.0] for imtermedate double input vars
                setting->value_count = 2;
                setting->value_range[0].d = default_float_range[0];
                setting->value_range[1].d = default_float_range[1];
                value.d = get_random_double(setting->value_range[0].d, setting->value_range[1].d);
            }
        } else if (setting->vtype == TYPE_UINT32 || setting->vtype == TYPE_UINT16 || setting->vtype == TYPE_UINT8) {
            // Integer variables in sub-semantic fuzzing are control flow / array
            // indices / pointer-derived scalars (e.g. _index, _size, _count, loop
            // counters), not data inputs. Randomizing them changes which memory slot
            // an indexed load reads and how many loop iterations run, making a stage's
            // output depend on uncaptured state (unfittable). So never set them here --
            // keep the concrete value setargs already wrote, so addressing/control flow
            // stay stable and only the float data is fuzzed.
            continue;
        } else {
            fprintf(stderr, "[VI randargs_sub_semantics] Unsupported value type in setting '%s'\n", setting->name);
            // perror("randargs");
            exit(EXIT_FAILURE);
        }

        // set value to corresponding location
        if (setting->location_type == TYPE_REG) {
            if (setting->vtype == TYPE_FLOAT) {
                printf("[VI randargs_sub_semantics] setting register %s to value: %g\n", setting->reg, value.f);
            } else if (setting->vtype == TYPE_DOUBLE) {
                printf("[VI randargs_sub_semantics] setting register %s to value: %g\n", setting->reg, value.d);
            } else if (setting->vtype == TYPE_UINT32) {
                printf("[VI randargs_sub_semantics] setting register %s to value: %u\n", setting->reg, value.u32);
            }
            else {
                fprintf(stderr, "[VI randargs_sub_semantics] Unsupported value type for register in setting '%s'\n", setting->name);
                exit(EXIT_FAILURE);
            }
            if (setting->vtype == TYPE_FLOAT) {
                // single-precision sN: remap to its double register + write only the
                // correct 4-byte half (preserving the sibling lane). The raw path below
                // writes the wrong double for any sN except s0 -- see qemu_set_register_32.
                qemu_set_register_32(get_reg_by_name(setting->reg), value.u32);
            } else {
                // GPR (and TYPE_DOUBLE dN -- single-precision firmware here, so dN does
                // not occur; if it ever does it needs an analogous qemu_set_register_64).
                qemu_plugin_set_register((uint8_t *)&value, get_reg_by_name(setting->reg));
            }
        } else if (setting->location_type == TYPE_ADDR) {
            if (setting->vtype == TYPE_FLOAT) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 4);
                printf("[VI randargs_sub_semantics] writing float value %g to memory address: 0x%lx\n", value.f, setting->addr);
            } else if (setting->vtype == TYPE_DOUBLE) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 8);
                printf("[VI randargs_sub_semantics] writing double value %g to memory address: 0x%lx\n", value.d, setting->addr);
            } else if (setting->vtype == TYPE_UINT32) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 4);
                printf("[VI randargs_sub_semantics] writing uint32 value %u to memory address: 0x%lx\n", value.u32, setting->addr);
            }
            else if (setting->vtype == TYPE_UINT16) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 2);
                printf("[VI randargs_sub_semantics] writing uint16 value %u to memory address: 0x%lx\n", (uint16_t)(value.u32 & 0xFFFF), setting->addr);
            }
            else if (setting->vtype == TYPE_UINT8) {
                qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 1);
                printf("[VI randargs_sub_semantics] writing uint8 value %u to memory address: 0x%lx\n", (uint8_t)(value.u32 & 0xFF), setting->addr);
            }
            else {
                fprintf(stderr, "[VI randargs_sub_semantics] Unsupported value type for memory in setting '%s'\n", setting->name);
                exit(EXIT_FAILURE);
            }
            // qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 4);
        } else {
            fprintf(stderr, "[VI randargs_sub_semantics] Unsupported location type in setting '%s'\n", setting->name);
            exit(EXIT_FAILURE);
        }

        // log values
        // logged_in_values[i] = value;
        setting->concrete_value = value; // use a field in ArgSetting to store concrete input value instead
    }
}

// --------------------------------------------------------------------------------------
// logrets
// --------------------------------------------------------------------------------------
static void logrets(unsigned int cpu_index, void *udata) {
    // This function is called when the magic instruction is executed
    // It will dump the latest return values to the log buffer
    printf("[VI logrets] logrets called, dumping latest return values.\n");
    for (size_t i = 0; i < ret_count; i++) {
        RetSetting *setting = &ret_settings[i];
        ValueUnion value;
        if (setting->location_type == TYPE_REG) {
            // Log register value
            // value.u32 = qemu_get_register(get_reg_by_name(setting->reg));
            if (setting->vtype == TYPE_FLOAT) {
                value.u32 = qemu_get_register_32(get_reg_by_name(setting->reg)); // just copy the bytes
                printf("[VI logrets] float register %s: %g\n", setting->reg, value.f);
            } else if (setting->vtype == TYPE_UINT32) {
                value.u32 = qemu_get_register_32(get_reg_by_name(setting->reg));
                printf("[VI logrets] uint32 register %s: %u\n", setting->reg, value.u32);
            } else if (setting->vtype == TYPE_DOUBLE) {
                value.u64 = qemu_get_register_64(get_reg_by_name(setting->reg)); // just copy the bytes
                printf("[VI logrets] double register %s: %g\n", setting->reg, value.d);
            } else {
                fprintf(stderr, "[VI logrets] Unsupported value type for register in setting '%s'\n", setting->name);
                perror("logrets");
                exit(EXIT_FAILURE);
            }   
        } else if (setting->location_type == TYPE_ADDR) {
            // Log memory value
            qemu_plugin_read_memory(setting->addr, (uint8_t *)&value, 4);
            if (setting->vtype == TYPE_FLOAT) {
                printf("[VI logrets] memory address 0x%lx: %g\n", setting->addr, value.f);
            } else {
                printf("[VI logrets] memory address 0x%lx: %u\n", setting->addr, value.u32);
            }
        } else {
            fprintf(stderr, "[VI logrets] Unsupported location type in setting '%s'\n", setting->name);
            perror("logrets");
            exit(EXIT_FAILURE);
        }

        // log out values
        // logged_out_values[i] = value;
        setting->concrete_value = value; // use a field in RetSetting to store concrete output value instead
    }
}

static void logrets_sub_semantics(unsigned int cpu_index, void *udata) {
    // This function is called when the magic instruction is executed
    // It will dump the latest return values to the log buffer

    // Visit gate: the end address may be a loop body hit multiple times; only
    // capture (and reset) on the configured visit.
    logrets_visit_counter++;
    if (logrets_target_visit != 0 && logrets_visit_counter != logrets_target_visit) {
        return;
    }
    printf("[VI logrets_sub_semantics] logrets_sub_semantics called (visit %d), dumping latest return values.\n", logrets_visit_counter);
    print_ret_settings(ret_settings, ret_count);
    for (size_t i = 0; i < ret_count; i++) {
        RetSetting *setting = &ret_settings[i];
        ValueUnion value;
        if (setting->location_type == TYPE_REG) {
            // Log register value
            // value.u32 = qemu_get_register(get_reg_by_name(setting->reg));
            if (setting->vtype == TYPE_FLOAT) {
                value.u32 = qemu_get_register_32(get_reg_by_name(setting->reg)); // just copy the bytes
                printf("[VI logrets_sub_semantics] float register %s: %g\n", setting->reg, value.f);
            } else if (setting->vtype == TYPE_UINT32) {
                value.u32 = qemu_get_register_32(get_reg_by_name(setting->reg));
                printf("[VI logrets_sub_semantics] uint32 register %s: %u\n", setting->reg, value.u32);
            } else if (setting->vtype == TYPE_DOUBLE) {
                value.u64 = qemu_get_register_64(get_reg_by_name(setting->reg)); // just copy the bytes
                printf("[VI logrets_sub_semantics] double register %s: %g\n", setting->reg, value.d);
            } else {
                fprintf(stderr, "[VI logrets_sub_semantics] Unsupported value type for register in setting '%s'\n", setting->name);
                exit(EXIT_FAILURE);
            }
        } else if (setting->location_type == TYPE_ADDR) {
            // Log memory value
            qemu_plugin_read_memory(setting->addr, (uint8_t *)&value, 4);
            if (setting->vtype == TYPE_FLOAT) {
                printf("[VI logrets_sub_semantics] memory address 0x%lx: %g\n", setting->addr, value.f);
            } else {
                printf("[VI logrets_sub_semantics] memory address 0x%lx: %u\n", setting->addr, value.u32);
            }
        } else {
            fprintf(stderr, "[VI logrets_sub_semantics] Unsupported location type in setting '%s'\n", setting->name);
            exit(EXIT_FAILURE);
        }

        // log out values
        // logged_out_values[i] = value;
        setting->concrete_value = value; // use a field in RetSetting to store concrete output value instead
    }

    // End of this stage's execution: reset PC back to the function start to re-run
    // for the next fuzzing iteration. This used to be a modifier inline-update at the
    // end address, but an inline update fires on every visit of a loop-body address
    // and would reset on the wrong pass -- doing it here keeps it visit-gated.
    ValueUnion func_start_pc;
    func_start_pc.u32 = func_start;
    qemu_plugin_set_register((uint8_t *)&func_start_pc, ARM_V7M_REG_R15);
    qemu_plugin_vcpu_exit_tb_now();
}

// --------------------------------------------------------------------------------------
// clearpathlogs, logbbstart
// --------------------------------------------------------------------------------------
static void clearpathlogs(unsigned int cpu_index, void *udata) {
    // Clear all path logs
    clear_all_path_logs();
}

/* Demote one discovered scalar field (by arg index) from suspected-pointer to
 * a small int, so a loop bound / array index stays bounded. */
static void demote_field_to_int(int idx) {
    ArgSetting *setting = &arg_settings[idx];
    setting->is_pointer = IS_PTR_FALSE;
    setting->vtype = TYPE_UINT32;
    setting->value_count = 2;
    setting->value_range[0].u32 = demote_int_range[0];
    setting->value_range[1].u32 = demote_int_range[1];
    printf("[WATCHDOG] demoting field '%s' (was unknown pointer) to int range [%u, %u]\n",
           setting->name, demote_int_range[0], demote_int_range[1]);
}

/*
 * Watchdog handler. Demotes still-IS_PTR_UNKNOWN 4-byte scalar fields (loop
 * bounds / array indices seeded with huge pointer-arena values) to small ints,
 * then restarts the invocation from func_start. Confirmed pointers (IS_PTR_TRUE,
 * promoted the moment their region is dereferenced) are never touched.
 *
 * Two demotion strategies, by trigger:
 *
 *  - spare_last_unknown == false  (basic-block runaway): demote ONE field, the
 *    earliest-discovered unknown (FIFO). A pure runaway loop recovers cleanly
 *    and the watchdog can fire again for the next field, so we demote the
 *    minimum. The loop bound is typically read at/near the top of the function.
 *
 *  - spare_last_unknown == true  (instruction-budget / fault): the trigger was a
 *    wild memory access (e.g. _array[_index] with a still-huge _index) that
 *    bus-faulted into a spinning handler. Recovery (PC reset) works ONCE, but a
 *    SECOND hardware fault while the first is active locks up the Cortex-M core
 *    -- and QEMU's NVIC active-exception state can't be reliably cleared from a
 *    plugin. So we must avoid a second fault: demote ALL unknown scalars in one
 *    shot EXCEPT the most-recently-discovered one, which is almost always the
 *    base pointer of the faulting deref (compiled code loads the base register
 *    just before the indexed access). One fault -> one clean retry with every
 *    index/count bounded and the base pointer intact (it then gets dereferenced
 *    in-arena and promoted normally). If there is only one unknown, demote it.
 *
 * If no unknown scalar remains, we cannot resolve it here, so we salvage what
 * was collected and exit rather than spin until the outer timeout.
 */
static void trigger_inf_exe_watchdog(const char *reason, bool spare_last_unknown) {
    // collect IS_PTR_UNKNOWN args
    int unknowns[MAX_ARGS];
    int n_unknown = 0;
    for (size_t i = 0; i < arg_count; i++) {
        ArgSetting *setting = &arg_settings[i];
        if (setting->vtype == TYPE_UINT32 && setting->is_pointer == IS_PTR_UNKNOWN) {
            unknowns[n_unknown++] = (int)i;
        }
    }

    if (n_unknown == 0) {
        printf("[WATCHDOG] %s, but no unknown scalar field left to demote; "
               "dumping collected logs and exiting\n", reason);
        dump_existing_path_logs(dump_path);
        exit(0);
    }

    int demote_count; /* demote unknowns[0 .. demote_count) */
    if (spare_last_unknown && n_unknown >= 2) {
        demote_count = n_unknown - 1; /* spare the last (likely base pointer) */
    } else if (spare_last_unknown) {
        demote_count = n_unknown;     /* only one unknown -> demote it */
    } else {
        demote_count = 1;             /* BB runaway: FIFO, one at a time */
    }

    printf("[WATCHDOG] %s: demoting %d of %d unknown scalar field(s) and retrying\n",
           reason, demote_count, n_unknown);
    for (int k = 0; k < demote_count; k++) {
        demote_field_to_int(unknowns[k]);
    }
    if (spare_last_unknown && n_unknown >= 2) {
        printf("[WATCHDOG] sparing last-discovered unknown '%s' (likely base pointer)\n",
               arg_settings[unknowns[n_unknown - 1]].name);
    }

    /* Arg settings changed -> previously logged traces are inconsistent. */
    clear_all_path_logs();
    is_logging_valid = false;
    current_path_len = 0;
    iter_insn_count = 0;

    /* Restart this invocation from the function entry. */
    ValueUnion func_start_pc;
    func_start_pc.u32 = func_start;
    qemu_plugin_set_register((uint8_t *)&func_start_pc, ARM_V7M_REG_R15);
    qemu_plugin_vcpu_exit_tb_now();
}

/*
 * Instruction-budget watchdog (see GLOBAL_EXEC_WATCHDOG_THRESHOLD). Registered on EVERY
 * executed instruction -- including out-of-function code -- so it catches cases
 * the basic-block watchdog cannot: a wild memory access (e.g. _array[_index]
 * with a still-huge _index) that bus-faults into a default handler which just
 * spins `b .`. That handler hits no instrumented basic block and touches no
 * tracked memory, so only a raw instruction count since function entry detects
 * it. Resolution is the same demote-one-then-retry as the BB watchdog: bounding
 * the offending index/count field stops the fault, and a genuine pointer field
 * (e.g. _array) is spared because once the index is small the read lands back in
 * its arena and the field gets promoted before we would demote it.
 */
static void count_insn_cb(unsigned int cpu_index, void *udata) {
    if (!function_reached) return;
    if (++iter_insn_count > GLOBAL_EXEC_WATCHDOG_THRESHOLD) {
        trigger_inf_exe_watchdog("instruction budget exceeded (suspected fault-spin or runaway)", true);
    }
}

static void logbbstart(unsigned int cpu_index, void *udata) {
    // get pc vlue
    // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15); // this is not accurate sometimes
    uint64_t pc = *(uint64_t *)udata;

    // Edge/block coverage. udata points into bb_starts[], so the block index is free.
    // Marked here -- before the watchdog early-return below -- so a runaway loop still
    // contributes the coverage of the blocks it was executing, and marked
    // unconditionally so an edge reached by a later-invalidated sample still counts as
    // "executed" (edge_rec, the committed subset, is marked separately at record time).
    int bb_idx = (int)((unsigned long *)udata - bb_starts);
    if (bb_idx >= 0 && bb_idx < bb_count) {
        bb_hit[bb_idx] = 1;
        if (have_last_bb && last_bb_idx >= 0 && last_bb_idx < bb_count) {
            edge_exec[last_bb_idx][bb_idx] = 1;
        }
        last_bb_idx = bb_idx;
        have_last_bb = true;
    }

    // Runaway-loop watchdog: a misclassified scalar loop bound (seeded with a
    // huge pointer-arena value) would loop here forever and overflow
    // current_path. Bail out and demote the offending field before that.
    if (current_path_len >= WATCHDOG_PATH_THRESHOLD) {
        trigger_inf_exe_watchdog("basic-block budget exceeded (runaway loop)", false);
        return;
    }
    current_path[current_path_len++] = (uint64_t)pc;
}

// --------------------------------------------------------------------------------------
// memory callbacks
// --------------------------------------------------------------------------------------
static void update_addr_var_mem_cb(unsigned int vcpu_index, qemu_plugin_meminfo_t info, uint64_t vaddr, void *udata) {
    if (!function_reached) return;

    unsigned sz_shift = qemu_plugin_mem_size_shift(info);  // 0=8b,1=16b,2=32b,3=64b,...
    unsigned sz_bytes = 1u << sz_shift; // 1,2,4,8 bytes
    int is_store = qemu_plugin_mem_is_store(info);

    // check pc
    // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
    uint64_t pc = *(uint64_t *)udata;
    fprintf(stdout, "[MEMCB update_addr_var_mem_cb] pc=0x%08lx, access=0x%08" PRIx64 " (%u-byte %s)\n",
            pc, vaddr, sz_bytes, is_store ? "STORE" : "LOAD"); // warn: this could still be the start of tb
    // TODO: handle non-fp memory variables
    // check whether the address is in arg_settings
    // Iterate through arg_settings to find a match
    bool found_arg_match = false;
    for (size_t i = 0; i < arg_count; i++) {
        ArgSetting *setting = &arg_settings[i];
        // if (setting->location_type == TYPE_ADDR && setting->addr == vaddr) {
        if (setting->location_type == TYPE_ADDR && same_mem_locs(setting, vaddr, sz_bytes)) {
            found_arg_match = true;
        }
    }
    if (!found_arg_match) {
        printf("[MEMCB update_addr_var_mem_cb] No matching arg setting for address 0x%lx, creating new arg setting\n", vaddr);
        // create new arg setting
        if (arg_count >= MAX_ARGS) {
            fprintf(stderr, "Maximum argument settings reached, cannot add new setting for address 0x%lx\n", vaddr);
            exit(EXIT_FAILURE);
        }
        int parent_allocated_struct_idx = find_parent_struct_by_addr(vaddr, sz_bytes);
        if (parent_allocated_struct_idx >= 0) { // struct variable
            /*
              Heuristic:
                for e2e analysis, treat all struct variables as input variables first, and create arg settings for them
                fine grained analysis will be done for sub-semantic analysis
            */
            assert(parent_allocated_struct_idx < allocated_struct_count);
            unsigned long parent_allocated_addr = allocated_structs[parent_allocated_struct_idx]->loc.addr;
            printf("[MEMCB update_addr_var_mem_cb] Found parent struct allocated at address 0x%lx\n", parent_allocated_addr);
            // assert(allocated_structs[parent_allocated_struct_idx]->is_pointer);
            size_t parent_ptr_size = allocated_structs[parent_allocated_struct_idx]->size;
            int parent_arg_setting_idx = find_ptr_arg_by_addr(parent_allocated_addr, parent_ptr_size, arg_settings, &arg_count);
            assert(parent_arg_setting_idx >= 0 && parent_arg_setting_idx < arg_count);
            struct NestedStruct *parent_struct = allocated_structs[parent_allocated_struct_idx];
            parent_struct->is_pointer = IS_PTR_TRUE; // mark as pointer

            // create new arg setting based on parent
            size_t offset = vaddr - parent_allocated_addr;
            ArgSetting *parent_setting = &arg_settings[parent_arg_setting_idx];
            parent_setting->is_pointer = IS_PTR_TRUE; // mark as pointer
            ArgSetting *new_setting = &arg_settings[arg_count++];
            init_arg_setting(new_setting);
            // snprintf(new_setting->name, sizeof(new_setting->name), "%s_off_%zu", parent_setting->name, offset);
            snprintf(new_setting->name, sizeof(new_setting->name), "arg%zu", arg_count); // just use arg_idx as name for simplicity
            new_setting->location_type = TYPE_ADDR;
            new_setting->addr = vaddr;
            new_setting->sz = sz_bytes;
            strncpy(new_setting->base_ptr_var_name, parent_setting->name, sizeof(new_setting->base_ptr_var_name) - 1);
            new_setting->base_ptr_offset = offset;
            // new_setting->vtype = TYPE_FLOAT;
            if (sz_bytes == 4) {
                new_setting->vtype = TYPE_UINT32; // treat as (unknown) pointer first
                new_setting->is_pointer = IS_PTR_UNKNOWN;
                new_setting->non_ptr_iters = 0;
                // handle struct allocation
                new_setting->value_count = 1;
                new_setting->value_range[0].u32 = cur_ptr_addr;
                // assert(new_setting->sz == 4); // 4 bytes addr size in arm
                struct NestedStruct* new_struct = ns_new_ptr(cur_ptr_addr, new_setting->sz, false);
                cur_ptr_addr += STRUCT_MEM_SIZE; // use (hopefully large enough) fixed size
                allocated_structs[allocated_struct_count++] = new_struct;
            } else if (sz_bytes == 2) {
                new_setting->vtype = TYPE_UINT16; // must be int
                new_setting->is_pointer = IS_PTR_FALSE; // 2-byte int not pointer
                new_setting->value_count = 2;
                new_setting->value_range[0].u32 = default_int_range[0];
                new_setting->value_range[1].u32 = default_int_range[1];
            } else if (sz_bytes == 1) {
                new_setting->vtype = TYPE_UINT8; // must be int
                new_setting->is_pointer = IS_PTR_FALSE; // 1-byte int not pointer
                new_setting->value_count = 2;
                new_setting->value_range[0].u32 = default_int_range[0];
                new_setting->value_range[1].u32 = default_int_range[1];
            } else {
                fprintf(stderr, "Unsupported size %u bytes for new arg setting at address 0x%lx\n", sz_bytes, vaddr);
                exit(EXIT_FAILURE);
            }

            printf("[MEMCB update_addr_var_mem_cb] logging invalidated: created new float arg setting '%s' for address 0x%lx\n", new_setting->name, vaddr);
            is_logging_valid = false;
            // set pc back to function start
            ValueUnion func_start_pc;
            func_start_pc.u32 = func_start;
            qemu_plugin_set_register((uint8_t *)&func_start_pc, ARM_V7M_REG_R15);
            // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
            // printf("[MEMCB update_addr_var_mem_cb] set PC back to function start: 0x%08x\n", pc);
            qemu_plugin_vcpu_exit_tb_now();
            // return;
        } else { // stack variables / code section variables (constants)
            /*
              Heuristic:
                1. Do read before write checking for stack variables to determine whether it's an input variable or not, using global stack_vars_write
                   TODO: r/w pattern could be disrupted by different execution paths
                2. Treat all stack variables as float
                   TODO: this is for the simplicity of soft-fp firmware handling
            */
            if (within_stack_bounds(vaddr, sz_bytes)) {
                printf("[MEMCB update_addr_var_mem_cb] Address 0x%lx is within stack bounds, creating new stack variable arg setting\n", vaddr);
                if (is_store) { // write to stack var, add to stack_vars_write
                    StackVar *v = &stack_vars_write[stack_var_write_count++];
                    v->addr = vaddr;
                    v->sz = sz_bytes;
                }
                else { // read from stack var
                    if (!is_stack_var_write(vaddr, sz_bytes)) { // read before write, mark as input
                        printf("[MEMCB update_addr_var_mem_cb] Address 0x%lx has prior write in this function, creating new stack variable arg setting\n", vaddr);
                        // create new arg setting
                        if (arg_count >= MAX_ARGS) {
                            fprintf(stderr, "Maximum argument settings reached, cannot add new setting for address 0x%lx\n", vaddr);
                            exit(EXIT_FAILURE);
                        }
                        ArgSetting *new_setting = &arg_settings[arg_count++];
                        init_arg_setting(new_setting);
                        int offset = vaddr - stack_ptr;
                        // snprintf(new_setting->name, sizeof(new_setting->name), "sp_%d", offset);
                        snprintf(new_setting->name, sizeof(new_setting->name), "arg%zu", arg_count); // just use arg_idx as name for simplicity
                        new_setting->location_type = TYPE_ADDR;
                        new_setting->addr = vaddr;
                        new_setting->sz = sz_bytes;
                        strncpy(new_setting->base_ptr_var_name, "sp", sizeof(new_setting->base_ptr_var_name) - 1);
                        new_setting->base_ptr_offset = offset;
                        if (sz_bytes == 4) {
                            new_setting->vtype = TYPE_FLOAT; // heuristic: all 4 bytes stack vars are floats
                            new_setting->is_pointer = IS_PTR_FALSE;
                            new_setting->value_count = 2;
                            new_setting->value_range[0].f = default_float_range[0];
                            new_setting->value_range[1].f = default_float_range[1];
                        }
                        else {
                            fprintf(stderr, "Unsupported size %u bytes for new stack variable arg setting at address 0x%lx\n", sz_bytes, vaddr);
                            exit(EXIT_FAILURE);
                        }
                        printf("[MEMCB update_addr_var_mem_cb] logging invalidated: created new float stack variable arg setting '%s' for address 0x%lx\n", new_setting->name, vaddr);
                        is_logging_valid = false;
                        // set pc back to function start
                        ValueUnion func_start_pc;
                        func_start_pc.u32 = func_start;
                        qemu_plugin_set_register((uint8_t *)&func_start_pc, ARM_V7M_REG_R15);
                        // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
                        // printf("[MEMCB update_addr_var_mem_cb] set PC back to function start: 0x%08x\n", pc);
                        qemu_plugin_vcpu_exit_tb_now();
                        // return;
                    }
                }
            }
            else if (within_flash_bounds(vaddr, sz_bytes)) {
                if (is_store) {
                    fprintf(stderr, "[MEMCB update_addr_var_mem_cb] Unsupported write to flash memory at address 0x%lx\n", vaddr);
                    exit(EXIT_FAILURE);
                }
                else {
                    printf("[MEMCB update_addr_var_mem_cb] Address 0x%lx is within flash bounds, likely a constant read, creating new arg setting\n", vaddr);
                    // create new arg setting
                    if (arg_count >= MAX_ARGS) {
                        fprintf(stderr, "Maximum argument settings reached, cannot add new setting for address 0x%lx\n", vaddr);
                        exit(EXIT_FAILURE);
                    }
                    ArgSetting *new_setting = &arg_settings[arg_count++];
                    init_arg_setting(new_setting);
                    // snprintf(new_setting->name, sizeof(new_setting->name), "const_0x%lx", vaddr);
                    snprintf(new_setting->name, sizeof(new_setting->name), "arg%zu", arg_count); // just use arg_idx as name for simplicity
                    new_setting->location_type = TYPE_ADDR;
                    new_setting->addr = vaddr;
                    new_setting->sz = sz_bytes;
                    if (sz_bytes == 4) {
                        new_setting->vtype = TYPE_UINT32; // treat as (unknown) pointer first
                        new_setting->is_pointer = IS_PTR_UNKNOWN;
                        new_setting->non_ptr_iters = 0;
                        // handle struct allocation
                        new_setting->value_count = 1;
                        uint32_t flash_value; // read the value from flash and use it as the default value for this setting
                        qemu_plugin_read_memory(vaddr, (uint8_t *)&flash_value, 4);
                        new_setting->value_range[0].u32 = flash_value;
                        // assert(new_setting->sz == 4); // 4 bytes addr size in arm
                        struct NestedStruct* new_struct = ns_new_ptr(flash_value, new_setting->sz, false);
                        // cur_ptr_addr += STRUCT_MEM_SIZE; // use (hopefully large enough) fixed size
                        allocated_structs[allocated_struct_count++] = new_struct;
                    } else if (sz_bytes == 2) {
                        new_setting->vtype = TYPE_UINT16; // must be int
                        new_setting->is_pointer = IS_PTR_FALSE; // 2-byte int not pointer
                        new_setting->value_count = 2;
                        new_setting->value_range[0].u32 = default_int_range[0];
                        new_setting->value_range[1].u32 = default_int_range[1];
                    } else if (sz_bytes == 1) {
                        new_setting->vtype = TYPE_UINT8; // must be int
                        new_setting->is_pointer = IS_PTR_FALSE; // 1-byte int not pointer
                        new_setting->value_count = 2;
                        new_setting->value_range[0].u32 = default_int_range[0];
                        new_setting->value_range[1].u32 = default_int_range[1];
                    } else {
                        fprintf(stderr, "Unsupported size %u bytes for new arg setting at address 0x%lx\n", sz_bytes, vaddr);
                        exit(EXIT_FAILURE);
                    }

                    printf("[MEMCB update_addr_var_mem_cb] logging invalidated: created new float stack variable arg setting '%s' for address 0x%lx\n", new_setting->name, vaddr);
                    is_logging_valid = false;
                    // set pc back to function start
                    ValueUnion func_start_pc;
                    func_start_pc.u32 = func_start;
                    qemu_plugin_set_register((uint8_t *)&func_start_pc, ARM_V7M_REG_R15);
                    // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
                    // printf("[MEMCB update_addr_var_mem_cb] set PC back to function start: 0x%08x\n", pc);
                    qemu_plugin_vcpu_exit_tb_now();
                }
            }
            else {
                fprintf(stderr, "[MEMCB update_addr_var_mem_cb] Unsupported memory access at address 0x%lx\n", vaddr);
                exit(EXIT_FAILURE);
            }
        }
    }
}

// TODO: could merge with update_addr_var_mem_cb
static void update_float_addr_var_mem_cb(unsigned int vcpu_index,
                   qemu_plugin_meminfo_t info, uint64_t vaddr, void *udata) {
    if (!function_reached) return;

    unsigned sz_shift = qemu_plugin_mem_size_shift(info);  // 0=8b,1=16b,2=32b,3=64b,...
    unsigned sz_bytes = 1u << sz_shift; // 1,2,4,8 bytes
    int is_store = qemu_plugin_mem_is_store(info);
    // check pc
    // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
    uint64_t pc = *(uint64_t *)udata;
    fprintf(stdout, "[MEMCB update_float_addr_var_mem_cb] pc=0x%08lx, access=0x%08" PRIx64 " (%u-bit %s)\n",
            pc, vaddr, 8u << sz_shift, is_store ? "STORE" : "LOAD");
    /* optional: value seen */
    // qemu_plugin_mem_value val = qemu_plugin_mem_get_value(info);

    // check whether the address is in arg_settings
    // if (sz_bytes == 4 && !is_store) { // only handle 32-bit loads
    // if (!is_store) {
    if (sz_bytes != 4 && sz_bytes != 8) {  // only handle 32/64 bit loads (for potential float/double struct fields)
        fprintf(stderr, "[MEMCB update_float_addr_var_mem_cb], Unsupported size %u bytes for float memory callback at address 0x%lx\n", sz_bytes, vaddr);
        exit(EXIT_FAILURE);
    }
    // Iterate through arg_settings to find a match
    bool found_arg_match = false;
    for (size_t i = 0; i < arg_count; i++) {
        ArgSetting *setting = &arg_settings[i];
        // if (setting->location_type == TYPE_ADDR && setting->addr == vaddr) {
        if (setting->location_type == TYPE_ADDR && same_mem_locs(setting, vaddr, sz_bytes)) {
            found_arg_match = true;
            // We have a match, update the arg setting
            // if (setting->vtype != TYPE_FLOAT) { // fix type if not float
            if (setting->vtype != TYPE_FLOAT && setting->sz == 4) {
                // update to float
                setting->vtype = TYPE_FLOAT;
                setting->sz = 4;
                setting->is_pointer = IS_PTR_FALSE;
                setting->value_count = 2; // single value
                setting->value_range[0].f = default_float_range[0];
                setting->value_range[1].f = default_float_range[1];
                /***********************************************************************************************
                    note:
                    Memory callbacks are called after a successful load or store
                    according to https://qemu.readthedocs.io/en/v9.0.4/devel/tcg-plugins.html
                    we cannot update the memory value here, should discard the results for the current iteration
                ***********************************************************************************************/
                // ValueUnion value;
                // value.f = get_random_float(setting->value_range[0].f, setting->value_range[1].f);
                // printf("[update_float_addr_var_mem_cb] update memory at 0x%lx to float value: %g\n", vaddr, value.f);
                // // write the new float value to memory
                // qemu_plugin_write_memory(vaddr, (uint8_t *)&value, 4);
                // // update current logged_in_values
                // logged_in_values[i].f = value.f;
                // printf("[update_float_addr_var_mem_cb] updated logged_in_values[%zu] to %g\n", i, logged_in_values[i].f);
                printf("[MEMCB update_float_addr_var_mem_cb] logging invalidated: updated arg setting '%s' for address 0x%lx to float type\n", setting->name, vaddr);
                is_logging_valid = false; // invalidate current logging
                // set pc back to function start
                ValueUnion func_start_pc;
                func_start_pc.u32 = func_start;
                qemu_plugin_set_register((uint8_t *)&func_start_pc, ARM_V7M_REG_R15);
                // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
                // printf("[MEMCB update_float_addr_var_mem_cb] set PC back to function start: 0x%08x\n", pc);
                qemu_plugin_vcpu_exit_tb_now();
                // return;
            }
            if (setting->vtype != TYPE_DOUBLE && setting->sz == 8) {
                // update to double
                setting->vtype = TYPE_DOUBLE;
                setting->sz = 8;
                setting->is_pointer = IS_PTR_FALSE;
                setting->value_count = 2; // single value
                setting->value_range[0].d = default_double_range[0];
                setting->value_range[1].d = default_double_range[1];

                printf("[MEMCB update_float_addr_var_mem_cb] logging invalidated: updated arg setting '%s' for address 0x%lx to double type\n", setting->name, vaddr);
                is_logging_valid = false; // invalidate current logging
                // set pc back to function start
                ValueUnion func_start_pc;
                func_start_pc.u32 = func_start;
                qemu_plugin_set_register((uint8_t *)&func_start_pc, ARM_V7M_REG_R15);
                // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
                // printf("[MEMCB update_float_addr_var_mem_cb] set PC back to function start: 0x%08x\n", pc);
                qemu_plugin_vcpu_exit_tb_now();
                // return;
            }
        }
    }
    if (!found_arg_match) {
        printf("[MEMCB update_float_addr_var_mem_cb] No matching arg setting for address 0x%lx, creating new float setting\n", vaddr);
        // create new arg setting
        if (arg_count >= MAX_ARGS) {
            fprintf(stderr, "Maximum argument settings reached, cannot add new setting for address 0x%lx\n", vaddr);
            exit(EXIT_FAILURE);
        }
        int parent_allocated_struct_idx = find_parent_struct_by_addr(vaddr, sz_bytes);
        if (parent_allocated_struct_idx >= 0) { // struct var
            /*
              Heuristic:
                for e2e analysis, treat all struct variables as input variables first, and create arg settings for them
                fine grained analysis will be done for sub-semantic analysis
            */
            assert(parent_allocated_struct_idx < allocated_struct_count);
            unsigned long parent_allocated_addr = allocated_structs[parent_allocated_struct_idx]->loc.addr;
            printf("[MEMCB update_float_addr_var_mem_cb] Found parent struct allocated at address 0x%lx\n", parent_allocated_addr);
            // assert(allocated_structs[parent_allocated_struct_idx]->is_pointer);
            size_t parent_ptr_size = allocated_structs[parent_allocated_struct_idx]->size;
            int parent_arg_setting_idx = find_ptr_arg_by_addr(parent_allocated_addr, parent_ptr_size, arg_settings, &arg_count);
            assert(parent_arg_setting_idx >= 0 && parent_arg_setting_idx < arg_count);
            struct NestedStruct *parent_struct = allocated_structs[parent_allocated_struct_idx];
            parent_struct->is_pointer = IS_PTR_TRUE; // mark as pointer

            // create new arg setting based on parent
            size_t offset = vaddr - parent_allocated_addr;
            ArgSetting *parent_setting = &arg_settings[parent_arg_setting_idx];
            parent_setting->is_pointer = IS_PTR_TRUE; // mark as pointer
            ArgSetting *new_setting = &arg_settings[arg_count++];
            init_arg_setting(new_setting);
            // snprintf(new_setting->name, sizeof(new_setting->name), "%s_off_%zu", parent_setting->name, offset);
            snprintf(new_setting->name, sizeof(new_setting->name), "arg%zu", arg_count); // just use arg_idx as name for simplicity
            new_setting->location_type = TYPE_ADDR;
            new_setting->addr = vaddr;
            new_setting->sz = sz_bytes;
            strncpy(new_setting->base_ptr_var_name, parent_setting->name, sizeof(new_setting->base_ptr_var_name) - 1);
            new_setting->base_ptr_offset = offset;
            // new_setting->vtype = TYPE_FLOAT;
            if (sz_bytes == 4) {
                new_setting->vtype = TYPE_FLOAT;
            } else if (sz_bytes == 8) {
                new_setting->vtype = TYPE_DOUBLE;
            } else {
                fprintf(stderr, "Unsupported size %u bytes for new float arg setting at address 0x%lx\n", sz_bytes, vaddr);
                exit(EXIT_FAILURE);
            }
            new_setting->is_pointer = IS_PTR_FALSE; // TODO: handle nested structs
            new_setting->value_count = 2;
            // new_setting->value_range[0].f = default_float_range[0];
            // new_setting->value_range[1].f = default_float_range[1];
            if (sz_bytes == 4) {
                new_setting->value_range[0].f = default_float_range[0];
                new_setting->value_range[1].f = default_float_range[1];
            } else if (sz_bytes == 8) {
                new_setting->value_range[0].d = default_double_range[0];
                new_setting->value_range[1].d = default_double_range[1];
            }

            printf("[MEMCB update_float_addr_var_mem_cb] logging invalidated: created new float arg setting '%s' for address 0x%lx\n", new_setting->name, vaddr);
            is_logging_valid = false;
            // set pc back to function start
            ValueUnion func_start_pc;
            func_start_pc.u32 = func_start;
            qemu_plugin_set_register((uint8_t *)&func_start_pc, ARM_V7M_REG_R15);
            // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
            // printf("[MEMCB update_float_addr_var_mem_cb] set PC back to function start: 0x%08x\n", pc);
            qemu_plugin_vcpu_exit_tb_now();
            // return;
        } else { // stack variables / code section variables (constants)
            /*
              Heuristic:
                1. Do read before write checking for stack variables to determine whether it's an input variable or not, using global stack_vars_write
                   TODO: r/w pattern could be disrupted by different execution paths
                2. Only handle 4/8 byte stack variables, and treat all of them as float/double
            */
            if (within_stack_bounds(vaddr, sz_bytes)) {
                printf("[MEMCB update_float_addr_var_mem_cb] Address 0x%lx is within stack bounds, creating new float stack variable arg setting\n", vaddr);
                if (is_store) { // write to stack var, add to stack_vars_write
                    StackVar *v = &stack_vars_write[stack_var_write_count++];
                    v->addr = vaddr;
                    v->sz = sz_bytes;
                }
                else { // read from stack var
                    if (!is_stack_var_write(vaddr, sz_bytes)) { // read before write, mark as input
                        printf("[MEMCB update_float_addr_var_mem_cb] Address 0x%lx has prior write in this function, creating new float stack variable arg setting\n", vaddr);
                        // create new arg setting
                        if (arg_count >= MAX_ARGS) {
                            fprintf(stderr, "Maximum argument settings reached, cannot add new setting for address 0x%lx\n", vaddr);
                            exit(EXIT_FAILURE);
                        }
                        ArgSetting *new_setting = &arg_settings[arg_count++];
                        init_arg_setting(new_setting);
                        int offset = vaddr - stack_ptr;
                        // snprintf(new_setting->name, sizeof(new_setting->name), "sp_%d", offset);
                        snprintf(new_setting->name, sizeof(new_setting->name), "arg%zu", arg_count); // just use arg_idx as name for simplicity
                        new_setting->location_type = TYPE_ADDR;
                        new_setting->addr = vaddr;
                        new_setting->sz = sz_bytes;
                        strncpy(new_setting->base_ptr_var_name, "sp", sizeof(new_setting->base_ptr_var_name) - 1);
                        new_setting->base_ptr_offset = offset;
                        if (sz_bytes == 4) {
                            new_setting->vtype = TYPE_FLOAT; // heuristic: all 4 bytes stack vars are floats
                            new_setting->is_pointer = IS_PTR_FALSE;
                            new_setting->value_count = 2;
                            new_setting->value_range[0].f = default_float_range[0];
                            new_setting->value_range[1].f = default_float_range[1];
                        } else if (sz_bytes == 8) {
                            new_setting->vtype = TYPE_DOUBLE; // heuristic: all 8 bytes stack vars are doubles
                            new_setting->is_pointer = IS_PTR_FALSE;
                            new_setting->value_count = 2;
                            new_setting->value_range[0].d = default_double_range[0];
                            new_setting->value_range[1].d = default_double_range[1];
                        } else {
                            fprintf(stderr, "Unsupported size %u bytes for new float stack variable arg setting at address 0x%lx\n", sz_bytes, vaddr);
                            exit(EXIT_FAILURE);
                        }
                        printf("[MEMCB update_float_addr_var_mem_cb] logging invalidated: created new float stack variable arg setting '%s' for address 0x%lx\n", new_setting->name, vaddr);
                        is_logging_valid = false;
                        // set pc back to function start
                        ValueUnion func_start_pc;
                        func_start_pc.u32 = func_start;
                        qemu_plugin_set_register((uint8_t *)&func_start_pc, ARM_V7M_REG_R15);
                        // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
                        // printf("[MEMCB update_float_addr_var_mem_cb] set PC back to function start: 0x%08x\n", pc);
                        qemu_plugin_vcpu_exit_tb_now();
                        // return;
                    }
                }
            }
            else {
                // fprintf(stderr, "[MEMCB update_float_addr_var_mem_cb] Unsupported memory access at address 0x%lx\n", vaddr);
                // exit(EXIT_FAILURE);
                if (is_store) {
                    fprintf(stderr, "[MEMCB update_float_addr_var_mem_cb] Unsupported write to flash memory at address 0x%lx\n", vaddr);
                    exit(EXIT_FAILURE);
                }
                else {
                    // Flash/code-section float read = literal-pool constant (e.g. a coefficient
                    // or the FLT_MAX guard threshold loaded via `vldr sX, [pc, #imm]`). It is part
                    // of the function's own semantics, NOT an external input. Leave the memory
                    // untouched so the function reads its genuine constant, and do NOT promote it
                    // to a randomizable arg. (Promoting it produced a constant "input" pinned to
                    // the literal value and an illegal write into the code/literal pool.)
                    printf("[MEMCB update_float_addr_var_mem_cb] Address 0x%lx is within flash bounds, treating as constant (not an input)\n", vaddr);
                }
            }
        }
    }
}

static void update_subsem_float_addr_var_mem_cb(unsigned int vcpu_index,
                   qemu_plugin_meminfo_t info, uint64_t vaddr, void *udata) {
    // update_subsem_addr_var_mem_cb(vcpu_index, info, vaddr, udata);
    if (!sub_semantic_reached) return;
    if (sub_semantic_cur_iteration != 1) return; // everything should be set after first iteration for sub-semantics

    unsigned sz_shift = qemu_plugin_mem_size_shift(info);  // 0=8b,1=16b,2=32b,3=64b,...
    unsigned sz_bytes = 1u << sz_shift; // 1,2,4,8 bytes
    int is_store = qemu_plugin_mem_is_store(info);

    // check pc
    // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
    uint64_t pc = *(uint64_t *)udata;
    fprintf(stdout, "[MEMCB update_subsem_addr_var_mem_cb] pc=0x%08lx, access=0x%08" PRIx64 " (%u-byte %s)\n",
            pc, vaddr, sz_bytes, is_store ? "STORE" : "LOAD"); // warn: this could still be the start of tb

    // check whether the address is in arg_settings
    // Iterate through arg_settings to find a match

    // -----------------------------------------------------------------------------------------------------
    // input
    // -----------------------------------------------------------------------------------------------------
    // bool found_arg_match = false;
    // int match_idx = -1;
    // for (size_t i = 0; i < arg_count; i++) {
    //     ArgSetting *setting = &arg_settings[i];
    //     // if (setting->location_type == TYPE_ADDR && setting->addr == vaddr) {
    //     if (setting->location_type == TYPE_ADDR && same_mem_locs(setting, vaddr, sz_bytes)) {
    //         found_arg_match = true;
    //         match_idx = i;
    //         break;
    //     }
    // }
    // if (found_arg_match) {
    //     ArgSetting *setting = &arg_settings[match_idx];
    //     if (sz_bytes == 4) { // only float
    //         if (setting->vtype == TYPE_FLOAT) {
    //             if (is_store) { // write to float arg setting
    //                 printf("  [MEMCB update_subsem_addr_var_mem_cb] Address 0x%lx written, marking arg setting '%s' as is_written\n", vaddr, setting->name);
    //                 setting->is_written = true;
    //             }
    //             else { // the mem arg is read
    //                 if (!setting->is_written) { // read before write, mark as input
    //                     printf("  [MEMCB update_subsem_addr_var_mem_cb] Address 0x%lx read before write in sub-semantics, marking arg setting '%s' as input\n", vaddr, setting->name);
    //                     setting->is_read = true;
    //                     setting->is_sub_semantic_input = true;
    //                 }
    //             }
    //         }
    //     }
    // }
    // else { // not found_arg_match
    //     if (sz_bytes == 4) { // heuristic: only 4 bytes var, and treat as float
    //         if (within_stack_bounds(vaddr, sz_bytes)) { // only check whether there is new stack var
    //             // create new stack variable
    //             ArgSetting *new_setting = &arg_settings[arg_count++];
    //             int offset = vaddr - stack_ptr;
    //             snprintf(new_setting->name, sizeof(new_setting->name), "sp_%d", offset);
    //             new_setting->location_type = TYPE_ADDR;
    //             new_setting->addr = vaddr;
    //             new_setting->sz = sz_bytes;
    //             new_setting->vtype = TYPE_FLOAT;
    //             new_setting->is_pointer = IS_PTR_FALSE;
    //             new_setting->value_count = 2;
    //             new_setting->value_range[0].f = default_float_range[0];
    //             new_setting->value_range[1].f = default_float_range[1];
    //             if (is_store) { // write to stack var, add to stack_vars_write
    //                 new_setting->is_written = true;
    //                 printf("  [MEMCB update_subsem_addr_var_mem_cb] Marking new stack variable arg setting '%s' as written\n", new_setting->name);
    //             }
    //             else {
    //                 new_setting->is_read = true;
    //                 new_setting->is_sub_semantic_input = true;
    //                 printf("  [MEMCB update_subsem_addr_var_mem_cb] Marking new stack variable arg setting '%s' as read (input)\n", new_setting->name);
    //             }
    //         }
    //     }

    // }

    // bool found_reachdef_match = false;
    // int reachdef_var_idx = -1;
    // for (size_t i = 0; i < active_var_defs_count; i++) {
    //     ArgSetting *setting = &arg_settings[i];
    //     // if (setting->location_type == TYPE_ADDR && setting->addr == vaddr) {
    //     if (setting->location_type == TYPE_ADDR && same_mem_locs(setting, vaddr, sz_bytes)) {
    //         found_reachdef_match = true;
    //         reachdef_var_idx = i;
    //         break;
    //     }
    // }
    // if (found_reachdef_match) {

    // }

    // // -----------------------------------------------------------------------------------------------------
    // // output
    // // -----------------------------------------------------------------------------------------------------
    // bool found_ret_match = false;
    // for (size_t i = 0; i < ret_count; i++) {
    //     RetSetting *setting = &ret_settings[i];
    //     // if (setting->location_type == TYPE_ADDR && setting->addr == vaddr) {
    //     if (setting->location_type == TYPE_ADDR && same_mem_locs_ret(setting, vaddr)) {
    //         found_ret_match = true;
    //         if (sz_bytes == 4 && is_store) {
    //             setting->written_time = cur_timestamp++;
    //         }
    //         break;
    //     }
    // }
    // if (!found_ret_match) {
    //     if (sz_bytes == 4 && is_store) { // only float
    //         if (within_stack_bounds(vaddr, sz_bytes)) { // only check whether there is new stack var
    //             // create new ret setting
    //             RetSetting *new_setting = &ret_settings[ret_count++];
    //             int offset = vaddr - stack_ptr;
    //             snprintf(new_setting->name, sizeof(new_setting->name), "sp_%d", offset);
    //             new_setting->location_type = TYPE_ADDR;
    //             new_setting->addr = vaddr;
    //             // new_setting->sz = sz_bytes;
    //             new_setting->vtype = TYPE_FLOAT;
    //             new_setting->written_time = cur_timestamp++;
    //             printf("  [MEMCB update_subsem_addr_var_mem_cb] Address 0x%lx is written & not found in ret_settings, creating new ret setting '%s'\n", vaddr, new_setting->name);
    //         }
    //         else if (is_sub_semantic_last_stage && found_arg_match) {
    //             // for last stage of sub-semantics, if the written address matches an arg setting, create a ret setting
    //             ArgSetting *arg_setting = &arg_settings[match_idx];
    //             if (arg_setting->vtype == TYPE_FLOAT) {
    //                 RetSetting *new_setting = &ret_settings[ret_count++];
    //                 snprintf(new_setting->name, sizeof(new_setting->name), "%s", arg_setting->name);
    //                 new_setting->location_type = TYPE_ADDR;
    //                 new_setting->addr = vaddr;
    //                 // new_setting->sz = sz_bytes;
    //                 new_setting->vtype = TYPE_FLOAT;
    //                 new_setting->written_time = cur_timestamp++;
    //                 printf("  [MEMCB update_subsem_addr_var_mem_cb] Last stage: Written address 0x%lx matches arg setting '%s', creating new ret setting '%s'\n", vaddr, arg_setting->name, new_setting->name);
    //             }
    //         }
    //     }
    // }

    if (sz_bytes != 4) return; // FIXME: only handle 4 byte float for now

    bool found_arg_match = false;
    // int arg_match_idx = -1;
    for (size_t i = 0; i < arg_count; i++) {
        ArgSetting *setting = &arg_settings[i];
        if (setting->location_type == TYPE_ADDR && same_mem_locs(setting, vaddr, sz_bytes)) {
            found_arg_match = true;
            // arg_match_idx = i;
            break;
        }
    }

    bool found_ret_match = false;
    int ret_match_idx = -1;
    for (size_t i = 0; i < ret_count; i++) {
        RetSetting *setting = &ret_settings[i];
        if (setting->location_type == TYPE_ADDR && same_mem_locs_ret(setting, vaddr)) {
            found_ret_match = true;
            ret_match_idx = i;
            break;
        }
    }

    bool found_reachdef_match = false;
    int reachdef_var_idx = -1;
    for (size_t i = 0; i < active_var_defs_count; i++) {
        ArgSetting *setting = &active_var_defs[i];
        if (setting->location_type == TYPE_ADDR && same_mem_locs(setting, vaddr, sz_bytes) && !setting->is_redefined) {
            found_reachdef_match = true;
            reachdef_var_idx = i;
            break;
        }
    }

    if (!is_store) { // read
        if (!found_arg_match && !found_ret_match) { // read before write, create new input variable
            ArgSetting *new_setting = &arg_settings[arg_count];
            init_arg_setting(new_setting);
            snprintf(new_setting->name, sizeof(new_setting->name), "x_s%zu_%zu", stage_num, arg_count); // just use arg_idx as name for simplicity
            if (found_reachdef_match) {
                printf("[INFO] update_subsem_float_addr_var_mem_cb copy reaching variable definition to input %s\n", new_setting->name);
                print_arg_setting(&active_var_defs[reachdef_var_idx]);
                copy_arg_setting(new_setting, &active_var_defs[reachdef_var_idx]);
                match_var_defs[match_reachdef_count] = reachdef_var_idx;
                match_var_uses[match_reachdef_count] = arg_count;
            }
            else {
                // Flash/code-section read = literal-pool constant (e.g. a coefficient or a guard
                // threshold). It is part of the function's semantics, not an input — skip it
                // without promoting to a randomizable variable. Nothing has been committed yet
                // (arg_count / match_reachdef_count not incremented), so returning is safe.
                if (within_flash_bounds(vaddr, sz_bytes)) {
                    printf("[INFO] update_subsem_float_addr_var_mem_cb: read 0x%lx in flash, treating as constant (not an input)\n", vaddr);
                    return;
                }
                // A read-before-write of a RAM location (a stack local, or a struct/heap
                // field such as a PID gain) that was not produced by a prior stage is a
                // sub-semantic input. Register it with a default float range so it gets
                // randomized and the regression can recover the dependence.
                // (Previously any non-stack RAM read aborted collection with exit(FAILURE),
                // which killed every stage that reads struct fields -- e.g. the final PID
                // output block that loads _kp/_ki/_kd from the object at [r4, #...].)
                new_setting->location_type = TYPE_ADDR;
                new_setting->addr = vaddr;
                new_setting->sz = sz_bytes;
                new_setting->vtype = TYPE_FLOAT;
                new_setting->is_pointer = IS_PTR_FALSE;
                new_setting->value_count = 2;
                new_setting->value_range[0].f = default_float_range[0];
                new_setting->value_range[1].f = default_float_range[1];
                if (within_stack_bounds(vaddr, sz_bytes)) {
                    int offset = vaddr - stack_ptr;
                    strncpy(new_setting->base_ptr_var_name, "sp", sizeof(new_setting->base_ptr_var_name) - 1);
                    new_setting->base_ptr_offset = offset;
                }

                match_var_defs[match_reachdef_count] = -1; // -1 indicates no matching reachdef variable
                match_var_uses[match_reachdef_count] = arg_count;
            }
            arg_count++;
            match_reachdef_count++;

            printf("[INFO] update_subsem_float_addr_var_mem_cb identified new sub-semantic input:\n");
            print_arg_setting(new_setting);
        }
    }
    else { // write
        if (!found_ret_match) { // create new ret variable
            RetSetting *new_setting = &ret_settings[ret_count];
            snprintf(new_setting->name, sizeof(new_setting->name), "y_s%zu_%zu", stage_num, ret_count); // just use ret_idx as name for simplicity
            new_setting->location_type = TYPE_ADDR;
            new_setting->addr = vaddr;
            new_setting->sz = sz_bytes;
            new_setting->vtype = TYPE_FLOAT;
            new_setting->defined_stage = stage_num;
            new_setting->written_time = cur_timestamp++;
            
            ret_count++;

            if (found_reachdef_match) {
                active_var_defs[reachdef_var_idx].is_redefined = true; // mark the matched var as redefined
            }
            // new item in active_var_defs for the new definition
            strncpy(active_var_defs[active_var_defs_count].name, new_setting->name, sizeof(active_var_defs[active_var_defs_count].name) - 1);
            active_var_defs[active_var_defs_count].name[sizeof(active_var_defs[active_var_defs_count].name) - 1] = '\0';
            copy_arg_setting_from_ret_setting(&active_var_defs[active_var_defs_count], new_setting);
            active_var_defs_count++;
        }
        else { // ret varialbe already exists, update the written_time
            ret_settings[ret_match_idx].written_time = cur_timestamp++;
            if (found_reachdef_match) {
                // new memory write must have been recoreded, and update the active_var_defs aleary
                // check the found match has the same defined_stage as the current stage
                if (active_var_defs[reachdef_var_idx].defined_stage != stage_num) {
                    fprintf(stderr, "Error: redefinition of variable '%s' in different stages for sub-semantics at address 0x%lx, something wrong happened\n", active_var_defs[reachdef_var_idx].name, vaddr);
                    exit(EXIT_FAILURE);
                }
            }
        }
    }

}


static void update_subsem_addr_var_mem_cb(unsigned int vcpu_index, qemu_plugin_meminfo_t info, uint64_t vaddr, void *udata) {
    // if (!sub_semantic_reached) return;
    // if (sub_semantic_cur_iteration != 1) return; // everything should be set after first iteration for sub-semantics

    // unsigned sz_shift = qemu_plugin_mem_size_shift(info);  // 0=8b,1=16b,2=32b,3=64b,...
    // unsigned sz_bytes = 1u << sz_shift; // 1,2,4,8 bytes
    // int is_store = qemu_plugin_mem_is_store(info);

    // // check pc
    // // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
    // uint64_t pc = *(uint64_t *)udata;
    // fprintf(stdout, "[MEMCB update_subsem_addr_var_mem_cb] pc=0x%08lx, access=0x%08" PRIx64 " (%u-byte %s)\n",
    //         pc, vaddr, sz_bytes, is_store ? "STORE" : "LOAD"); // warn: this could still be the start of tb
    // // TODO: handle non-fp memory variables
    // // check whether the address is in arg_settings
    // // Iterate through arg_settings to find a match

    // // -----------------------------------------------------------------------------------------------------
    // // input
    // // -----------------------------------------------------------------------------------------------------
    // bool found_arg_match = false;
    // int match_idx = -1;
    // for (size_t i = 0; i < arg_count; i++) {
    //     ArgSetting *setting = &arg_settings[i];
    //     // if (setting->location_type == TYPE_ADDR && setting->addr == vaddr) {
    //     if (setting->location_type == TYPE_ADDR && same_mem_locs(setting, vaddr, sz_bytes)) {
    //         found_arg_match = true;
    //         match_idx = i;
    //         break;
    //     }
    // }
    // if (found_arg_match) {
    //     ArgSetting *setting = &arg_settings[match_idx];
    //     if (sz_bytes == 4) { // only float
    //         if (setting->vtype == TYPE_FLOAT) {
    //             if (is_store) { // write to float arg setting
    //                 printf("  [MEMCB update_subsem_addr_var_mem_cb] Address 0x%lx written, marking arg setting '%s' as is_written\n", vaddr, setting->name);
    //                 setting->is_written = true;
    //             }
    //             else { // the mem arg is read
    //                 if (!setting->is_written) { // read before write, mark as input
    //                     printf("  [MEMCB update_subsem_addr_var_mem_cb] Address 0x%lx read before write in sub-semantics, marking arg setting '%s' as input\n", vaddr, setting->name);
    //                     setting->is_read = true;
    //                     setting->is_sub_semantic_input = true;
    //                 }
    //             }
    //         }
    //     }
    // }
    // else { // not found_arg_match
    //     if (sz_bytes == 4) { // heuristic: only 4 bytes var, and treat as float
    //         if (within_stack_bounds(vaddr, sz_bytes)) { // only check whether there is new stack var
    //             // create new stack variable
    //             ArgSetting *new_setting = &arg_settings[arg_count++];
    //             int offset = vaddr - stack_ptr;
    //             snprintf(new_setting->name, sizeof(new_setting->name), "sp_%d", offset);
    //             new_setting->location_type = TYPE_ADDR;
    //             new_setting->addr = vaddr;
    //             new_setting->sz = sz_bytes;
    //             new_setting->vtype = TYPE_FLOAT;
    //             new_setting->is_pointer = IS_PTR_FALSE;
    //             new_setting->value_count = 2;
    //             new_setting->value_range[0].f = default_float_range[0];
    //             new_setting->value_range[1].f = default_float_range[1];
    //             if (is_store) { // write to stack var, add to stack_vars_write
    //                 new_setting->is_written = true;
    //                 printf("  [MEMCB update_subsem_addr_var_mem_cb] Marking new stack variable arg setting '%s' as written\n", new_setting->name);
    //             }
    //             else {
    //                 new_setting->is_read = true;
    //                 new_setting->is_sub_semantic_input = true;
    //                 printf("  [MEMCB update_subsem_addr_var_mem_cb] Marking new stack variable arg setting '%s' as read (input)\n", new_setting->name);
    //             }
    //         }
    //     }

    // }

    // // -----------------------------------------------------------------------------------------------------
    // // output
    // // -----------------------------------------------------------------------------------------------------
    // bool found_ret_match = false;
    // for (size_t i = 0; i < ret_count; i++) {
    //     RetSetting *setting = &ret_settings[i];
    //     // if (setting->location_type == TYPE_ADDR && setting->addr == vaddr) {
    //     if (setting->location_type == TYPE_ADDR && same_mem_locs_ret(setting, vaddr)) {
    //         found_ret_match = true;
    //         if (sz_bytes == 4 && is_store) {
    //             setting->written_time = cur_timestamp++;
    //         }
    //         break;
    //     }
    // }
    // if (!found_ret_match) {
    //     if (sz_bytes == 4 && is_store) { // only float
    //         if (within_stack_bounds(vaddr, sz_bytes)) { // only check whether there is new stack var
    //             // create new ret setting
    //             RetSetting *new_setting = &ret_settings[ret_count++];
    //             int offset = vaddr - stack_ptr;
    //             snprintf(new_setting->name, sizeof(new_setting->name), "sp_%d", offset);
    //             new_setting->location_type = TYPE_ADDR;
    //             new_setting->addr = vaddr;
    //             // new_setting->sz = sz_bytes;
    //             new_setting->vtype = TYPE_FLOAT;
    //             new_setting->written_time = cur_timestamp++;
    //             printf("  [MEMCB update_subsem_addr_var_mem_cb] Address 0x%lx is written & not found in ret_settings, creating new ret setting '%s'\n", vaddr, new_setting->name);
    //         }
    //         else if (is_sub_semantic_last_stage && found_arg_match) {
    //             // for last stage of sub-semantics, if the written address matches an arg setting, create a ret setting
    //             ArgSetting *arg_setting = &arg_settings[match_idx];
    //             if (arg_setting->vtype == TYPE_FLOAT) {
    //                 RetSetting *new_setting = &ret_settings[ret_count++];
    //                 snprintf(new_setting->name, sizeof(new_setting->name), "%s", arg_setting->name);
    //                 new_setting->location_type = TYPE_ADDR;
    //                 new_setting->addr = vaddr;
    //                 // new_setting->sz = sz_bytes;
    //                 new_setting->vtype = TYPE_FLOAT;
    //                 new_setting->written_time = cur_timestamp++;
    //                 printf("  [MEMCB update_subsem_addr_var_mem_cb] Last stage: Written address 0x%lx matches arg setting '%s', creating new ret setting '%s'\n", vaddr, arg_setting->name, new_setting->name);
    //             }
    //         }
    //     }
    // }
    update_subsem_float_addr_var_mem_cb(vcpu_index, info, vaddr, udata); // TODO: handle non-fp memory variables
}

// int inline_ins = 0;
#define MAX_MATCHES 10


// static int init = 0;
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
	// if (runtime && !init) {
	// 		qemu_plugin_load_elf((char *)runtime);
	// 		init = 1;
	// }
    size_t n = qemu_plugin_tb_n_insns(tb);
    size_t i;
	UpdateEntry *matches[MAX_MATCHES];

	// printf("->Virtual Clock: %llu \n", (unsigned long long)qemu_plugin_get_virtual_timer());


    csh cshandle;
    cs_insn *csinsn;
    size_t cs_disasm_count;
    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &cshandle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to open Capstone disassembler\n");
        return;
    }

    for (i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

        // Instruction-budget watchdog: register on EVERY instruction, including
        // code outside the function (e.g. a default fault handler that just spins
        // `b .`), so a fault/runaway that never re-enters an instrumented basic
        // block is still caught. Must be before the function-range filter below.
        if (!is_sub_semantics_mode) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, count_insn_cb, QEMU_PLUGIN_CB_RW_REGS, NULL);
        }

        // check insn addr within [function_start, function_end]
        unsigned long largest_func_end = func_ends[0];
        for (size_t fi = 1; fi < func_end_count; fi++) {
            if (func_ends[fi] > largest_func_end) {
                largest_func_end = func_ends[fi];
            }
        }
        if (qemu_plugin_insn_vaddr(insn) < func_start || qemu_plugin_insn_vaddr(insn) > largest_func_end) {
            continue;
        }
        // }
        // else {
        //     if (qemu_plugin_insn_vaddr(insn) < sub_semantic_start || qemu_plugin_insn_vaddr(insn) > sub_semantic_end) {
        //         continue;
        //     }
        // }

		// //Highest priority: Logger
		// LookupResult ret = lookup_addr(qemu_plugin_insn_vaddr(insn));
		// if (ret.list) {
		// 	qemu_plugin_u64 entry_tmp;
		// 	if (!ret.list->log_buf.buffer) {
		// 			ret.list->log_buf.buffer = malloc(UINT16_MAX + 1);
		// 	}
		// 	entry_tmp.offset = (size_t)&ret.list->log_buf;
		// 	qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_LOG_REG, entry_tmp, ret.entry->reg);
		// }

        // // zz: this need support for float reg in log_reg
        // for (size_t j = 0; j < ret_count; j++) {
        //     RetSetting *setting = &ret_settings[j];
        //     if (setting->xaddr == qemu_plugin_insn_vaddr(insn)) {
        //         qemu_plugin_u64 entry_tmp;
        //         setting->log_buf.buffer = malloc(UINT16_MAX + 1);
        //         setting->log_buf.index = 0;
        //         entry_tmp.offset = (size_t)&setting->log_buf;
        //         if (setting->location_type == TYPE_REG) {
        //             // Register logging
        //             printf("Ret setting for register logging: %s, get_reg_by_name=%d\n", setting->reg, get_reg_by_name(setting->reg));
        //             qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_LOG_REG, entry_tmp, get_reg_by_name(setting->reg));
        //         } else if (setting->location_type == TYPE_ADDR) {
        //             // Memory logging
        //             // not implemented yet
        //             printf("Ret setting for memory logging not implemented yet\n");
        //             perror("vcpu_tb_trans");
        //             exit(EXIT_FAILURE);
        //         }
        //     }
        // }

        // install logpc vi for all instructions
        int instr_idx = -1;
        if (!is_instr_logged(qemu_plugin_insn_vaddr(insn))) {
            // log_instr_address(qemu_plugin_insn_vaddr(insn));
            instr_addrs[instr_count] = qemu_plugin_insn_vaddr(insn);
            // qemu_plugin_register_vcpu_insn_exec_cb(insn, logpc, QEMU_PLUGIN_CB_RW_REGS, (void *)&instr_addrs[instr_count]);
            instr_idx = instr_count;
            instr_count++;
        } else {
            // get the index
            instr_idx = get_logged_instr_index(qemu_plugin_insn_vaddr(insn));
            // qemu_plugin_register_vcpu_insn_exec_cb(insn, logpc, QEMU_PLUGIN_CB_RW_REGS, (void *)&instr_addrs[instr_idx]);
        }
        assert(instr_idx >= 0 && instr_idx < instr_count);

		// randargs, logrets, randargs_sub_semantics, logrets_sub_semantics
		// rule_t  *rule;
        // if (find_rule_by_address(qemu_plugin_insn_vaddr(insn), &rule)) {
        //     printf("[INSTALL randargs/logrets] 0x%lx\n", instr_addrs[instr_idx]);
        //     qemu_plugin_register_vcpu_insn_exec_cb(
        //         insn, rule->func, QEMU_PLUGIN_CB_RW_REGS, (void *)&instr_addrs[instr_idx]);
        // }
        for (size_t rid = 0; rid < rules_count; rid++) {
            rule_t* rule = &rules[rid];
            if (rule->address == qemu_plugin_insn_vaddr(insn)) {
                printf("[INSTALL randargs/logrets/setargs/randargs_sub_semantics/logrets_sub_semantics] 0x%lx (visit %d)\n", instr_addrs[instr_idx], rule->trigger_visit);
                // Capture the visit index for the sub-semantic loop-stage triggers so
                // the callbacks can gate on it (one randargs + one logrets rule per stage).
                if (rule->func == randargs_sub_semantics) {
                    randargs_target_visit = rule->trigger_visit;
                } else if (rule->func == logrets_sub_semantics) {
                    logrets_target_visit = rule->trigger_visit;
                }
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, rule->func, QEMU_PLUGIN_CB_RW_REGS, (void *)&instr_addrs[instr_idx]);
            }
        }
        // bb start
        if (!is_sub_semantics_mode) { // only for end-to-end mode
            for (size_t j = 0; j < bb_count; j++) {
                if (bb_starts[j] == qemu_plugin_insn_vaddr(insn)) {
                    // Register the callback for bb start
                    printf("[INSTALL bb start] 0x%lx\n", qemu_plugin_insn_vaddr(insn));
                    qemu_plugin_register_vcpu_insn_exec_cb(
                        insn, logbbstart, QEMU_PLUGIN_CB_RW_REGS, (void *)&bb_starts[j]);
                }
            }
        }

        // install resetpc vi for all instructions
        // qemu_plugin_register_vcpu_insn_exec_cb(insn, resetpc, QEMU_PLUGIN_CB_RW_REGS, NULL); // zz: this not work, use qemu_plugin_vcpu_exit_tb_now


        // [zz] moemory callbacks after VI for:
        //      (1) dynamic struct field identification
        //      (2) dynamic variable type identification (float vs int)
        if (!is_sub_semantics_mode) {
            size_t inst_len = qemu_plugin_insn_size(insn);
            GByteArray *inst_bytes = g_byte_array_sized_new(inst_len);
            g_byte_array_set_size(inst_bytes, inst_len);
            size_t copied = qemu_plugin_insn_data(insn, inst_bytes->data, inst_len);
            uint64_t insn_addr = qemu_plugin_insn_vaddr(insn);

            printf("[INSTALL instr] 0x%08lx: ", (unsigned long)insn_addr);
            for (size_t b = 0; b < copied; b++) {
                printf("%02x ", inst_bytes->data[b]);
            }
            printf("\n");
            // capstone disassembly
            cs_option(cshandle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_disasm_count = cs_disasm(
                cshandle, inst_bytes->data, inst_len, insn_addr, 1, &csinsn);
            if (cs_disasm_count > 0) {
                // printf("[INSTALL disas] %s\t%s \n", csinsn[0].mnemonic, csinsn[0].op_str);
                // printf("[INSTALL disas] 0x%lx:\t%s\t%s \n", csinsn[0].address, csinsn[0].mnemonic, csinsn[0].op_str);
                if (arm_insn_is_fp_mem_access(csinsn)) {
                    printf("    [INSTALL mem] float instruction @0x%08lx accesses floating point memory\n", csinsn[0].address);
                    qemu_plugin_register_vcpu_mem_cb(insn, update_float_addr_var_mem_cb, QEMU_PLUGIN_CB_RW_REGS, QEMU_PLUGIN_MEM_RW, (void *)&instr_addrs[instr_idx]);
                    printf("    [INSTALL disas] 0x%lx:\t%s\t%s \n", csinsn[0].address, csinsn[0].mnemonic, csinsn[0].op_str);
                }
                // check if the instructino access memory
                else if (arm_insn_accesses_mem(csinsn)) {
                    printf("    [INSTALL mem] instruction @0x%08lx accesses memory\n", csinsn[0].address);
                    qemu_plugin_register_vcpu_mem_cb(insn, update_addr_var_mem_cb, QEMU_PLUGIN_CB_RW_REGS, QEMU_PLUGIN_MEM_RW, (void *)&instr_addrs[instr_idx]);
                    printf("    [INSTALL disas] 0x%lx:\t%s\t%s \n", csinsn[0].address, csinsn[0].mnemonic, csinsn[0].op_str);
                }


            } else {
                printf("[INSTALL disas] <disas error>\n");
            }
            g_byte_array_free(inst_bytes, TRUE);
        } else { // sub-semantics mode
            if (qemu_plugin_insn_vaddr(insn) >= sub_semantic_start && qemu_plugin_insn_vaddr(insn) < sub_semantic_end) {
                size_t inst_len = qemu_plugin_insn_size(insn);
                GByteArray *inst_bytes = g_byte_array_sized_new(inst_len);
                g_byte_array_set_size(inst_bytes, inst_len);
                size_t copied = qemu_plugin_insn_data(insn, inst_bytes->data, inst_len);
                uint64_t insn_addr = qemu_plugin_insn_vaddr(insn);

                printf("[INSTALL instr] 0x%08lx: ", (unsigned long)insn_addr);
                for (size_t b = 0; b < copied; b++) {
                    printf("%02x ", inst_bytes->data[b]);
                }
                printf("\n");
                // capstone disassembly
                cs_option(cshandle, CS_OPT_DETAIL, CS_OPT_ON);
                cs_disasm_count = cs_disasm(
                    cshandle, inst_bytes->data, inst_len, insn_addr, 1, &csinsn);
                if (cs_disasm_count > 0) {
                    // printf("[INSTALL disas] %s\t%s \n", csinsn[0].mnemonic, csinsn[0].op_str);
                    // printf("[INSTALL disas] 0x%lx:\t%s\t%s \n", csinsn[0].address, csinsn[0].mnemonic, csinsn[0].op_str);
                    if (arm_insn_is_fp_mem_access(csinsn)) {
                        printf("    [INSTALL subsem mem] float instruction @0x%08lx accesses floating point memory\n", csinsn[0].address);
                        qemu_plugin_register_vcpu_mem_cb(insn, update_subsem_float_addr_var_mem_cb, QEMU_PLUGIN_CB_RW_REGS, QEMU_PLUGIN_MEM_RW, (void *)&instr_addrs[instr_idx]);
                        printf("    [INSTALL subsem disas] 0x%lx:\t%s\t%s \n", csinsn[0].address, csinsn[0].mnemonic, csinsn[0].op_str);
                    }
                    // check if the instructino access memory
                    else if (arm_insn_accesses_mem(csinsn)) {
                        printf("    [INSTALL subsem mem] instruction @0x%08lx accesses memory\n", csinsn[0].address);
                        qemu_plugin_register_vcpu_mem_cb(insn, update_subsem_addr_var_mem_cb, QEMU_PLUGIN_CB_RW_REGS, QEMU_PLUGIN_MEM_RW, (void *)&instr_addrs[instr_idx]);
                        printf("    [INSTALL subsem disas] 0x%lx:\t%s\t%s \n", csinsn[0].address, csinsn[0].mnemonic, csinsn[0].op_str);
                    }


                } else {
                    printf("[INSTALL subsem disas] <disas error>\n");
                }
                g_byte_array_free(inst_bytes, TRUE);
            }
        }

		//Second to Highest priority: Modifier (zz: move modifier after vi)
		//void * handle= qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn,  QEMU_PLUGIN_CB_GEN_LABEL, NULL, 0);
		size_t count = find_updates_for_address(qemu_plugin_insn_vaddr(insn), matches, MAX_MATCHES);
		if (count > 0) {
		for (size_t match_idx = 0; match_idx < count; ++match_idx) {
			UpdateEntry *e = matches[match_idx];

			printf("[INSTALL modifier] Update Point: 0x%lx, ", e->update_point);
	        if (e->type == TARGET_REGISTER || e->type == TARGET_DEREF) {
                printf("[INSTALL modifier] Target: r%d, ", e->target.reg_num);
                qemu_plugin_u64 entry;
                // In TCG frontend it is already set, if you want to modify it you will have to
                // change CPSR.
                entry.offset = (size_t)(e->value.imm);
                entry.data = (void *)e;
                qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_UPDATE_REG, entry, e->target.reg_num);
           } else if (e->type == TARGET_MEMORY) {
                printf("[INSTALL modifier] Target: r%d, ", e->target.reg_num);
                qemu_plugin_u64 entry;
                // In TCG frontend it is already set, if you want to modify it you will have to
                // change CPSR.
                entry.offset = (size_t)(e->value.imm);
                qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_UPDATE_MEM, entry, e->target.addr);
                printf("[INSTALL modifier] Target: 0x%lx, ", e->target.addr);
       		}

    	}
		}

		// //Lowest priority is detour
		// AddressTuple * tuple = is_target_address(qemu_plugin_insn_vaddr(insn));
        // if (tuple) {
        //         qemu_plugin_u64 entry;
        //         // In TCG frontend it is already set, if you want to modify it you will have to
        //         // change CPSR.
        //         entry.offset = (tuple->anchor & ~(0x1));
        //         qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_UPDATE_REG, entry, 15);
        // }
    }

    printf("---- Finished translating TB at 0x%llx with %zu instructions ----\n",
           (unsigned long long)qemu_plugin_tb_vaddr(tb), n);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
}

char * get_arg(const char * key, int argc, char **argv);
char * get_arg(const char * key, int argc, char **argv) {
	int len = strlen(key);
	for (int i =0; i < argc; i ++) {
        if (strncmp(argv[i], key, len) == 0) {
            return (argv[i] + len + 1);
        }
    }

	return NULL;
}

// uint64_t my_unimp_read(void *opaque, hwaddr offset, unsigned size);
// uint64_t my_unimp_read(void *opaque, hwaddr offset, unsigned size) {
//     printf("Read at offset 0x%" PRIx64 "\n", offset);
//     return 0x0;
// }

// void my_unimp_write(void *opaque, hwaddr offset, uint64_t value, unsigned size);
// void my_unimp_write(void *opaque, hwaddr offset, uint64_t value, unsigned size) {
//     printf("Write at offset 0x%" PRIx64 " value 0x%" PRIx64 "\n", offset, value);
// }

// DEV_XPORTER importer = {.read = my_unimp_read,
//         .write = my_unimp_write};


QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
	if (argc < 1) {
        fprintf(stderr, "Usage: plugin.so <address_file.txt>\n");
        return -1;
    }

	// const char *filename= get_arg("detour", argc, argv);
    // num_tuples = read_tuples_from_file(filename, address_tuples, MAX_TUPLES);

	const char * filename= get_arg("modifier", argc, argv);
	load_update_entries(filename);

	filename = get_arg("virtual", argc, argv);
	parse_rules_file(filename);

    filename = get_arg("func_start_args", argc, argv);
    parse_func_start_json_args(filename);

    filename = get_arg("args", argc, argv);
    parse_json_args(filename);

    /* If the args statically pre-populate an object arena (memory-located fields at
     * ~0x30000020+, reconstructed from a callee's interface for a delegating
     * function), advance cur_ptr_addr past those 512-byte blocks so any later DYNAMIC
     * field discovery allocates non-colliding arenas. No-op for a normally-discovered
     * function (its args carry no arena-region addr). */
    for (size_t i = 0; i < arg_count; i++) {
        ArgSetting *s = &arg_settings[i];
        if (s->location_type == TYPE_ADDR && (unsigned long)s->addr >= 0x30000020UL) {
            unsigned long block = 0x30000020UL +
                (((unsigned long)s->addr - 0x30000020UL) / STRUCT_MEM_SIZE) * STRUCT_MEM_SIZE;
            if (block + STRUCT_MEM_SIZE > cur_ptr_addr)
                cur_ptr_addr = block + STRUCT_MEM_SIZE;
        }
    }

    filename = get_arg("outs", argc, argv);
    parse_json_outs(filename);

    filename = get_arg("basicblocks", argc, argv);
    parse_basic_block_file(filename);

    // edge.txt (CFG edge set for edge coverage). MUST come after basicblocks so
    // bb_starts[] is populated. Optional: absent in sub-semantic mode (which does not
    // register logbbstart), so guard against a NULL arg like other optional files.
    filename = get_arg("edge", argc, argv);
    if (filename) parse_edge_file(filename);

    filename = get_arg("function_starts", argc, argv);
    parse_function_start_file(filename);

    filename = get_arg("function_ends", argc, argv);
    parse_function_end_file(filename);

    filename = get_arg("sub_semantic_start", argc, argv);
    parse_sub_semantic_start_file(filename);

    filename = get_arg("sub_semantic_end", argc, argv);
    parse_sub_semantic_end_file(filename);

    filename = get_arg("active_vars", argc, argv);
    parse_active_vars_file(filename);

	// filename = get_arg("logger", argc, argv);
	// load_logger_config(filename);

	filename = get_arg("monitor", argc, argv);
	// runtime = filename; // Lazy Init

    const char* pass_in_dump_path = get_arg("dump_path", argc, argv);
    if (pass_in_dump_path) {
        strncpy(dump_path, pass_in_dump_path, sizeof(dump_path) - 1);
    }
    printf("Dump path set to: %s\n", dump_path);

    const char* sub_semantics_mode_str = get_arg("sub_semantics_mode", argc, argv);
    if (sub_semantics_mode_str && strcmp(sub_semantics_mode_str, "1") == 0) {
        is_sub_semantics_mode = true;
        printf("Sub-semantics mode enabled\n");
    }

    const char* sub_semantic_last_stage_str = get_arg("sub_semantic_last_stage", argc, argv);
    if (sub_semantic_last_stage_str && strcmp(sub_semantic_last_stage_str, "1") == 0) {
        is_sub_semantic_last_stage = true;
        printf("Sub-semantics last stage enabled\n");
    }

    const char* stage_num_str = get_arg("stage_num", argc, argv);
    if (stage_num_str) {
        stage_num = atoi(stage_num_str);
        printf("Stage number set to: %zu\n", stage_num);
    }

    // Phase-2 (coverage-guided range widening): override the ranges used for DISCOVERED
    // fields so the outer loop can progressively widen them. Format "lo:hi" (colon, NOT
    // comma -- QEMU splits the --plugin argument on commas). Absent -> compiled-in
    // defaults ({0,3} int, {0.5,5} float) are kept.
    const char* int_range_str = get_arg("int_range", argc, argv);
    if (int_range_str && sscanf(int_range_str, "%d:%d", &default_int_range[0], &default_int_range[1]) == 2) {
        printf("[VI] default_int_range override: [%d, %d]\n", default_int_range[0], default_int_range[1]);
    }
    const char* demote_range_str = get_arg("demote_range", argc, argv);
    if (demote_range_str && sscanf(demote_range_str, "%d:%d", &demote_int_range[0], &demote_int_range[1]) == 2) {
        printf("[VI] demote_int_range override: [%d, %d]\n", demote_int_range[0], demote_int_range[1]);
    }
    const char* float_range_str = get_arg("float_range", argc, argv);
    if (float_range_str && sscanf(float_range_str, "%f:%f", &default_float_range[0], &default_float_range[1]) == 2) {
        printf("[VI] default_float_range override: [%g, %g]\n", default_float_range[0], default_float_range[1]);
    }

	// qemu_plugin_unimp_export_device((void *)&importer);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
