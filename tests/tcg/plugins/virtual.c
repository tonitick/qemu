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
#include "json_parse.h"
#include "path_logger.h"
#include "capstone_util.h"
#include "struct_recovery.h"
#include "logger.h"
#include "modifier.h"
#include "detour.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
// int counter;

// #define HOOK_POINT	(0x106d6)
// #define ANCHOR		(0x106cc)

char dump_path[256] = "collected_data";
int default_int_range[2] = {0, 2};
float default_float_range[2] = {0.5, 5.0};
double default_double_range[2] = {0.5, 5.0};

// typedef unsigned long hwaddr;
// typedef struct unimp_exporter {
//     uint64_t (*read)(void *opaque, hwaddr offset, unsigned size);
//     void (*write)(void *opaque, hwaddr offset, uint64_t value, unsigned size);
// } DEV_XPORTER;

// static const char * runtime;

// --------------------------------------------------------------------------------------
// randargs
// --------------------------------------------------------------------------------------
unsigned char get_random_byte(void);
unsigned char get_random_byte(void) {
	//This will make things linux specific, but lot of hardcoded things.
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        perror("fopen /dev/urandom");
        exit(EXIT_FAILURE);
    }

    unsigned char byte;
    size_t result = fread(&byte, 1, 1, fp);
    fclose(fp);

    if (result != 1) {
        fprintf(stderr, "Failed to read from /dev/urandom\n");
        exit(EXIT_FAILURE);
    }

    return byte;
}
uint32_t get_random_word(void);
uint32_t get_random_word(void) {
    //This will make things linux specific, but lot of hardcoded things.
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        perror("fopen /dev/urandom");
        exit(EXIT_FAILURE);
    }

    uint32_t word;
    size_t result = fread(&word, sizeof(uint32_t), 1, fp);
    fclose(fp);

    if (result != 1) {
        fprintf(stderr, "Failed to read from /dev/urandom\n");
        exit(EXIT_FAILURE);
    }

    return word;
}

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

float get_random_float(float min, float max);
float get_random_float(float min, float max) {
    // Generate a random float in the range [min, max]
    unsigned int random_word = get_random_word();
    return min + (random_word / (float)UINT32_MAX) * (max - min);
}

double get_random_double(double min, double max);
double get_random_double(double min, double max) {
    // Generate a random double in the range [min, max]
    unsigned int random_word = get_random_word();
    return (double)(((float)min + (random_word / (float)UINT32_MAX) * ((float)max - (float)min)));
}

static int cur_iteration = 0;
#define MAX_FUZZ_ITERATIONS 10000000
static void randargs(unsigned int cpu_index, void *udata) {
    // print pc for debugging
    uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
    printf("[VI randargs] Current PC: 0x%08x\n", pc);

    function_reached = true;

    // printf("randargs - results for iteration %d:\n", cur_iteration);
    if (cur_iteration >= MAX_FUZZ_ITERATIONS) {
        printf("[VI randargs] reached max fuzzing iterations %d, dump existing path logs andexiting\n", MAX_FUZZ_ITERATIONS);
        dump_existing_path_logs(dump_path);
        exit(0);
    }
    if (check_path_log_size_and_dump(dump_path)) {
        printf("[VI randargs] log finished, dump related path logs\n");
        // dump_all_path_logs();
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
        // record_trace_values(current_path, current_path_len, logged_in_values, logged_out_values);
        record_trace_values(current_path, current_path_len);
        // }
        // clear
        // current_path_len = 0;
    }
    else if (!is_logging_valid) {
        clear_all_path_logs(); // zz: log only when arg settings can stably generate valid logs
        // printf("[VI randargs] dump path log after clear:\n");
        // dump_all_path_logs();

        // dump arg settings for debugging
        printf("[VI randargs] previous iteration logging invalid, fix arg settings\n");
        dump_arg_settings();
        // fix all unknown pointer args to non-pointer integers
        // TODO: take care of the control flows, assume the same path for now
    }

    // increment non_ptr_iters for all unknown pointer args
    for (size_t i = 0; i < arg_count; i++) {
        ArgSetting *setting = &arg_settings[i];
        if (setting->vtype == TYPE_UINT32 && setting->is_pointer == IS_PTR_UNKNOWN) {
            setting->non_ptr_iters++;
            printf("[VI randargs] unknown pointer arg '%s' has been tried %d times\n", setting->name, setting->non_ptr_iters);
            if (setting->non_ptr_iters > NON_PTR_ITER_MAX) {
                printf("[VI randargs] fixing unknown pointer arg '%s' to non-pointer integer after %d tries\n", setting->name, setting->non_ptr_iters);
                if (setting->location_type == TYPE_ADDR) { // heuristic: all 4 bytes struct are floats (todo: improve)
                    // set to float
                    setting->is_pointer = IS_PTR_FALSE;
                    setting->vtype = TYPE_FLOAT;
                    setting->value_count = 2;
                    setting->value_range[0].f = default_float_range[0];
                    setting->value_range[1].f = default_float_range[1];

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
            }
        }
    }

    current_path_len = 0;

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
                // Generate a random float in the range
                value.f = get_random_float(setting->value_range[0].f, setting->value_range[1].f);
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
            qemu_plugin_set_register((uint8_t *)&value, get_reg_by_name(setting->reg)); // TODO: check with arslan, looks like it write 8 bytes for all float regs?
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

// --------------------------------------------------------------------------------------
// clearpathlogs, logbbstart
// --------------------------------------------------------------------------------------
static void clearpathlogs(unsigned int cpu_index, void *udata) {
    // Clear all path logs
    clear_all_path_logs();
}

static void logbbstart(unsigned int cpu_index, void *udata) {
    // get pc vlue
    uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
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
    fprintf(stdout, "[MEMCB update_addr_var_mem_cb] @ 0x%08" PRIx64 " (%u-byte %s), pc=0x%08x\n",
            vaddr, sz_bytes, is_store ? "STORE" : "LOAD", qemu_get_register_32(ARM_V7M_REG_R15)); // warn: this could still be the start of tb
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
        printf("[MEMCB update_addr_var_mem_cb] No matching arg setting for address 0x%lx, creating new float setting\n", vaddr);
        // create new arg setting
        if (arg_count >= MAX_ARGS) {
            fprintf(stderr, "Maximum argument settings reached, cannot add new setting for address 0x%lx\n", vaddr);
            exit(EXIT_FAILURE);
        }
        int parent_allocated_struct_idx = find_parent_struct_by_addr(vaddr, sz_bytes);
        if (parent_allocated_struct_idx >= 0) {
            assert(parent_allocated_struct_idx < allocated_struct_count);
            unsigned long parent_allocated_addr = allocated_structs[parent_allocated_struct_idx]->loc.addr;
            printf("[MEMCB update_addr_var_mem_cb] Found parent struct allocated at address 0x%lx\n", parent_allocated_addr);
            // assert(allocated_structs[parent_allocated_struct_idx]->is_pointer);
            size_t parent_ptr_size = allocated_structs[parent_allocated_struct_idx]->size;
            int parent_arg_setting_idx = find_ptr_arg_by_addr(parent_allocated_addr, parent_ptr_size);
            assert(parent_arg_setting_idx >= 0 && parent_arg_setting_idx < arg_count);
            struct NestedStruct *parent_struct = allocated_structs[parent_allocated_struct_idx];
            parent_struct->is_pointer = IS_PTR_TRUE; // mark as pointer

            // create new arg setting based on parent
            size_t offset = vaddr - parent_allocated_addr;
            ArgSetting *parent_setting = &arg_settings[parent_arg_setting_idx];
            parent_setting->is_pointer = IS_PTR_TRUE; // mark as pointer
            ArgSetting *new_setting = &arg_settings[arg_count++];
            snprintf(new_setting->name, sizeof(new_setting->name), "%s_off_%zu", parent_setting->name, offset);
            new_setting->location_type = TYPE_ADDR;
            new_setting->addr = vaddr;
            new_setting->sz = sz_bytes;
            // new_setting->vtype = TYPE_FLOAT;
            if (sz_bytes == 4) {
                new_setting->vtype = TYPE_UINT32; // treat as (unknown) pointer first
                new_setting->is_pointer = IS_PTR_UNKNOWN;
                new_setting->non_ptr_iters = 0;
                // handle struct allocation
                new_setting->value_count = 1;
                new_setting->value_range[0].u32 = cur_ptr_addr;
                assert(new_setting->sz == 4); // 4 bytes addr size in arm
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
            qemu_plugin_vcpu_exit_tb_now();
            // // set pc back to function start
            // ValueUnion func_start_pc;
            // func_start_pc.u32 = func_start;
            // qemu_plugin_set_register((uint8_t *)&func_start_pc, ARM_V7M_REG_R15);
            // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
            // printf("[MEMCB update_addr_var_mem_cb] set PC back to function start: 0x%08x\n", pc);
            // return;
        }
        // ArgSetting *new_setting = &arg_settings[arg_count++];
        // printf("[MEMCB update_addr_var_mem_cb] New float setting creation for address 0x%lx done\n", vaddr);
    }
}

static void update_float_addr_var_mem_cb(unsigned int vcpu_index,
                   qemu_plugin_meminfo_t info, uint64_t vaddr, void *udata) {
    if (!function_reached) return;

    unsigned sz_shift = qemu_plugin_mem_size_shift(info);  // 0=8b,1=16b,2=32b,3=64b,...
    unsigned sz_bytes = 1u << sz_shift; // 1,2,4,8 bytes
    int is_store = qemu_plugin_mem_is_store(info);
    // check pc
    // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
    fprintf(stdout, "[MEMCB update_float_addr_var_mem_cb] @ 0x%08" PRIx64 " (%u-bit %s), pc=0x%08x\n",
            vaddr, 8u << sz_shift, is_store ? "STORE" : "LOAD", qemu_get_register_32(ARM_V7M_REG_R15));
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
                qemu_plugin_vcpu_exit_tb_now();
                // // set pc back to function start
                // ValueUnion func_start_pc;
                // func_start_pc.u32 = func_start;
                // qemu_plugin_set_register((uint8_t *)&func_start_pc, ARM_V7M_REG_R15);
                // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
                // printf("[MEMCB update_float_addr_var_mem_cb] set PC back to function start: 0x%08x\n", pc);
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
                qemu_plugin_vcpu_exit_tb_now();
                // // set pc back to function start
                // ValueUnion func_start_pc;
                // func_start_pc.u32 = func_start;
                // qemu_plugin_set_register((uint8_t *)&func_start_pc, ARM_V7M_REG_R15);
                // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
                // printf("[MEMCB update_float_addr_var_mem_cb] set PC back to function start: 0x%08x\n", pc);
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
        if (parent_allocated_struct_idx >= 0) {
            assert(parent_allocated_struct_idx < allocated_struct_count);
            unsigned long parent_allocated_addr = allocated_structs[parent_allocated_struct_idx]->loc.addr;
            printf("[MEMCB update_float_addr_var_mem_cb] Found parent struct allocated at address 0x%lx\n", parent_allocated_addr);
            // assert(allocated_structs[parent_allocated_struct_idx]->is_pointer);
            size_t parent_ptr_size = allocated_structs[parent_allocated_struct_idx]->size;
            int parent_arg_setting_idx = find_ptr_arg_by_addr(parent_allocated_addr, parent_ptr_size);
            assert(parent_arg_setting_idx >= 0 && parent_arg_setting_idx < arg_count);
            struct NestedStruct *parent_struct = allocated_structs[parent_allocated_struct_idx];
            parent_struct->is_pointer = IS_PTR_TRUE; // mark as pointer

            // create new arg setting based on parent
            size_t offset = vaddr - parent_allocated_addr;
            ArgSetting *parent_setting = &arg_settings[parent_arg_setting_idx];
            parent_setting->is_pointer = IS_PTR_TRUE; // mark as pointer
            ArgSetting *new_setting = &arg_settings[arg_count++];
            snprintf(new_setting->name, sizeof(new_setting->name), "%s_off_%zu", parent_setting->name, offset);
            new_setting->location_type = TYPE_ADDR;
            new_setting->addr = vaddr;
            new_setting->sz = sz_bytes;
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
            qemu_plugin_vcpu_exit_tb_now();
            // // set pc back to function start
            // ValueUnion func_start_pc;
            // func_start_pc.u32 = func_start;
            // qemu_plugin_set_register((uint8_t *)&func_start_pc, ARM_V7M_REG_R15);
            // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
            // printf("[MEMCB update_float_addr_var_mem_cb] set PC back to function start: 0x%08x\n", pc);
            // return;
        }
        // ArgSetting *new_setting = &arg_settings[arg_count++];
        // printf("[MEMCB update_float_addr_var_mem_cb] New float setting creation for address 0x%lx done\n", vaddr);
    }
    // }
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

		// if (qemu_plugin_insn_vaddr(insn) == 0x20800050) {
		// 		//Magic instruction
		// 		qemu_plugin_u64 entry_tmp;
        //         // In TCG frontend it is already set, if you want to modify it you will have to
        //         // change CPSR.
        //         entry_tmp.data = NULL;
		// 		qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_UPDATE_REG, entry_tmp, -1);
		// 		return;
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



		// //Second to Highest priority: Modifier
		// //void * handle= qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn,  QEMU_PLUGIN_CB_GEN_LABEL, NULL, 0);
		// size_t count = find_updates_for_address(qemu_plugin_insn_vaddr(insn), matches, MAX_MATCHES);
		// if (count > 0) {
		// for (size_t match_idx = 0; match_idx < count; ++match_idx) {
		// 	UpdateEntry *e = matches[match_idx];

		// 	printf("  Update Point: 0x%lx, ", e->update_point);
	    //     if (e->type == TARGET_REGISTER || e->type == TARGET_DEREF) {
    	//         printf("Target: r%d, ", e->target.reg_num);
		// 		qemu_plugin_u64 entry;
        //         // In TCG frontend it is already set, if you want to modify it you will have to
        //         // change CPSR.
        //         entry.offset = (size_t)(e->value.imm);
		// 		entry.data = (void *)e;
        //         qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_UPDATE_REG, entry, e->target.reg_num);
	    //     } else if (e->type == TARGET_MEMORY) {
		// 		printf("Target: r%d, ", e->target.reg_num);
        //         qemu_plugin_u64 entry;
        //         // In TCG frontend it is already set, if you want to modify it you will have to
        //         // change CPSR.
        //         entry.offset = (size_t)(e->value.imm);
        //         qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_UPDATE_MEM, entry, e->target.addr);
    	//         printf("Target: 0x%lx, ", e->target.addr);
       	// 	}

    	// }
		// }

        // install logpc vi for all instructions
        // qemu_plugin_register_vcpu_insn_exec_cb(insn, logpc, QEMU_PLUGIN_CB_RW_REGS, NULL); // zz: this may not show the exact pc changes, pc may keep for few instructions

		//Middle prioirity is Virtual instructions (randargs, logrets)
		rule_t  *rule;
        if (find_rule_by_address(qemu_plugin_insn_vaddr(insn), &rule)) {
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, rule->func, QEMU_PLUGIN_CB_RW_REGS, rule->args);
        }
        // zz: logbbstart for bb_starts addresses
        for (size_t j = 0; j < bb_count; j++) {
            if (bb_starts[j] == qemu_plugin_insn_vaddr(insn)) {
                // Register the callback for bb start
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, logbbstart, QEMU_PLUGIN_CB_RW_REGS, NULL);
            }
        }

        // install resetpc vi for all instructions
        // qemu_plugin_register_vcpu_insn_exec_cb(insn, resetpc, QEMU_PLUGIN_CB_RW_REGS, NULL); // zz: this not work, use qemu_plugin_vcpu_exit_tb_now


        // [zz] moemory callbacks after VI for:
        //      (1) dynamic struct field identification
        //      (2) dynamic variable type identification (float vs int)
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
                qemu_plugin_register_vcpu_mem_cb(insn, update_float_addr_var_mem_cb, QEMU_PLUGIN_CB_RW_REGS, QEMU_PLUGIN_MEM_RW, NULL);
                printf("    [INSTALL disas] 0x%lx:\t%s\t%s \n", csinsn[0].address, csinsn[0].mnemonic, csinsn[0].op_str);
            }
            // check if the instructino access memory
            else if (arm_insn_accesses_mem(csinsn)) {
                printf("    [INSTALL mem] instruction @0x%08lx accesses memory\n", csinsn[0].address);
                qemu_plugin_register_vcpu_mem_cb(insn, update_addr_var_mem_cb, QEMU_PLUGIN_CB_RW_REGS, QEMU_PLUGIN_MEM_RW, NULL);
                printf("    [INSTALL disas] 0x%lx:\t%s\t%s \n", csinsn[0].address, csinsn[0].mnemonic, csinsn[0].op_str);
            }


        } else {
            printf("[INSTALL disas] <disas error>\n");
        }
        g_byte_array_free(inst_bytes, TRUE);

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

		//Lowest priority is detour
		AddressTuple * tuple = is_target_address(qemu_plugin_insn_vaddr(insn));
        if (tuple) {
                qemu_plugin_u64 entry;
                // In TCG frontend it is already set, if you want to modify it you will have to
                // change CPSR.
                entry.offset = (tuple->anchor & ~(0x1));
                qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_UPDATE_REG, entry, 15);
        }
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

    filename = get_arg("args", argc, argv);
    parse_json_args(filename);

    filename = get_arg("outs", argc, argv);
    parse_json_outs(filename);

    filename = get_arg("basicblocks", argc, argv);
    parse_basic_block_file(filename);

    filename = get_arg("function_starts", argc, argv);
    parse_function_start_file(filename);

    filename = get_arg("function_ends", argc, argv);
    parse_function_end_file(filename);

	// filename = get_arg("logger", argc, argv);
	// load_logger_config(filename);

	filename = get_arg("monitor", argc, argv);
	// runtime = filename; // Lazy Init

    const char* pass_in_dump_path = get_arg("dump_path", argc, argv);
    if (pass_in_dump_path) {
        strncpy(dump_path, pass_in_dump_path, sizeof(dump_path) - 1);
    }
    printf("Dump path set to: %s\n", dump_path);


	// qemu_plugin_unimp_export_device((void *)&importer);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
