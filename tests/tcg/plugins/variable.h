#ifndef VARIABLE_H
#define VARIABLE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <cjson/cJSON.h>

// ===============================================================================================================================
// Basic args structs
// ===============================================================================================================================

#define MAX_NAME 32  // maximum length for argument name, register name, etc. 
#define MAX_REG 8  // maximum length for register name (e.g., "eax", "xmm0", etc.)
#define MAX_ARGS 1000 // maximum distinct argument objects
#define MAX_REACHDEFS 1000 // maximum distinct reaching definitions


typedef enum {
    TYPE_REG,
    TYPE_ADDR,
} ValueLocationType;

typedef enum {
    TYPE_UNKNOWN,
    TYPE_FLOAT,
    TYPE_DOUBLE,
    TYPE_UINT32,
    TYPE_UINT16,
    TYPE_UINT8,
} IOValueType;

typedef enum {
    IS_PTR_TRUE,
    IS_PTR_FALSE,
    IS_PTR_UNKNOWN
} IsPointerType;

typedef union {
    float f;
    double d; // heuristic: all 8 bytes struct are double (todo: improve)
    uint32_t u32; // heuristic: only int less than 4 bytes (uint16 & uint8), and reuse the uint32_t field (todo: 8 bytes int?)
    uint64_t u64;
} ValueUnion;

// type to string
const char* io_value_type_to_string(IOValueType type);
const char* io_value_type_to_string(IOValueType type) {
    switch (type) {
        case TYPE_FLOAT:   return "float";
        case TYPE_DOUBLE:  return "double";
        case TYPE_UINT32:  return "uint32";
        case TYPE_UINT16:  return "uint16";
        case TYPE_UINT8:   return "uint8";
        case TYPE_UNKNOWN: return "unknown";
    }
    return "unknown";
}

const char* is_pointer_type_to_string(IsPointerType type);
const char* is_pointer_type_to_string(IsPointerType type) {
    switch (type) {
        case IS_PTR_TRUE:    return "true";
        case IS_PTR_FALSE:   return "false";
        case IS_PTR_UNKNOWN: return "unknown";
    }
    return "unknown";
}

// input variable struct
typedef struct {
    char name[MAX_NAME];

    ValueLocationType location_type; /* register or addr, exactly one of the two will be set */
    char reg[MAX_REG];
    unsigned long addr;
    size_t sz; // size in bytes

    IsPointerType is_pointer; /* whether the value is a pointer */

    IOValueType vtype;
    ValueUnion value_range[2]; /* one- or two-element range */
    size_t value_count;

    int non_ptr_iters; /* iterator for non-pointer values */

    ValueUnion concrete_value; /* for logging concrete input for paths */
    // for mem var calling interface
    char base_ptr_var_name[MAX_NAME]; // empty string if no parent pointer variable (struct var) for this mem arg
    int base_ptr_offset;

    // for mem arg analysis in sub-semantics recovery
    // bool is_written;
    // bool is_read;
    // bool is_sub_semantic_input; /* whether this arg is used in sub-semantics */
    int defined_stage; /* stage the reaching defintion comes from, used for sub-semantics recovery to track the reaching definition, set to -1 for non-sub-semantic mode */
                       /* -1 indicates the input for the function */
                       /* -2 indicates reach def not found */
    int is_redefined; /* whether the arg is re-defined during sub-semantic data dependency analysis */
} ArgSetting;

void init_arg_setting(ArgSetting *setting);
void init_arg_setting(ArgSetting *setting) {
    setting->location_type = TYPE_UNKNOWN;
    setting->reg[0] = '\0';
    setting->addr = 0;
    setting->sz = 0;
    setting->is_pointer = IS_PTR_UNKNOWN;
    setting->vtype = TYPE_UNKNOWN;
    setting->value_count = 0;
    setting->non_ptr_iters = 0;
    setting->concrete_value.u64 = 0;

    setting->base_ptr_var_name[0] = '\0';
    setting->base_ptr_offset = 0;

    // setting->is_written = false;
    // setting->is_read = false;
    // setting->is_sub_semantic_input = false;
    setting->defined_stage = -1;
    setting->is_redefined = 0;
}

void copy_arg_setting(ArgSetting *dest, const ArgSetting *src);
void copy_arg_setting(ArgSetting *dest, const ArgSetting *src) {
    dest->location_type = src->location_type;
    strncpy(dest->reg, src->reg, sizeof(dest->reg) - 1);
    dest->reg[sizeof(dest->reg) - 1] = '\0';
    dest->addr = src->addr;
    dest->sz = src->sz;
    dest->is_pointer = src->is_pointer;
    dest->vtype = src->vtype;
    dest->value_count = src->value_count;
    for (size_t i = 0; i < src->value_count && i < 2; i++) {
        dest->value_range[i] = src->value_range[i];
    }
    dest->non_ptr_iters = src->non_ptr_iters;
    dest->concrete_value = src->concrete_value;

    strncpy(dest->base_ptr_var_name, src->base_ptr_var_name, sizeof(dest->base_ptr_var_name) - 1);
    dest->base_ptr_var_name[sizeof(dest->base_ptr_var_name) - 1] = '\0';
    dest->base_ptr_offset = src->base_ptr_offset;

    // dest->is_written = src->is_written;
    // dest->is_read = src->is_read;
    // dest->is_sub_semantic_input = src->is_sub_semantic_input;
    dest->defined_stage = src->defined_stage;
    dest->is_redefined = src->is_redefined;
}

// output variable struct
typedef struct {
    char name[MAX_NAME];

    // unsigned long xaddr; // target address to examine output value

    /* Exactly one of the two will be set */
    ValueLocationType location_type; /* register or addr */
    char reg[MAX_REG];
    unsigned long addr;
    size_t sz; // size in bytes

    IOValueType vtype;
    // Buffy log_buf; // needed by tcg logger, use VI for now

    ValueUnion concrete_value;

    unsigned long written_time; // timestamp when this ret value is written

    int defined_stage; /* stage the variable is defined, used for sub-semantics recovery to track the reaching definition, set to -1 for non-sub-semantic mode */
                       /* -1 indicates function input */
} RetSetting;

void init_ret_setting(RetSetting *s);
void init_ret_setting(RetSetting *s) {
    s->location_type = TYPE_REG; // default to reg, can be overwritten by JSON
    s->reg[0] = '\0';
    s->addr = 0;
    s->sz = 0;
    s->vtype = TYPE_UNKNOWN;
    s->concrete_value.u64 = 0;
    s->written_time = 0;
    s->defined_stage = -1;
}

void copy_arg_setting_from_ret_setting(ArgSetting *arg_setting, const RetSetting *ret_setting);
void copy_arg_setting_from_ret_setting(ArgSetting *arg_setting, const RetSetting *ret_setting) {
    arg_setting->location_type = ret_setting->location_type;
    strncpy(arg_setting->reg, ret_setting->reg, sizeof(arg_setting->reg) - 1);
    arg_setting->reg[sizeof(arg_setting->reg) - 1] = '\0';
    arg_setting->addr = ret_setting->addr;
    arg_setting->sz = ret_setting->sz;
    arg_setting->vtype = ret_setting->vtype;
    // arg_setting->concrete_value = ret_setting->concrete_value;
    arg_setting->defined_stage = ret_setting->defined_stage;
}

// ===============================================================================================================================
// variable struct utilities
// ===============================================================================================================================
// check whether variables match
int same_mem_locs(const ArgSetting *a, uint64_t addr, size_t sz);
int same_mem_locs(const ArgSetting *a, uint64_t addr, size_t sz)
{
    if (a->location_type != TYPE_ADDR) return 0; /* not a memory location */
    if (a->sz == 0 || sz == 0) return 0; /* unknown size */
    if (a->addr == addr && a->sz == sz) return 1; /* exact match */
    return 0; /* no match */
}

int same_mem_locs_ret(const RetSetting *r, uint64_t addr);
int same_mem_locs_ret(const RetSetting *r, uint64_t addr)
{
    if (r->location_type != TYPE_ADDR) return 0; /* not a memory location */
    if (r->addr == addr) return 1; /* exact match */
    return 0; /* no match */
}

// check whether variables overlap
int overlap_mem_locs(const ArgSetting *a, uint64_t addr, size_t sz);
int overlap_mem_locs(const ArgSetting *a, uint64_t addr, size_t sz)
{
    if (a->location_type != TYPE_ADDR) return 0; /* not a memory location */
    if (a->sz == 0 || sz == 0) return 0; /* unknown size */
    if (same_mem_locs(a, addr, sz)) return 0; /* exact match */
    if (a->addr < addr + sz && addr < a->addr + a->sz) return 1; /* overlap */
    return 0; /* not overlap */
}

// find pointer arg setting by memory address the pointer points to
// return the index in arg_settings, or -1 if not found
int find_ptr_arg_by_addr(unsigned long addr, size_t sz, ArgSetting *asettings, size_t *acount); 
int find_ptr_arg_by_addr(unsigned long addr, size_t sz, ArgSetting *asettings, size_t *acount) {
    for (size_t i = 0; i < *acount; i++) {
        ArgSetting *s = &asettings[i];
        // if (s->location_type == TYPE_ADDR && s->is_pointer == IS_PTR_TRUE) {
        //     if (addr == s->addr && sz == s->sz) {
        //         return (int)i;
        //     }
        // }
        if ((s->is_pointer == IS_PTR_TRUE || s->is_pointer == IS_PTR_UNKNOWN) && s->vtype == TYPE_UINT32 && s->value_count == 1) {
            if (addr == s->value_range[0].u32 && sz == s->sz) {
                return (int)i;
            }
        }
    }
    return -1;
}

// dump arg setting for debugging
void print_arg_setting(ArgSetting *setting);
void print_arg_setting(ArgSetting *setting) {
    printf("Arg name: %s, location_type: %s, ", setting->name,
           setting->location_type == TYPE_REG ? "reg" :
           setting->location_type == TYPE_ADDR ? "addr" : "unknown");
    if (setting->location_type == TYPE_REG) {
        printf("reg: %s, ", setting->reg);
    } else if (setting->location_type == TYPE_ADDR) {
        printf("addr: 0x%lx, ", setting->addr);
    }
    printf("size: %zu, is_pointer: %s, type: %s, value_count: %zu\n",
           setting->sz,
           is_pointer_type_to_string(setting->is_pointer),
           io_value_type_to_string(setting->vtype),
           setting->value_count);
    printf("value_range: [");
    for (size_t i = 0; i < setting->value_count && i < 2; i++) {
        if (setting->vtype == TYPE_FLOAT) {
            printf("%g", setting->value_range[i].f);
        } else if (setting->vtype == TYPE_DOUBLE) {
            printf("%g", setting->value_range[i].d);
        } else if (setting->vtype == TYPE_UINT32) {
            printf("%u", setting->value_range[i].u32);
        } else if (setting->vtype == TYPE_UINT16) {
            printf("%u", setting->value_range[i].u32);
        } else if (setting->vtype == TYPE_UINT8) {
            printf("%u", setting->value_range[i].u32);
        }
    }
    printf("]\n");
}

// dump asettings for debugging
void print_arg_settings(ArgSetting *asettings, size_t *acount);
void print_arg_settings(ArgSetting *asettings, size_t *acount)
{
    puts("Parsed arguments:");
    for (size_t i = 0; i < *acount; ++i) {
        const ArgSetting *p = &asettings[i];
        if (p->vtype == TYPE_UNKNOWN) {
            printf("Arg %zu: name='%s', type=unknown, location_type=%s, ",
                   i, p->name,
                   p->location_type == TYPE_REG ? "reg" : "addr");
        } else if (p->vtype == TYPE_FLOAT) {
            printf("Arg %zu: name='%s', type=float, location_type=%s, ",
                   i, p->name,
                   p->location_type == TYPE_REG ? "reg" : "addr");
        } else if (p->vtype == TYPE_DOUBLE) {
            printf("Arg %zu: name='%s', type=double, location_type=%s, ",
                   i, p->name,
                   p->location_type == TYPE_REG ? "reg" : "addr");
        } else if (p->vtype == TYPE_UINT32) {
            printf("Arg %zu: name='%s', type=uint32, location_type=%s, ",
                   i, p->name,
                   p->location_type == TYPE_REG ? "reg" : "addr");
        } else if (p->vtype == TYPE_UINT16) {
            printf("Arg %zu: name='%s', type=uint16, location_type=%s, ",
                   i, p->name,
                   p->location_type == TYPE_REG ? "reg" : "addr");
        } else if (p->vtype == TYPE_UINT8) {
            printf("Arg %zu: name='%s', type=uint8, location_type=%s, ",
                   i, p->name,
                   p->location_type == TYPE_REG ? "reg" : "addr");
        } else {
            fprintf(stderr, "Unknown type for argument '%s'\n", p->name);
            exit(EXIT_FAILURE);
        }
        if (p->location_type == TYPE_REG) {
            printf("reg=%s, ", p->reg);
        } else if (p->location_type == TYPE_ADDR) {
            printf("addr=0x%lx, ", p->addr);
        }

        if (p->sz != 0) {
            printf("size=%zu bytes, ", p->sz);
        } else {
            printf("size=unknown, ");
        }

        if (p->is_pointer == IS_PTR_TRUE) {
            printf("is_pointer=true, ");
        } else if (p->is_pointer == IS_PTR_FALSE) {
            printf("is_pointer=false, ");
        } else {
            printf("is_pointer=unknown, ");
        }

        printf("value_range=[");
        for (size_t j = 0; j < p->value_count; ++j) {
            if (p->vtype == TYPE_FLOAT) {
                printf("%g%s", p->value_range[j].f,
                       j + 1 == p->value_count ? "" : ", ");
            } else if (p->vtype == TYPE_DOUBLE) {
                printf("%g%s", p->value_range[j].d,
                       j + 1 == p->value_count ? "" : ", ");
            } else if (p->vtype == TYPE_UINT32) {
                printf("%u%s", p->value_range[j].u32,
                       j + 1 == p->value_count ? "" : ", ");
            }
        }
        printf("]\n");
    }
}

// print ret settings for debugging
void print_ret_settings(RetSetting* rsettings, size_t rcount);
void print_ret_settings(RetSetting* rsettings, size_t rcount)
{
    printf("Parsed %zu ret settings:\n", rcount);
    for (size_t i = 0; i < rcount; ++i) {
        const RetSetting *p = &rsettings[i];
        if (p->vtype == TYPE_UNKNOWN) {
            printf("Ret %zu: name='%s', type=unknown, location_type=%s, ",
                   i, p->name,
                   p->location_type == TYPE_REG ? "reg" : "addr");
        } else if (p->vtype == TYPE_FLOAT) {
            printf("Ret %zu: name='%s', type=float, location_type=%s, ",
                   i, p->name,
                   p->location_type == TYPE_REG ? "reg" : "addr");
        } else if (p->vtype == TYPE_UINT32) {
            printf("Ret %zu: name='%s', type=uint32, location_type=%s, ",
                   i, p->name,
                   p->location_type == TYPE_REG ? "reg" : "addr");
        } else if (p->vtype == TYPE_DOUBLE) {
            printf("Ret %zu: name='%s', type=double, location_type=%s, ",
                   i, p->name,
                   p->location_type == TYPE_REG ? "reg" : "addr");
        } else {
            fprintf(stderr, "Unknown type for ret '%s'\n", p->name);
            exit(1);
        }

        if (p->location_type == TYPE_REG) {
            printf("reg=%s, ", p->reg);
        } else if (p->location_type == TYPE_ADDR) {
            printf("addr=0x%lx, ", p->addr);
        }
        // printf("xaddr=0x%lx\n", p->xaddr);
        printf("\n");
    }
}


// ===============================================================================================================================
// globals
// ===============================================================================================================================
// input
ArgSetting arg_settings[MAX_ARGS];
size_t arg_count = 0;

// output
RetSetting ret_settings[MAX_ARGS];
size_t ret_count = 0;
unsigned long cur_timestamp = 0; // global timestamp for ret value writes

// for sub-semantic analysis, track the argument settings at function entry that tigger the specific execution path
ArgSetting func_start_arg_settings[MAX_ARGS];
size_t func_start_arg_count = 0;

// for sub-semantic analysis, track memory variable definition
ArgSetting active_var_defs[MAX_ARGS];
size_t active_var_defs_count = 0;
// match_var_defs[i] & match_var_uses[i] denote a reaching definition
int match_var_defs[MAX_REACHDEFS]; // index in active_var_defs for the reaching definition that matches the memory variable in sub-semantic execution stage, -1 if not found
int match_var_uses[MAX_REACHDEFS]; // index in arg_settings for the input argument that matches the reaching definition in sub-semantic execution stage, must be non-negative
size_t match_reachdef_count = 0; // number of reaching definitions tracked
#endif // VARIABLE_H
