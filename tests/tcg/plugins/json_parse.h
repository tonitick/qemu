#ifndef JSON_PARSE_H
#define JSON_PARSE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <cjson/cJSON.h>

// ===============================================================================================================================
// File helpers
// ===============================================================================================================================
char *read_file_to_buf(const char *path);
char *read_file_to_buf(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "cannot open '%s': %s\n", path, strerror(errno));
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    rewind(fp);

    char *buf = malloc((size_t)len + 1);
    if (!buf) {
        fprintf(stderr, "out of memory\n");
        fclose(fp);
        return NULL;
    }
    if (fread(buf, 1, (size_t)len, fp) != (size_t)len) {
        fprintf(stderr, "short read from '%s'\n", path);
        free(buf);
        fclose(fp);
        return NULL;
    }
    buf[len] = '\0';
    fclose(fp);
    return buf;
}


// ===============================================================================================================================
// Basic args structs
// ===============================================================================================================================

#define MAX_NAME  32
#define MAX_REG    8
#define MAX_ARGS  100          /* maximum distinct argument objects */


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


// ===============================================================================================================================
// input
// ===============================================================================================================================

/* -------------------------------------------------------------------------- */
/* Data structure describing one argument                                     */
/* -------------------------------------------------------------------------- */
#define NON_PTR_ITER_MAX 50
typedef struct {
    char name[MAX_NAME];

    /* Exactly one of the two will be set */
    ValueLocationType location_type; /* register or addr */
    char reg[MAX_REG];
    unsigned long addr;
    size_t sz; // size in bytes

    IsPointerType is_pointer; /* whether the value is a pointer */

    IOValueType vtype;
    ValueUnion value_range[2]; /* one- or two-element range */
    size_t value_count;

    int non_ptr_iters; /* iterator for non-pointer values */

    ValueUnion concrete_value; /* for logging concrete input for paths */

    // for mem arg analysis for sub-semantics recovery
    bool is_written;
    bool is_read;
    bool is_sub_semantic_input; /* whether this arg is used in sub-semantics */
} ArgSetting;
ArgSetting arg_settings[MAX_ARGS];
size_t arg_count = 0;

int find_ptr_arg_by_addr(unsigned long addr, size_t sz); // return the index in arg_settings, or -1 if not found
int find_ptr_arg_by_addr(unsigned long addr, size_t sz) {
    for (size_t i = 0; i < arg_count; i++) {
        ArgSetting *s = &arg_settings[i];
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

/* -------------------------------------------------------------------------- */
/* Parsing utilities (parse_json_args)                                        */
/* -------------------------------------------------------------------------- */
// parse
void parse_arg_settings(const char *json);
void parse_arg_settings(const char *json)
{
    cJSON *root = cJSON_Parse(json);
    if (!root || !cJSON_IsObject(root)) {
        fprintf(stderr, "Invalid JSON root object\n");
        cJSON_Delete(root);
        return;
    }

    size_t idx = 0;
    for (cJSON *arg = root->child; arg && idx < MAX_ARGS; arg = arg->next, ++idx) {
        ArgSetting *s = &arg_settings[idx];
        memset(s, 0, sizeof(*s));
        strncpy(s->name, arg->string, MAX_NAME - 1);

        /* reg or addr (mutually exclusive) */
        cJSON *reg = cJSON_GetObjectItemCaseSensitive(arg, "reg");
        if (cJSON_IsString(reg)) {
            strncpy(s->reg, reg->valuestring, MAX_REG - 1);
            s->location_type = TYPE_REG;
        }
        cJSON *addr = cJSON_GetObjectItemCaseSensitive(arg, "addr");
        if (cJSON_IsNumber(addr)) {
            s->addr = addr->valueint;
            s->location_type = TYPE_ADDR;
        }

        /* type */
        cJSON *type = cJSON_GetObjectItemCaseSensitive(arg, "type");
        if (cJSON_IsString(type)) {
            if (strcmp(type->valuestring, "unknown") == 0) {
                s->vtype = TYPE_UNKNOWN;
            }
            else if (strcmp(type->valuestring, "float") == 0) {
                s->vtype = TYPE_FLOAT;
            } else if (strcmp(type->valuestring, "uint32") == 0) {
                s->vtype = TYPE_UINT32;
            } else if (strcmp(type->valuestring, "double") == 0) {
                s->vtype = TYPE_DOUBLE;
            } else if (strcmp(type->valuestring, "uint16") == 0) {
                s->vtype = TYPE_UINT16;
            } else if (strcmp(type->valuestring, "uint8") == 0) {
                s->vtype = TYPE_UINT8;
            } else {
                fprintf(stderr, "Unsupported type '%s' in '%s'\n", type->valuestring, s->name);
                cJSON_Delete(root);
                exit(EXIT_FAILURE);
            }
        }

        /* size */
        cJSON *size = cJSON_GetObjectItemCaseSensitive(arg, "size");
        if (cJSON_IsNumber(size)) {
            s->sz = (size_t)size->valueint;
        } else {
            // default size
            if (s->vtype == TYPE_FLOAT) {
                s->sz = 4; // float32
            } else if (s->vtype == TYPE_UINT32) {
                s->sz = 4; // uint32
            } else {
                s->sz = 0; // indicating unknown size
            }
        }

        /* is_pointer */
        cJSON *is_ptr = cJSON_GetObjectItemCaseSensitive(arg, "is_pointer");
        if (cJSON_IsString(is_ptr)) {
            if (strcmp(is_ptr->valuestring, "true") == 0) {
                s->is_pointer = IS_PTR_TRUE;
            } else if (strcmp(is_ptr->valuestring, "false") == 0) {
                s->is_pointer = IS_PTR_FALSE;
            } else if (strcmp(is_ptr->valuestring, "unknown") == 0) {
                s->is_pointer = IS_PTR_UNKNOWN;
            } else {
                // s->is_pointer = IS_PTR_UNKNOWN;
                fprintf(stderr, "Unsupported is_pointer value '%s' in '%s'\n", is_ptr->valuestring, s->name);
                cJSON_Delete(root);
                exit(EXIT_FAILURE);  // exit on unsupported value
            }
        } else {
            s->is_pointer = IS_PTR_UNKNOWN; // default
        }


        /* value_range: array of 1 or 2 numbers */
        cJSON *vr = cJSON_GetObjectItemCaseSensitive(arg, "value_range");
        if (cJSON_IsArray(vr)) {
            size_t n = cJSON_GetArraySize(vr);
            s->value_count = n > 2 ? 2 : n;
            for (size_t i = 0; i < s->value_count; ++i) {
                cJSON *num = cJSON_GetArrayItem(vr, (int)i);
                // s->value_range[i] = cJSON_IsNumber(num) ? num->valuedouble : 0.0;
                if (cJSON_IsNumber(num)) {
                    if (s->vtype == TYPE_FLOAT) {
                        s->value_range[i].f = num->valuedouble;  // store as float
                    } else if (s->vtype == TYPE_DOUBLE) {
                        s->value_range[i].d = num->valuedouble;
                    } else if (s->vtype == TYPE_UINT32) {
                        s->value_range[i].u32 = (uint32_t)num->valueint;  // store as uint32_t
                    } else if (s->vtype == TYPE_UINT16) {
                        s->value_range[i].u32 = (uint32_t)num->valueint;
                    } else if (s->vtype == TYPE_UINT8) {
                        s->value_range[i].u32 = (uint32_t)num->valueint;
                    } else {
                        fprintf(stderr, "Unsupported type for value_range in '%s'\n", s->name);
                        s->value_count = 0;  // reset count on error
                        break;
                    }
                } else {
                    fprintf(stderr, "Invalid value in value_range for '%s'\n", s->name);
                    s->value_count = 0;  // reset count on error
                    break;
                }

            }
        }

        // concrete_value (optional)
        cJSON *cv = cJSON_GetObjectItemCaseSensitive(arg, "concrete_value");
        if (cJSON_IsNumber(cv)) {
            if (s->vtype == TYPE_FLOAT) {
                s->concrete_value.f = cv->valuedouble;
            } else if (s->vtype == TYPE_DOUBLE) {
                s->concrete_value.d = cv->valuedouble;
            } else if (s->vtype == TYPE_UINT32) {
                s->concrete_value.u32 = (uint32_t)cv->valueint;
            } else if (s->vtype == TYPE_UINT16) {
                s->concrete_value.u32 = (uint32_t)cv->valueint;
            } else if (s->vtype == TYPE_UINT8) {
                s->concrete_value.u32 = (uint32_t)cv->valueint;
            } else {
                fprintf(stderr, "Unsupported type for concrete_value in '%s'\n", s->name);
            }
        }
    }

    cJSON_Delete(root);
    arg_count = idx;  /* store the count in a global variable */

    // init sub-semantic fields to false
    for (size_t i = 0; i < arg_count; i++) {
        arg_settings[i].is_written = false;
        arg_settings[i].is_read = false;
        arg_settings[i].is_sub_semantic_input = false;
    }
}

// dump
void dump_arg_settings(void);
void dump_arg_settings(void)
{
    puts("Parsed arguments:");
    for (size_t i = 0; i < arg_count; ++i) {
        const ArgSetting *p = &arg_settings[i];
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

// export
void parse_json_args(const char *filename);
void parse_json_args(const char *filename)
{
    char *json = read_file_to_buf(filename);
    if (!json) {
        perror("read_file_to_buf failed");
        return;
    }

    parse_arg_settings(json);

    free(json);

    dump_arg_settings();
}

/* -------------------------------------------------------------------------- */
/* Dumping utilities (arg_setting_to_json)                                    */
/* -------------------------------------------------------------------------- */
const char* io_value_type_to_str(IOValueType type);
const char* io_value_type_to_str(IOValueType type) {
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

cJSON* create_json_from_value_union(const ValueUnion* val, IOValueType vtype);
cJSON* create_json_from_value_union(const ValueUnion* val, IOValueType vtype) {
    switch (vtype) {
        case TYPE_FLOAT:
            return cJSON_CreateNumber(val->f);
        case TYPE_DOUBLE:
            return cJSON_CreateNumber(val->d);
        case TYPE_UINT32:
        case TYPE_UINT16: // Per your struct comment, re-use u32 field
        case TYPE_UINT8:  // Per your struct comment, re-use u32 field
            return cJSON_CreateNumber(val->u32);
        // Note: Your IOValueType does not have a uint64 type,
        // so val->u64 is not handled here.
        case TYPE_UNKNOWN:
        default:
            return cJSON_CreateNull();
    }
}

// export
cJSON* arg_setting_to_json(const ArgSetting* arg);
cJSON* arg_setting_to_json(const ArgSetting* arg) {
    cJSON *json_obj = cJSON_CreateObject();
    if (json_obj == NULL) {
        return NULL;
    }

    /*
     * The 'name' field is no longer serialized here,
     * as it's used as the key in the parent object (e.g., "arg1").
     */

    // Handle location_type (conditional)
    if (arg->location_type == TYPE_REG) {
        if (cJSON_AddStringToObject(json_obj, "reg", arg->reg) == NULL) {
            goto error;
        }
    } else {
        if (cJSON_AddNumberToObject(json_obj, "addr", arg->addr) == NULL) {
            goto error;
        }
    }

    // Handle size
    if (cJSON_AddNumberToObject(json_obj, "size", arg->sz) == NULL) {
        goto error;
    }

    // Handle is_pointer
    if (cJSON_AddStringToObject(json_obj, "is_pointer", is_pointer_type_to_string(arg->is_pointer)) == NULL) {
        goto error;
    }

    // Handle type
    if (cJSON_AddStringToObject(json_obj, "type", io_value_type_to_str(arg->vtype)) == NULL) {
        goto error;
    }

    // Handle value_range
    cJSON *range_array = cJSON_CreateArray();
    if (range_array == NULL) {
        goto error;
    }
    cJSON_AddItemToObject(json_obj, "value_range", range_array); // Ownership transferred

    for (size_t i = 0; i < arg->value_count; i++) {
        cJSON *range_item = create_json_from_value_union(&arg->value_range[i], arg->vtype);
        if (range_item == NULL) {
            goto error;
        }
        cJSON_AddItemToArray(range_array, range_item); // Ownership transferred
    }

    // Handle concrete_value
    cJSON *concrete_val = create_json_from_value_union(&arg->concrete_value, arg->vtype);
    if (concrete_val == NULL) {
        goto error;
    }
    cJSON_AddItemToObject(json_obj, "concrete_value", concrete_val); // Ownership transferred

    // non_ptr_iters is skipped as requested

    return json_obj;

error:
    // If any "Add" operation failed, delete the entire object and return NULL.
    cJSON_Delete(json_obj);
    return NULL;
}

// ===============================================================================================================================
// func start input, for sub-semantic recovery
// ===============================================================================================================================
ArgSetting func_start_arg_settings[MAX_ARGS];
size_t func_start_arg_count = 0;

/* -------------------------------------------------------------------------- */
/* Parsing utilities (parse_json_args)                                        */
/* -------------------------------------------------------------------------- */
// parse
void parse_func_start_arg_settings(const char *json);
void parse_func_start_arg_settings(const char *json)
{
    cJSON *root = cJSON_Parse(json);
    if (!root || !cJSON_IsObject(root)) {
        fprintf(stderr, "Invalid JSON root object\n");
        cJSON_Delete(root);
        return;
    }

    size_t idx = 0;
    for (cJSON *arg = root->child; arg && idx < MAX_ARGS; arg = arg->next, ++idx) {
        ArgSetting *s = &func_start_arg_settings[idx];
        memset(s, 0, sizeof(*s));
        strncpy(s->name, arg->string, MAX_NAME - 1);

        /* reg or addr (mutually exclusive) */
        cJSON *reg = cJSON_GetObjectItemCaseSensitive(arg, "reg");
        if (cJSON_IsString(reg)) {
            strncpy(s->reg, reg->valuestring, MAX_REG - 1);
            s->location_type = TYPE_REG;
        }
        cJSON *addr = cJSON_GetObjectItemCaseSensitive(arg, "addr");
        if (cJSON_IsNumber(addr)) {
            s->addr = addr->valueint;
            s->location_type = TYPE_ADDR;
        }

        /* type */
        cJSON *type = cJSON_GetObjectItemCaseSensitive(arg, "type");
        if (cJSON_IsString(type)) {
            if (strcmp(type->valuestring, "unknown") == 0) {
                s->vtype = TYPE_UNKNOWN;
            }
            else if (strcmp(type->valuestring, "float") == 0) {
                s->vtype = TYPE_FLOAT;
            } else if (strcmp(type->valuestring, "uint32") == 0) {
                s->vtype = TYPE_UINT32;
            } else if (strcmp(type->valuestring, "double") == 0) {
                s->vtype = TYPE_DOUBLE;
            } else if (strcmp(type->valuestring, "uint16") == 0) {
                s->vtype = TYPE_UINT16;
            } else if (strcmp(type->valuestring, "uint8") == 0) {
                s->vtype = TYPE_UINT8;
            } else {
                fprintf(stderr, "Unsupported type '%s' in '%s'\n", type->valuestring, s->name);
                cJSON_Delete(root);
                exit(EXIT_FAILURE);
            }
        }

        /* size */
        cJSON *size = cJSON_GetObjectItemCaseSensitive(arg, "size");
        if (cJSON_IsNumber(size)) {
            s->sz = (size_t)size->valueint;
        } else {
            // default size
            if (s->vtype == TYPE_FLOAT) {
                s->sz = 4; // float32
            } else if (s->vtype == TYPE_UINT32) {
                s->sz = 4; // uint32
            } else {
                s->sz = 0; // indicating unknown size
            }
        }

        /* is_pointer */
        cJSON *is_ptr = cJSON_GetObjectItemCaseSensitive(arg, "is_pointer");
        if (cJSON_IsString(is_ptr)) {
            if (strcmp(is_ptr->valuestring, "true") == 0) {
                s->is_pointer = IS_PTR_TRUE;
            } else if (strcmp(is_ptr->valuestring, "false") == 0) {
                s->is_pointer = IS_PTR_FALSE;
            } else if (strcmp(is_ptr->valuestring, "unknown") == 0) {
                s->is_pointer = IS_PTR_UNKNOWN;
            } else {
                // s->is_pointer = IS_PTR_UNKNOWN;
                fprintf(stderr, "Unsupported is_pointer value '%s' in '%s'\n", is_ptr->valuestring, s->name);
                cJSON_Delete(root);
                exit(EXIT_FAILURE);  // exit on unsupported value
            }
        } else {
            s->is_pointer = IS_PTR_UNKNOWN; // default
        }


        /* value_range: array of 1 or 2 numbers */
        cJSON *vr = cJSON_GetObjectItemCaseSensitive(arg, "value_range");
        if (cJSON_IsArray(vr)) {
            size_t n = cJSON_GetArraySize(vr);
            s->value_count = n > 2 ? 2 : n;
            for (size_t i = 0; i < s->value_count; ++i) {
                cJSON *num = cJSON_GetArrayItem(vr, (int)i);
                // s->value_range[i] = cJSON_IsNumber(num) ? num->valuedouble : 0.0;
                if (cJSON_IsNumber(num)) {
                    if (s->vtype == TYPE_FLOAT) {
                        s->value_range[i].f = num->valuedouble;  // store as float
                    } else if (s->vtype == TYPE_DOUBLE) {
                        s->value_range[i].d = num->valuedouble;
                    } else if (s->vtype == TYPE_UINT32) {
                        s->value_range[i].u32 = (uint32_t)num->valueint;  // store as uint32_t
                    } else if (s->vtype == TYPE_UINT16) {
                        s->value_range[i].u32 = (uint32_t)num->valueint;
                    } else if (s->vtype == TYPE_UINT8) {
                        s->value_range[i].u32 = (uint32_t)num->valueint;
                    } else {
                        fprintf(stderr, "Unsupported type for value_range in '%s'\n", s->name);
                        s->value_count = 0;  // reset count on error
                        break;
                    }
                } else {
                    fprintf(stderr, "Invalid value in value_range for '%s'\n", s->name);
                    s->value_count = 0;  // reset count on error
                    break;
                }

            }
        }

        // concrete_value (optional)
        cJSON *cv = cJSON_GetObjectItemCaseSensitive(arg, "concrete_value");
        if (cJSON_IsNumber(cv)) {
            if (s->vtype == TYPE_FLOAT) {
                s->concrete_value.f = cv->valuedouble;
            } else if (s->vtype == TYPE_DOUBLE) {
                s->concrete_value.d = cv->valuedouble;
            } else if (s->vtype == TYPE_UINT32) {
                s->concrete_value.u32 = (uint32_t)cv->valueint;
            } else if (s->vtype == TYPE_UINT16) {
                s->concrete_value.u32 = (uint32_t)cv->valueint;
            } else if (s->vtype == TYPE_UINT8) {
                s->concrete_value.u32 = (uint32_t)cv->valueint;
            } else {
                fprintf(stderr, "Unsupported type for concrete_value in '%s'\n", s->name);
            }
        }
    }

    cJSON_Delete(root);
    func_start_arg_count = idx;  /* store the count in a global variable */

    // init sub-semantic fields to false
    for (size_t i = 0; i < func_start_arg_count; i++) {
        func_start_arg_settings[i].is_written = false;
        func_start_arg_settings[i].is_read = false;
        func_start_arg_settings[i].is_sub_semantic_input = false;
    }
}

// dump
void dump_func_start_arg_settings(void);
void dump_func_start_arg_settings(void)
{
    puts("Parsed arguments:");
    for (size_t i = 0; i < func_start_arg_count; ++i) {
        const ArgSetting *p = &func_start_arg_settings[i];
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

// export
void parse_func_start_json_args(const char *filename);
void parse_func_start_json_args(const char *filename)
{
    char *json = read_file_to_buf(filename);
    if (!json) {
        perror("read_file_to_buf failed");
        return;
    }

    parse_func_start_arg_settings(json);

    free(json);

    dump_func_start_arg_settings();
}


// ===============================================================================================================================
// ret
// ===============================================================================================================================
typedef struct {
    char name[MAX_NAME];

    // unsigned long xaddr; // target address to examine output value

    /* Exactly one of the two will be set */
    ValueLocationType location_type; /* register or addr */
    char reg[MAX_REG];
    unsigned long addr;

    IOValueType vtype;
    // Buffy log_buf; // needed by tcg logger, use VI for now

    ValueUnion concrete_value;
} RetSetting;
RetSetting ret_settings[MAX_ARGS];
size_t ret_count = 0;

void parse_ret_settings(const char *json);
void parse_ret_settings(const char *json)
{
    cJSON *root = cJSON_Parse(json);
    if (!root || !cJSON_IsObject(root)) {
        fprintf(stderr, "Invalid JSON root object\n");
        cJSON_Delete(root);
        return;
    }

    size_t idx = 0;
    for (cJSON *arg = root->child; arg && idx < MAX_ARGS; arg = arg->next, ++idx) {
        RetSetting *s = &ret_settings[idx];
        memset(s, 0, sizeof(*s));
        strncpy(s->name, arg->string, MAX_NAME - 1);

        // /* xaddr */
        // cJSON *xaddr = cJSON_GetObjectItemCaseSensitive(arg, "xaddr");
        // if (cJSON_IsNumber(xaddr)) {
        //     s->xaddr = xaddr->valueint;
        // }

        /* reg or addr (mutually exclusive) */
        cJSON *reg = cJSON_GetObjectItemCaseSensitive(arg, "reg");
        if (cJSON_IsString(reg)) {
            strncpy(s->reg, reg->valuestring, MAX_REG - 1);
            s->location_type = TYPE_REG;
        }
        cJSON *offset = cJSON_GetObjectItemCaseSensitive(arg, "addr");
        if (cJSON_IsNumber(offset)) {
            s->addr = offset->valueint;
            s->location_type = TYPE_ADDR;
        }

        /* type */
        cJSON *type = cJSON_GetObjectItemCaseSensitive(arg, "type");
        if (cJSON_IsString(type)) {
            if (strcmp(type->valuestring, "unknown") == 0) {
                s->vtype = TYPE_UNKNOWN;
            }
            else if (strcmp(type->valuestring, "float") == 0) {
                s->vtype = TYPE_FLOAT;
            } else if (strcmp(type->valuestring, "uint32") == 0) {
                s->vtype = TYPE_UINT32;
            } else if (strcmp(type->valuestring, "double") == 0) {
                s->vtype = TYPE_DOUBLE;
            } else if (strcmp(type->valuestring, "uint16") == 0) {
                s->vtype = TYPE_UINT16;
            } else if (strcmp(type->valuestring, "uint8") == 0) {
                s->vtype = TYPE_UINT8;
            } else {
                fprintf(stderr, "Unsupported type '%s' in '%s'\n", type->valuestring, s->name);
                cJSON_Delete(root);
                return;
            }
        }
    }

    cJSON_Delete(root);
    ret_count = idx;  /* store the count in a global variable */
}

void dump_ret_settings(void);
void dump_ret_settings(void)
{
    printf("Parsed %zu ret settings:\n", ret_count);
    for (size_t i = 0; i < ret_count; ++i) {
        const RetSetting *p = &ret_settings[i];
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
    }
}

void parse_json_outs(const char *filename);
void parse_json_outs(const char *filename)
{
    char *json = read_file_to_buf(filename);
    if (!json) {
        perror("read_file_to_buf failed");
        return;
    }

    parse_ret_settings(json);

    free(json);

    dump_ret_settings();
}

// used by tcg logger, use VI for now
// void dump_ret_values(void);
// void dump_ret_values(void) {
//     printf("Dumping ret values:\n");
//     for (size_t i = 0; i < ret_count; ++i) {
//         const RetSetting *p = &ret_settings[i];
//         if (p->log_buf.buffer && p->log_buf.index > 0) {
//             printf("Ret %zu (%s): ", i, p->name);
//             // for (uint16_t j = 0; j < p->log_buf.index;) {
//             //     if (p->vtype == TYPE_FLOAT) {
//             //         printf("%g ", ((float *)p->log_buf.buffer)[j]);
//             //     } else if (p->vtype == TYPE_UINT32) {
//             //         printf("%u ", ((uint32_t *)p->log_buf.buffer)[j]);
//             //     }
//             // }
//             if (p->vtype == TYPE_FLOAT) {
//                 for (int j = 0; j < ((int)p->log_buf.index) / sizeof(float); j++) {
//                     printf("%g ", ((float *)p->log_buf.buffer)[j]);
//                 }
//             } else if (p->vtype == TYPE_UINT32) {
//                 for (int j = 0; j < ((int)p->log_buf.index) / sizeof(uint32_t); j++) {
//                     printf("%u ", ((uint32_t *)p->log_buf.buffer)[j]);
//                 }
//             } else {
//                 printf("Unknown type for ret %s\n", p->name);
//                 perror("dump_ret_values");
//                 exit(EXIT_FAILURE);
//             }
//             printf("\n");
//         }
//     }
// }

// void dump_latest_ret_values(void);
// void dump_latest_ret_values(void) {
//     printf("Dumping latest ret values:\n");
//     for (size_t i = 0; i < ret_count; ++i) {
//         const RetSetting *p = &ret_settings[i];
//         if (p->log_buf.buffer && p->log_buf.index > 0) {
//             if (p->vtype == TYPE_FLOAT) {
//                 int type_index = (int)p->log_buf.index / sizeof(float) - 1;
//                 printf("Ret %s[%d/%d]: ", p->name, (int)p->log_buf.index, type_index);
//                 printf("%g\n", ((float *)p->log_buf.buffer)[type_index]);
//             } else if (p->vtype == TYPE_UINT32) {
//                 int type_index = (int)p->log_buf.index / sizeof(uint32_t) - 1;
//                 printf("Ret %s[%d/%d]: ", p->name, (int)p->log_buf.index, type_index);
//                 printf("%u\n", ((uint32_t *)p->log_buf.buffer)[type_index]);
//             } else {
//                 printf("Unknown type for ret %s\n", p->name);
//                 perror("dump_latest_ret_values");
//                 exit(EXIT_FAILURE);
//             }
//         }
//         else {
//             printf("Ret %s has no values logged yet.\n", p->name);
//         }
//     }
// }

// ===============================================================================================================================
// Utility: check whether mem var locations are equivalent or overlap
// ===============================================================================================================================
int same_mem_locs(const ArgSetting *a, uint64_t addr, size_t sz);
int same_mem_locs(const ArgSetting *a, uint64_t addr, size_t sz)
{
    if (a->location_type != TYPE_ADDR) return 0; /* not a memory location */
    if (a->sz == 0 || sz == 0) return 0; /* unknown size */
    if (a->addr == addr && a->sz == sz) return 1; /* exact match */
    return 0; /* no match */
}


int overlap_mem_locs(const ArgSetting *a, uint64_t addr, size_t sz);
int overlap_mem_locs(const ArgSetting *a, uint64_t addr, size_t sz)
{
    if (a->location_type != TYPE_ADDR) return 0; /* not a memory location */
    if (a->sz == 0 || sz == 0) return 0; /* unknown size */
    if (same_mem_locs(a, addr, sz)) return 0; /* exact match */
    if (a->addr < addr + sz && addr < a->addr + a->sz) return 1; /* overlap */
    return 0; /* not overlap */
}

#endif // JSON_PARSE_H
