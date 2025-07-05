/*
 * parse_args.c
 *
 * Stand-alone demo that loads the JSON file given on the command line,
 * parses it with cJSON, and prints a summary of every top-level entry.
 *
 * Build:  gcc -std=c11 -Wall -Wextra -pedantic parse_args.c -lcjson -o parse_args
 */

#ifndef JSON_PARSE_H
#define JSON_PARSE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <cjson/cJSON.h>

/* -------------------------------------------------------------------------- */
/* Slurp an entire file into memory                                           */
/* -------------------------------------------------------------------------- */
char *read_json_file(const char *path);
char *read_json_file(const char *path)
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
// for randars
// ===============================================================================================================================

#define MAX_NAME  32
#define MAX_REG    8
#define MAX_ARGS  32          /* maximum distinct argument objects */


typedef enum {
    TYPE_REG,
    TYPE_ADDR,
} ValueLocationType;

typedef enum {
    TYPE_FLOAT,
    TYPE_UINT32
} IOValueType;

typedef union {
    float f;
    uint32_t u32;
} ValueUnion;



/* -------------------------------------------------------------------------- */
/* Data structure describing one argument                                     */
/* -------------------------------------------------------------------------- */
typedef struct {
    char name[MAX_NAME];

    /* Exactly one of the two will be set */
    ValueLocationType location_type; /* register or addr */
    char reg[MAX_REG];
    unsigned long addr;

    IOValueType vtype;
    ValueUnion value_range[2]; /* one- or two-element range */
    size_t value_count;
} ArgSetting;
ArgSetting arg_settings[MAX_ARGS];
size_t arg_count = 0;

/* -------------------------------------------------------------------------- */
/* Parse JSON text into an array of ArgSetting                                */
/* -------------------------------------------------------------------------- */
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
            if (strcmp(type->valuestring, "float") == 0) {
                s->vtype = TYPE_FLOAT;
            } else if (strcmp(type->valuestring, "uint32") == 0) {
                s->vtype = TYPE_UINT32;
            } else {
                fprintf(stderr, "Unsupported type '%s' in '%s'\n", type->valuestring, s->name);
                cJSON_Delete(root);
                return;  // exit on unsupported type
            }
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
                    } else if (s->vtype == TYPE_UINT32) {
                        s->value_range[i].u32 = (uint32_t)num->valueint;  // store as uint32_t
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
    }

    cJSON_Delete(root);
    arg_count = idx;  /* store the count in a global variable */
}

/* -------------------------------------------------------------------------- */
/* Pretty-print the parsed data                                               */
/* -------------------------------------------------------------------------- */
void dump_arg_settings(void);
void dump_arg_settings(void)
{
    puts("Parsed arguments:");
    for (size_t i = 0; i < arg_count; ++i) {
        const ArgSetting *p = &arg_settings[i];
        printf("Arg %zu: name='%s', type=%s, location_type=%s, ",
               i, p->name,
               p->vtype == TYPE_FLOAT ? "float" : "uint32",
               p->location_type == TYPE_REG ? "reg" : "addr");
        if (p->location_type == TYPE_REG) {
            printf("reg=%s, ", p->reg);
        } else if (p->location_type == TYPE_ADDR) {
            printf("addr=0x%lx, ", p->addr);
        }

        printf("value_range=[");
        for (size_t j = 0; j < p->value_count; ++j) {
            if (p->vtype == TYPE_FLOAT) {
                printf("%g%s", p->value_range[j].f,
                       j + 1 == p->value_count ? "" : ", ");
            } else if (p->vtype == TYPE_UINT32) {
                printf("%u%s", p->value_range[j].u32,
                       j + 1 == p->value_count ? "" : ", ");
            }
        }
        printf("]\n");
    }
}

#endif // JSON_PARSE_H

// ===============================================================================================================================
// for ret
// ===============================================================================================================================
// typedef struct {
//     uint32_t *buffer;  // Pointer to the buffer
//     uint16_t index;     // Current index into the buffer
// } Buffy;

typedef struct {
    char name[MAX_NAME];

    unsigned long xaddr; // target address to examine output value

    /* Exactly one of the two will be set */
    ValueLocationType location_type; /* register or addr */
    char reg[MAX_REG];
    unsigned long addr;

    IOValueType vtype;
    // Buffy log_buf; // needed by tcg logger, use VI for now
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

        /* xaddr */
        cJSON *xaddr = cJSON_GetObjectItemCaseSensitive(arg, "xaddr");
        if (cJSON_IsNumber(xaddr)) {
            s->xaddr = xaddr->valueint;
        }

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
            if (strcmp(type->valuestring, "float") == 0) {
                s->vtype = TYPE_FLOAT;
            } else if (strcmp(type->valuestring, "uint32") == 0) {
                s->vtype = TYPE_UINT32;
            } else {
                fprintf(stderr, "Unsupported type '%s' in '%s'\n", type->valuestring, s->name);
                cJSON_Delete(root);
                return;  // exit on unsupported type
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
        printf("Ret %zu: name='%s', type=%s, location_type=%s, ",
               i, p->name,
               p->vtype == TYPE_FLOAT ? "float" : "uint32",
               p->location_type == TYPE_REG ? "reg" : "addr");
        if (p->location_type == TYPE_REG) {
            printf("reg=%s, ", p->reg);
        } else if (p->location_type == TYPE_ADDR) {
            printf("addr=0x%lx, ", p->addr);
        }
        printf("xaddr=0x%lx\n", p->xaddr);
    }
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