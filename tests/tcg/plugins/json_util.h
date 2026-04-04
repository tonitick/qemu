#ifndef JSON_UTIL_H
#define JSON_UTIL_H

#include <cjson/cJSON.h>
#include "variable.h"

// ===============================================================================================================================
// file read helper
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
// input varialbe
// ===============================================================================================================================
// parse input variables from json to asettings & acount
void parse_arg_settings_from_json(const char *json, ArgSetting *asettings, size_t *acount);
void parse_arg_settings_from_json(const char *json, ArgSetting *asettings, size_t *acount)
{
    cJSON *root = cJSON_Parse(json);
    if (!root || !cJSON_IsObject(root)) {
        fprintf(stderr, "Invalid JSON root object\n");
        cJSON_Delete(root);
        return;
    }

    size_t idx = 0;
    for (cJSON *arg = root->child; arg && idx < MAX_ARGS; arg = arg->next, ++idx) {
        ArgSetting *s = &asettings[idx];
        init_arg_setting(s);
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
    *acount = idx;  /* store the count in a global variable */
}

// helper: create cJSON entry from ValueUnion based on IOValueType
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

// a sinle ArgSetting to cJSON entry
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
    if (cJSON_AddStringToObject(json_obj, "type", io_value_type_to_string(arg->vtype)) == NULL) {
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

    // non_ptr_iters is skipped, only used for type refinement during fuzzing

    // Handle concrete_value
    cJSON *concrete_val = create_json_from_value_union(&arg->concrete_value, arg->vtype);
    if (concrete_val == NULL) {
        goto error;
    }
    cJSON_AddItemToObject(json_obj, "concrete_value", concrete_val); // Ownership transferred

    // Handle base_ptr_var_name and base_ptr_offset for mem args
    if (arg->location_type == TYPE_ADDR) {
        if (arg->base_ptr_var_name[0] != '\0') { // non-empty base_ptr_var_name indicates there is a parent pointer variable (struct var) for this mem arg
            if (cJSON_AddStringToObject(json_obj, "base_ptr_var_name", arg->base_ptr_var_name) == NULL) {
                goto error;
            }
            if (cJSON_AddNumberToObject(json_obj, "base_ptr_offset", arg->base_ptr_offset) == NULL) {
                goto error;
            }
        }
    }

    return json_obj;

error:
    // If any "Add" operation failed, delete the entire object and return NULL.
    cJSON_Delete(json_obj);
    return NULL;
}

// a sinle ArgSetting to cJSON call interface entry
// TODO: could be merge with arg_setting_to_json
cJSON* arg_setting_to_call_interface_json(const ArgSetting* arg);
cJSON* arg_setting_to_call_interface_json(const ArgSetting* arg) {
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
    if (cJSON_AddStringToObject(json_obj, "type", io_value_type_to_string(arg->vtype)) == NULL) {
        goto error;
    }

    // skip value_range and concrete_value, not needed for calling interface

    // non_ptr_iters is skipped, only used for type refinement during fuzzing

    // Handle base_ptr_var_name and base_ptr_offset for mem args
    if (arg->location_type == TYPE_ADDR) {
        if (arg->base_ptr_var_name[0] != '\0') { // non-empty base_ptr_var_name indicates there is a parent pointer variable (struct var) for this mem arg
            if (cJSON_AddStringToObject(json_obj, "base_ptr_var_name", arg->base_ptr_var_name) == NULL) {
                goto error;
            }
            if (cJSON_AddNumberToObject(json_obj, "base_ptr_offset", arg->base_ptr_offset) == NULL) {
                goto error;
            }
        }
    }

    return json_obj;

error:
    // If any "Add" operation failed, delete the entire object and return NULL.
    cJSON_Delete(json_obj);
    return NULL;
}

// ===============================================================================================================================
// output variable
// ===============================================================================================================================
// parse output variable from json to rsettings & rcount
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
        init_ret_setting(s);
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
    }

    cJSON_Delete(root);
    ret_count = idx;  /* store the count in a global variable */
}

// a single RetSetting to cJSON entry
cJSON* ret_setting_to_call_interface_json(const RetSetting* ret);
cJSON* ret_setting_to_call_interface_json(const RetSetting* ret) {
    cJSON *json_obj = cJSON_CreateObject();
    if (json_obj == NULL) {
        return NULL;
    }

    /*
     * The 'name' field is no longer serialized here,
     * as it's used as the key in the parent object (e.g., "ret1").
     */

    // Handle location_type (conditional)
    if (ret->location_type == TYPE_REG) {
        if (cJSON_AddStringToObject(json_obj, "reg", ret->reg) == NULL) {
            goto error;
        }
    } else {
        if (cJSON_AddNumberToObject(json_obj, "addr", ret->addr) == NULL) {
            goto error;
        }
    }

    // Handle type
    if (cJSON_AddStringToObject(json_obj, "type", io_value_type_to_string(ret->vtype)) == NULL) {
        goto error;
    }

    // Handle size
    if (cJSON_AddNumberToObject(json_obj, "size", ret->sz) == NULL) {
        goto error;
    }

    return json_obj;

error:
    // If any "Add" operation failed, delete the entire object and return NULL.
    cJSON_Delete(json_obj);
    return NULL;
}


#endif // JSON_UTIL_H