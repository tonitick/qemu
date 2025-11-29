#ifndef VIRTUAL_H
#define VIRTUAL_H

#include <qemu-plugin.h>
#include "path_logger.h"

// ---------------------------------------------------------------
// helpers
// ---------------------------------------------------------------
typedef enum {
    ARM_V7M_REG_INVALID = -1,
    ARM_V7M_REG_R0 = 0,
    ARM_V7M_REG_R1 = 1,
    ARM_V7M_REG_R2 = 2,
    ARM_V7M_REG_R3 = 3,
    ARM_V7M_REG_R4 = 4,
    ARM_V7M_REG_R5 = 5,
    ARM_V7M_REG_R6 = 6,
    ARM_V7M_REG_R7 = 7,
    ARM_V7M_REG_R8 = 8,
    ARM_V7M_REG_R9 = 9,
    ARM_V7M_REG_R10 = 10,
    ARM_V7M_REG_R11 = 11,
    ARM_V7M_REG_R12 = 12,
    ARM_V7M_REG_R13 = 13, // Stack Pointer (SP)
    ARM_V7M_REG_R14 = 14, // Link Register (LR)
    ARM_V7M_REG_R15 = 15, // Program Counter (PC)

    ARM_V7M_S0 = 26, // Floating-point register s0
    ARM_V7M_S1 = 27,
    ARM_V7M_S2 = 28,
    ARM_V7M_S3 = 29,
    ARM_V7M_S4 = 30,
    ARM_V7M_S5 = 31,
    ARM_V7M_S6 = 32,
    ARM_V7M_S7 = 33,
    ARM_V7M_S8 = 34,
    ARM_V7M_S9 = 35,
    ARM_V7M_S10 = 36,
    ARM_V7M_S11 = 37,
    ARM_V7M_S12 = 38,
    ARM_V7M_S13 = 39,
    ARM_V7M_S14 = 40,
    ARM_V7M_S15 = 41, // Floating-point register s15
    ARM_V7M_S16 = 42,
    ARM_V7M_S17 = 43,
    ARM_V7M_S18 = 44,
    ARM_V7M_S19 = 45,
    ARM_V7M_S20 = 46,
    ARM_V7M_S21 = 47,
    ARM_V7M_S22 = 48,
    ARM_V7M_S23 = 49,
    ARM_V7M_S24 = 50,
    ARM_V7M_S25 = 51,
    ARM_V7M_S26 = 52,
    ARM_V7M_S27 = 53,
    ARM_V7M_S28 = 54,
    ARM_V7M_S29 = 55,
    ARM_V7M_S30 = 56,
    ARM_V7M_S31 = 57,

    ARM_V7M_D0 = 26,
    ARM_V7M_D1 = 27,
    ARM_V7M_D2 = 28,
    ARM_V7M_D3 = 29,
    ARM_V7M_D4 = 30,
    ARM_V7M_D5 = 31,
    ARM_V7M_D6 = 32,
    ARM_V7M_D7 = 33,
    ARM_V7M_D8 = 34,
    ARM_V7M_D9 = 35,
    ARM_V7M_D10 = 36,
    ARM_V7M_D11 = 37,
    ARM_V7M_D12 = 38,
    ARM_V7M_D13 = 39,
    ARM_V7M_D14 = 40,
    ARM_V7M_D15 = 41
    // ARM_V7M_D0 = 58,
    // ARM_V7M_D1 = 59,
    // ARM_V7M_D2 = 60,
    // ARM_V7M_D3 = 61,
    // ARM_V7M_D4 = 62,
    // ARM_V7M_D5 = 63,
    // ARM_V7M_D6 = 64,
    // ARM_V7M_D7 = 65,
    // ARM_V7M_D8 = 66,
    // ARM_V7M_D9 = 67,
    // ARM_V7M_D10 = 68,
    // ARM_V7M_D11 = 69,
    // ARM_V7M_D12 = 70,
    // ARM_V7M_D13 = 71,
    // ARM_V7M_D14 = 72,
    // ARM_V7M_D15 = 73
} ARM_V7M_REG;

ARM_V7M_REG get_reg_by_name(const char *name);
ARM_V7M_REG get_reg_by_name(const char *name) {
    if (strcmp(name, "r0") == 0) return ARM_V7M_REG_R0;
    if (strcmp(name, "r1") == 0) return ARM_V7M_REG_R1;
    if (strcmp(name, "r2") == 0) return ARM_V7M_REG_R2;
    if (strcmp(name, "r3") == 0) return ARM_V7M_REG_R3;
    if (strcmp(name, "r4") == 0) return ARM_V7M_REG_R4;
    if (strcmp(name, "r5") == 0) return ARM_V7M_REG_R5;
    if (strcmp(name, "r6") == 0) return ARM_V7M_REG_R6;
    if (strcmp(name, "r7") == 0) return ARM_V7M_REG_R7;
    if (strcmp(name, "r8") == 0) return ARM_V7M_REG_R8;
    if (strcmp(name, "r9") == 0) return ARM_V7M_REG_R9;
    if (strcmp(name, "r10") == 0) return ARM_V7M_REG_R10;
    if (strcmp(name, "r11") == 0) return ARM_V7M_REG_R11;
    if (strcmp(name, "r12") == 0) return ARM_V7M_REG_R12;
    if (strcmp(name, "sp") == 0 || strcmp(name, "r13") == 0) return ARM_V7M_REG_R13; // SP
    if (strcmp(name, "lr") == 0 || strcmp(name, "r14") == 0) return ARM_V7M_REG_R14; // LR
    if (strcmp(name, "pc") == 0 || strcmp(name, "r15") == 0) return ARM_V7M_REG_R15; // PC

    if (strcmp(name, "s0") == 0) return ARM_V7M_S0;
    if (strcmp(name, "s1") == 0) return ARM_V7M_S1;
    if (strcmp(name, "s2") == 0) return ARM_V7M_S2;
    if (strcmp(name, "s3") == 0) return ARM_V7M_S3;
    if (strcmp(name, "s4") == 0) return ARM_V7M_S4;
    if (strcmp(name, "s5") == 0) return ARM_V7M_S5;
    if (strcmp(name, "s6") == 0) return ARM_V7M_S6;
    if (strcmp(name, "s7") == 0) return ARM_V7M_S7;
    if (strcmp(name, "s8") == 0) return ARM_V7M_S8;
    if (strcmp(name, "s9") == 0) return ARM_V7M_S9;
    if (strcmp(name, "s10") == 0) return ARM_V7M_S10;
    if (strcmp(name, "s11") == 0) return ARM_V7M_S11;
    if (strcmp(name, "s12") == 0) return ARM_V7M_S12;
    if (strcmp(name, "s13") == 0) return ARM_V7M_S13;
    if (strcmp(name, "s14") == 0) return ARM_V7M_S14;
    if (strcmp(name, "s15") == 0) return ARM_V7M_S15;
    if (strcmp(name, "s16") == 0) return ARM_V7M_S16;
    if (strcmp(name, "s17") == 0) return ARM_V7M_S17;
    if (strcmp(name, "s18") == 0) return ARM_V7M_S18;
    if (strcmp(name, "s19") == 0) return ARM_V7M_S19;
    if (strcmp(name, "s20") == 0) return ARM_V7M_S20;
    if (strcmp(name, "s21") == 0) return ARM_V7M_S21;
    if (strcmp(name, "s22") == 0) return ARM_V7M_S22;
    if (strcmp(name, "s23") == 0) return ARM_V7M_S23;
    if (strcmp(name, "s24") == 0) return ARM_V7M_S24;
    if (strcmp(name, "s25") == 0) return ARM_V7M_S25;
    if (strcmp(name, "s26") == 0) return ARM_V7M_S26;
    if (strcmp(name, "s27") == 0) return ARM_V7M_S27;
    if (strcmp(name, "s28") == 0) return ARM_V7M_S28;
    if (strcmp(name, "s29") == 0) return ARM_V7M_S29;
    if (strcmp(name, "s30") == 0) return ARM_V7M_S30;
    if (strcmp(name, "s31") == 0) return ARM_V7M_S31;

    if (strcmp(name, "d0") == 0) return ARM_V7M_D0;
    if (strcmp(name, "d1") == 0) return ARM_V7M_D1;
    if (strcmp(name, "d2") == 0) return ARM_V7M_D2;
    if (strcmp(name, "d3") == 0) return ARM_V7M_D3;
    if (strcmp(name, "d4") == 0) return ARM_V7M_D4;
    if (strcmp(name, "d5") == 0) return ARM_V7M_D5;
    if (strcmp(name, "d6") == 0) return ARM_V7M_D6;
    if (strcmp(name, "d7") == 0) return ARM_V7M_D7;
    if (strcmp(name, "d8") == 0) return ARM_V7M_D8;
    if (strcmp(name, "d9") == 0) return ARM_V7M_D9;
    if (strcmp(name, "d10") == 0) return ARM_V7M_D10;
    if (strcmp(name, "d11") == 0) return ARM_V7M_D11;
    if (strcmp(name, "d12") == 0) return ARM_V7M_D12;
    if (strcmp(name, "d13") == 0) return ARM_V7M_D13;
    if (strcmp(name, "d14") == 0) return ARM_V7M_D14;
    if (strcmp(name, "d15") == 0) return ARM_V7M_D15;

    // return ARM_V7M_REG_INVALID; // Invalid register name
    fprintf(stderr, "Error: unrecognized register name '%s'\n", name);
    exit(EXIT_FAILURE);
}

uint32_t qemu_get_register_32(int reg);
uint32_t qemu_get_register_32(int reg)
{
    g_autoptr(GArray) reg_list = qemu_plugin_get_registers();
    g_autoptr(GByteArray) reg_value = g_byte_array_new();
	int offset = 0;
	int oreg = reg;

	if (reg >= ARM_V7M_S0)
		oreg = 17 + ((reg - ARM_V7M_S0) / 2);


    if (reg_list) {
            qemu_plugin_reg_descriptor *rd = &g_array_index(
                reg_list, qemu_plugin_reg_descriptor, oreg);
            int count = qemu_plugin_read_register(rd->handle, reg_value);
            g_assert(count > 0);
    }

	if ((reg >= ARM_V7M_S0) && ((reg - ARM_V7M_S0)  %2)) {
			//S1...
			offset = 4;
	}

    uint32_t return_data = reg_value->data[offset + 0];
    return_data = (((uint32_t) (reg_value->data[offset + 1])) << 8)  | return_data;
    return_data = (((uint32_t) (reg_value->data[offset + 2])) << 16) | return_data;
    return_data = (((uint32_t) (reg_value->data[offset + 3])) << 24) | return_data;
    return return_data;
}

uint64_t qemu_get_register_64(int reg);
uint64_t qemu_get_register_64(int reg)
{
    g_autoptr(GArray) reg_list = qemu_plugin_get_registers();
    g_autoptr(GByteArray) reg_value = g_byte_array_new();
    int offset = 0;
    int oreg = reg;

    if (reg >= ARM_V7M_D0 && reg <= ARM_V7M_D15) {
        oreg = 17 + ((reg - ARM_V7M_D0) / 2);
    }
    else {
        fprintf(stderr, "Error: only D0-D15 supported for 64-bit register read\n");
        exit(EXIT_FAILURE);
    }

    if (reg_list) {
            qemu_plugin_reg_descriptor *rd = &g_array_index(
                reg_list, qemu_plugin_reg_descriptor, oreg);
            int count = qemu_plugin_read_register(rd->handle, reg_value);
            g_assert(count > 0);
    }

    uint64_t return_data = reg_value->data[offset + 0];
    return_data = (((uint64_t) (reg_value->data[offset + 1])) << 8)  | return_data;
    return_data = (((uint64_t) (reg_value->data[offset + 2])) << 16) | return_data;
    return_data = (((uint64_t) (reg_value->data[offset + 3])) << 24) | return_data;
    return_data = (((uint64_t) (reg_value->data[offset + 4])) << 32) | return_data;
    return_data = (((uint64_t) (reg_value->data[offset + 5])) << 40) | return_data;
    return_data = (((uint64_t) (reg_value->data[offset + 6])) << 48) | return_data;
    return_data = (((uint64_t) (reg_value->data[offset + 7])) << 56) | return_data;
    return return_data;
}

// ---------------------------------------------------------------
// vi impl globals & helpers
// ---------------------------------------------------------------
// basic blocks
#define MAX_BASIC_BLOCKS 1024
unsigned long bb_starts[MAX_BASIC_BLOCKS];
int bb_count = 0;
void parse_basic_block_file(const char *filename);
void parse_basic_block_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Error opening basic block file");
        return;
    }
    // format: 0x..., separated by newlines
    char line[64];                 // plenty for one address + newline
    while (fgets(line, sizeof(line), fp)) {
        errno = 0;
        char *end;
        uint64_t addr = strtoull(line, &end, 0);  // base 0 ⇒ handles “0x…”
        if (errno || end == line) {               // conversion failed
            fprintf(stderr, "Invalid address: %s", line);
            continue;
        }

        if (bb_count < MAX_BASIC_BLOCKS) {
            bb_starts[bb_count++] = addr;
        } else {
            fprintf(stderr, "Max basic blocks limit reached (%d), skipping rest\n", MAX_BASIC_BLOCKS);
            break;
        }
    }
    fclose(fp);

    for (int i = 0; i < bb_count; i++) {
        printf("Basic Block %d starts at: 0x%lx\n", i, bb_starts[i]);
    }
}

// function start
unsigned long func_start;
void parse_function_start_file(const char *filename);
void parse_function_start_file(const char *filename) {
    // a single line file with function start address in hex
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Error opening function start file");
        return;
    }

    char line[64];
    if (fgets(line, sizeof(line), fp)) {
        errno = 0;
        char *end;
        func_start = strtoull(line, &end, 0);
        if (errno || end == line) {
            fprintf(stderr, "Invalid function start address: %s", line);
        }
    }
    fclose(fp);
    printf("Function start address parsed: 0x%lx\n", func_start);
}

// function end
#define MAX_FUNCTION_ENDS 100
unsigned long func_ends[MAX_FUNCTION_ENDS];
int func_end_count = 0;
void parse_function_end_file(const char *filename);
void parse_function_end_file(const char *filename) {
    // same format as basic block file
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Error opening function end file");
        return;
    }
    char line[64];                 // plenty for one address + newline
    while (fgets(line, sizeof(line), fp)) {
        errno = 0;
        char *end;
        unsigned long addr = strtoull(line, &end, 0);
        if (errno || end == line) {
            fprintf(stderr, "Invalid function end address: %s", line);
            continue;
        }

        if (func_end_count < MAX_FUNCTION_ENDS) {
            func_ends[func_end_count++] = addr;
        } else {
            fprintf(stderr, "Max function ends limit reached (%d), skipping rest\n", MAX_FUNCTION_ENDS);
            break;
        }
    }
    fclose(fp);

    for (int i = 0; i < func_end_count; i++) {
        printf("Function End %d at: 0x%lx\n", i, func_ends[i]);
    }
}

unsigned long sub_semantic_start;
unsigned long sub_semantic_end;
bool is_sub_semantic_collection = false;
bool is_sub_semantics_mode = false;
bool is_sub_semantic_last_stage = false;
void parse_sub_semantic_start_file(const char *filename);
void parse_sub_semantic_start_file(const char *filename) {
    // a single line file with sub semantic start address in hex
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Error opening sub semantic start file");
        return;
    }

    char line[64];
    if (fgets(line, sizeof(line), fp)) {
        errno = 0;
        char *end;
        sub_semantic_start = strtoull(line, &end, 0);
        if (errno || end == line) {
            fprintf(stderr, "Invalid sub semantic start address: %s", line);
        }
    }
    fclose(fp);
    printf("Sub Semantic Start address parsed: 0x%lx\n", sub_semantic_start);
}

void parse_sub_semantic_end_file(const char *filename);
void parse_sub_semantic_end_file(const char *filename) {
    // a single line file with sub semantic end address in hex
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Error opening sub semantic end file");
        return;
    }

    char line[64];
    if (fgets(line, sizeof(line), fp)) {
        errno = 0;
        char *end;
        sub_semantic_end = strtoull(line, &end, 0);
        if (errno || end == line) {
            fprintf(stderr, "Invalid sub semantic end address: %s", line);
        }
    }
    fclose(fp);
    printf("Sub Semantic End address parsed: 0x%lx\n", sub_semantic_end);
}

// ---------------------------------------------------------------
// global structs
// ---------------------------------------------------------------
#define MAX_RULES 256

typedef void (*cb_func_t)(unsigned int cpu_index, void *userdata);

typedef struct {
    const char *name;
    cb_func_t func;
} cb_entry_t;

typedef struct {
    unsigned long long address;
    cb_func_t func;        // function pointer, NOT the name
    char args[384];
} rule_t;

rule_t rules[MAX_RULES];
size_t rules_count = 0;

bool find_rule_by_address(unsigned long long addr, rule_t **out_rule);
bool find_rule_by_address(unsigned long long addr, rule_t **out_rule) {
    for (size_t i = 0; i < rules_count; i++) {
        if (rules[i].address == addr) {
            if (out_rule) {
                *out_rule = &rules[i];
            }
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------
// virtual instructions
// ---------------------------------------------------------------
bool function_reached = false;
bool sub_semantic_reached = false;

// static void raiseirq(unsigned int cpu_index, void *udata);
// static void updatepc(unsigned int cpu_index, void *udata);
// static void updatereg(unsigned int cpu_index, void *udata);
// static void updatemem(unsigned int cpu_index, void *udata);
// static void randstate(unsigned int cpu_index, void *udata);
static void logpc(unsigned int cpu_index, void *udata);
static void resetpc(unsigned int cpu_index, void *udata);
static void randargs(unsigned int cpu_index, void *udata);
static void setargs(unsigned int cpu_index, void *udata);
static void randargs_sub_semantics(unsigned int cpu_index, void *udata);
static void logrets(unsigned int cpu_index, void *udata);
static void logrets_sub_semantics(unsigned int cpu_index, void *udata);
static void clearpathlogs(unsigned int cpu_index, void *udata);
static void logbbstart(unsigned int cpu_index, void *udata);
// static void dumplogger(unsigned int cpu_index, void *udata);
// static void dyninst(unsigned int cpu_index, void *udata);
// static void dyninst_lib(unsigned int cpu_index, void *udata);

// ----- updatemem -----
// #define MAX_BUFFER_SIZE 256

// typedef struct {
//     uint32_t address;
//     char mode; // 'r' or 'w'
//     uint32_t length;
//     uint8_t buffer[MAX_BUFFER_SIZE];
// } MemAccess;


// int parse_update_mem_arg(const char *input, MemAccess *out);
// int parse_update_mem_arg(const char *input, MemAccess *out) {
//     if (!input || !out) return -1;

//     // Temporary copy of input string for tokenizing
// 	char *temp = malloc(strlen(input) + 1);
// 	if (!temp) return -1;
// 	strcpy(temp, input);


//     char *token = strtok(temp, ":");
//     if (!token) { free(temp); return -1;}
//     out->address = strtoul(token, NULL, 0); // parse address

//     token = strtok(NULL, ":");
//     if (!token || (token[0] != 'r' && token[0] != 'w')) return -1;
//     out->mode = token[0]; // parse mode

//     token = strtok(NULL, ":");
//     if (!token) { free(temp); return -1;}
//     out->length = strtoul(token, NULL, 0); // parse length
//     if (out->length > MAX_BUFFER_SIZE) return -1;

//     token = strtok(NULL, ":");
//     if (!token) { free(temp); return -1;}

//     // Now parse comma-separated bytes
//     uint32_t i = 0;
//     char *byte_str = strtok(token, ",");
//     while (byte_str && i < out->length) {
//         out->buffer[i++] = (uint8_t)strtoul(byte_str, NULL, 0);
//         byte_str = strtok(NULL, ",");
//     }

//     if (i != out->length) { printf("Invalid Argument \n"); free(temp); return -1;}

// 	free(temp);
//     return 0; // success
// }

// static void updatemem(unsigned int cpu_index, void *udata) {
// 	const char *input = (const char *) udata;
// 	MemAccess mem;

//     if (parse_update_mem_arg(input, &mem) == 0) {
// 		if (mem.mode == 'r') {
// 			qemu_plugin_read_memory(mem.address, mem.buffer, mem.length);
// 		} else {
// 			qemu_plugin_write_memory(mem.address, mem.buffer, mem.length);
// 		}
// 	}
// }


// ----- dyninst, dyninst_lib -----
// #define MAX_FILENAME_LEN 256

// typedef struct {
//     uint64_t addr;
//     char filename[MAX_FILENAME_LEN];  // Fixed-size buffer
// } AddrFilePair;

// static void dyninst_lib(unsigned int cpu_index, void *udata) {
// 	qemu_plugin_load_elf((char *) udata);
// }


// AddrFilePair parse_addr_file(const char *input);
// AddrFilePair parse_addr_file(const char *input) {
//     AddrFilePair result = {0, {0}};

//     const char *colon = strchr(input, ':');
//     if (!colon) {
//         fprintf(stderr, "Invalid format: no ':' found.\n");
//         return result;
//     }

//     // Parse address part
//     char addr_str[32] = {0}; // Enough for 64-bit address string
//     size_t addr_len = colon - input;

//     if (addr_len >= sizeof(addr_str)) {
//         fprintf(stderr, "Address string too long.\n");
//         return result;
//     }

//     strncpy(addr_str, input, addr_len);
//     addr_str[addr_len] = '\0';

//     result.addr = strtoull(addr_str, NULL, 0); // auto-detect 0x

//     // Copy filename part into fixed buffer
//     const char *filename = colon + 1;

//     if (strlen(filename) >= MAX_FILENAME_LEN) {
//         fprintf(stderr, "Filename too long. Truncated.\n");
//         strncpy(result.filename, filename, MAX_FILENAME_LEN - 1);
//         result.filename[MAX_FILENAME_LEN - 1] = '\0'; // Null-terminate
//     } else {
//         strcpy(result.filename, filename);
//     }

//     return result;
// }

// // Reads entire file into a buffer.
// // Returns pointer to buffer and sets *length to file size.
// // Returns NULL on error.
// void* read_file(const char *filename, size_t *length);
// void* read_file(const char *filename, size_t *length) {
//     FILE *file = fopen(filename, "rb");
//     if (!file) {
//         perror("Error opening file");
//         return NULL;
//     }

//     // Seek to end to find file size
//     if (fseek(file, 0, SEEK_END) != 0) {
//         perror("Error seeking file");
//         fclose(file);
//         return NULL;
//     }

//     long file_size = ftell(file);
//     if (file_size < 0) {
//         perror("Error telling file position");
//         fclose(file);
//         return NULL;
//     }
//     rewind(file); // Go back to start

//     // Allocate buffer
//     void *buffer = malloc(file_size);
//     if (!buffer) {
//         perror("Memory allocation failed");
//         fclose(file);
//         return NULL;
//     }

//     // Read entire file into buffer
//     size_t read_size = fread(buffer, 1, file_size, file);
//     if (read_size != file_size) {
//         perror("Error reading file");
//         free(buffer);
//         fclose(file);
//         return NULL;
//     }

//     fclose(file);
//     *length = file_size; // Return size
//     return buffer;
// }

// void dyninst(unsigned int cpu_index, void *udata) {
// 	AddrFilePair parsed = parse_addr_file((char *)udata);
	
// 	size_t file_len = 0;
// 	void *file_buf = read_file(parsed.filename, &file_len);
// 	if (file_buf) {
// 		qemu_plugin_write_memory(parsed.addr, file_buf, file_len);
// 		free(file_buf);
// 	}
// }

// ----- raiseirq, updatepc, updatereg -----
// static void raiseirq(unsigned int cpu_index, void *udata){
// 	qemu_plugin_raise_irq(15);
// }

// static void updatepc(unsigned int cpu_index, void *udata)
// {
// 	// BUGON: This wont' work anymore
// 	uint32_t val = 0xdeadbeef;
// 	val = (0x106cc | 1);
// 	qemu_plugin_set_register((uint8_t *)&val, 15);
// }

// static void updatereg(unsigned int cpu_index, void *udata)
// {
//     ValueUnion vn;
//     vn.f = 6.28;
//     qemu_plugin_set_register((uint8_t *)&vn, 26); //  26 is s0
// }

// ----- logpc, resetpc -----
#define MAX_INSTRUCTION_NUM 10000
unsigned long instr_addrs[MAX_BASIC_BLOCKS];
int instr_count = 0;
int is_instr_logged(unsigned long addr);
int is_instr_logged(unsigned long addr) {
    for (int i = 0; i < instr_count; i++) {
        if (instr_addrs[i] == addr) {
            return 1;
        }
    }
    return 0;
}
int get_logged_instr_index(unsigned long addr);
int get_logged_instr_index(unsigned long addr) {
    for (int i = 0; i < instr_count; i++) {
        if (instr_addrs[i] == addr) {
            return i;
        }
    }
    return -1;
}

static void logpc(unsigned int cpu_index, void *udata)
{
    // if (function_reached) {
        // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15); // this is not the true pc sometime
        // uint32_t pc = *(uint32_t *)udata;
        uint64_t pc = *(uint64_t *)udata;
        printf("[VI logpc] Current PC: 0x%08lx\n", pc);
    // }
}
static void resetpc(unsigned int cpu_index, void *udata)
{
    if (function_reached) {
        // uint32_t pc = qemu_get_register_32(ARM_V7M_REG_R15);
        // printf("[VI resetpc] Current PC: 0x%08x\n", pc); // this is not the true pc sometime
        if (!is_logging_valid) {
            // reset to func_start
            uint32_t pc = (uint32_t) func_start;
            qemu_plugin_set_register((uint8_t *)&pc, ARM_V7M_REG_R15);
            printf("[VI resetpc] PC reset to function start: 0x%08x\n", pc);
            // qemu_plugin_vcpu_request_exit();
        }
    }
}

// ---------------------------------------------------------------
// cb_registry
// ---------------------------------------------------------------

cb_entry_t cb_registry[] = {
    // { "updatepc", updatepc },
	// { "updatereg", updatereg},
	// { "updatemem", updatemem},
	// { "randstate", randstate},
    { "logpc", logpc},
    { "resetpc", resetpc},
    { "randargs", randargs },
    { "setargs", setargs},
    { "randargs_sub_semantics", randargs_sub_semantics},
    { "logrets", logrets},
    { "logrets_sub_semantics", logrets_sub_semantics},
    { "clearpathlogs", clearpathlogs},
    { "logbbstart", logbbstart},
    // { "raiseirq", raiseirq },
	// { "dumplog", dumplogger},
	// { "dyninst", dyninst},
	// { "dyninst_lib", dyninst_lib},
};

const size_t cb_registry_len = sizeof(cb_registry) / sizeof(cb_registry[0]);

static cb_func_t lookup_callback(const char *name) {
    for (size_t i = 0; i < cb_registry_len; i++) {
        if (strcmp(cb_registry[i].name, name) == 0)
            return cb_registry[i].func;
    }
    return NULL;
}

void parse_rules_file(const char *filename);
void parse_rules_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("Failed to open rules file");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '\n' || line[0] == '#') continue;
        line[strcspn(line, "\r\n")] = 0;

        char addr_str[32];
        char cb_name[64];
        char args[384] = {0};

        int n = sscanf(line, "%31s %63s %383[^\n]", addr_str, cb_name, args);
        if (n < 2) {
            fprintf(stderr, "Invalid line in rules file: '%s'\n", line);
            continue;
        }

        cb_func_t cb = lookup_callback(cb_name);
        if (!cb) {
            fprintf(stderr, "Error: Callback '%s' not found in registry (line: '%s')\n", cb_name, line);
            continue;
        }

        if (rules_count >= MAX_RULES) {
            fprintf(stderr, "Max rules limit reached (%d), skipping rest\n", MAX_RULES);
            break;
        }

        rules[rules_count].address = strtoull(addr_str, NULL, 0);
        rules[rules_count].func = cb;

        if (n == 3) {
            // strncpy(rules[rules_count].args, args, sizeof(rules[rules_count].args) - 1);
            strncpy(rules[rules_count].args, args, sizeof(rules[rules_count].args));
            rules[rules_count].args[sizeof(rules[rules_count].args) - 1] = '\0';
        } else {
            rules[rules_count].args[0] = '\0';
        }

        rules_count++;
    }

    fclose(f);
}

#endif // VIRTUAL_H
