/*
 * Copyright (C) 2018, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
int isdigit(int c);
#include <ctype.h>
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>

#include <qemu-plugin.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "virtual.h"
#include "json_parse.h"
#include "path_logger.h"

#define MAX_ENTRIES 1024
#define MAX_LINE_LEN 128
#define MAX_RULES 256

typedef unsigned long hwaddr;
typedef struct unimp_exporter {
    uint64_t (*read)(void *opaque, hwaddr offset, unsigned size);
    void (*write)(void *opaque, hwaddr offset, uint64_t value, unsigned size);
} DEV_XPORTER;

typedef enum {
    VALUE_IMMEDIATE, // existing: value is immediate
    VALUE_REGISTER,  // new: value comes from another register (e.g., r3)
    VALUE_DEREF      // new: value is loaded from the memory address held in r3
} ValueType;

typedef enum {
    TARGET_REGISTER,
    TARGET_MEMORY,
	TARGET_DEREF
} TargetType;

typedef struct {
    unsigned long update_point;
    TargetType type; // TARGET_REGISTER or TARGET_MEMORY

    union {
        int reg_num;          // if TARGET_REGISTER
        unsigned long addr;   // if TARGET_MEMORY
    } target;

    ValueType value_type;

    union {
        unsigned long imm; // VALUE_IMMEDIATE
        int reg_num;       // VALUE_REGISTER and VALUE_DEREF (source register)
    } value;
} UpdateEntry;

static const char * runtime;

#define MAX_LISTS 100
#define MAX_ENTRIES_PER_LIST 100
#define LINE_BUFFER_SIZE 1024

typedef struct {
    uint32_t *buffer;  // Pointer to the buffer
    uint16_t index;     // Current index into the buffer
} Buffy;

typedef struct {
    uintptr_t address;
    int reg; // "register" number (just a number)
} LoggerEntry;

typedef struct {
    LoggerEntry entries[MAX_ENTRIES_PER_LIST];
    size_t count;
	Buffy log_buf;
} AddressList;

AddressList addressLists[MAX_LISTS];
size_t listCount = 0;

// Helper: Parse "0xADDR:REGISTER" format
bool parse_entry(const char* token, LoggerEntry* entry);
bool parse_entry(const char* token, LoggerEntry* entry) {
    char* colonPos = strchr(token, ':');
    if (!colonPos) return false;

    *colonPos = '\0';
    const char* addrPart = token;
    const char* regPart = colonPos + 1;

    // Parse address
    uintptr_t addr = (uintptr_t)strtoull(addrPart, NULL, 0);

    // Parse register (as a simple integer)
    int regNum = atoi(regPart);

    entry->address = addr;
    entry->reg = regNum;
    return true;
}

// Parse a single line into an AddressList
void parse_logger(const char* line);
void parse_logger(const char* line) {
    if (listCount >= MAX_LISTS) {
        fprintf(stderr, "Too many lists!\n");
        return;
    }

    AddressList* list = &addressLists[listCount];
    list->count = 0;

    char* lineCopy = strdup(line);
    if (!lineCopy) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }

    char* token = strtok(lineCopy, ",\n\r");
    while (token != NULL && list->count < MAX_ENTRIES_PER_LIST) {
        while (*token == ' ' || *token == '\t') token++; // trim leading whitespace

        LoggerEntry entry;
        if (parse_entry(token, &entry)) {
            list->entries[list->count++] = entry;
        } else {
            fprintf(stderr, "Invalid entry: %s\n", token);
        }

        token = strtok(NULL, ",\n\r");
    }

    free(lineCopy);
    listCount++;
}

// Load logger configuration file
void load_logger_config(const char* filename);
void load_logger_config(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    char buffer[LINE_BUFFER_SIZE];
    while (fgets(buffer, sizeof(buffer), file)) {
        parse_logger(buffer);
    }

    fclose(file);
}

// Check if address+register exists in any list
bool address_in_any_list(uintptr_t addr, int reg);
bool address_in_any_list(uintptr_t addr, int reg) {
    for (size_t i = 0; i < listCount; i++) {
        AddressList* list = &addressLists[i];
        for (size_t j = 0; j < list->count; j++) {
            if (list->entries[j].address == addr && list->entries[j].reg == reg) {
                return true;
            }
        }
    }
    return false;
}
rule_t rules[MAX_RULES];
size_t rules_count = 0;

// Global storage
UpdateEntry update_entries[MAX_ENTRIES];
size_t update_entry_count = 0;



// Helper to parse a single line
static int parse_update_line(const char *line, UpdateEntry *entry);
int parse_update_line(const char *line, UpdateEntry *entry) {
    char buf[128];
    char *token;
    char *endptr;

    strncpy(buf, line, sizeof(buf));
    buf[sizeof(buf) - 1] = '\0'; // Ensure null termination

    // First token: update_point
    token = strtok(buf, " \t");
    if (!token) return -1;
    entry->update_point = strtoul(token, &endptr, 0);
    if (*endptr != '\0') return -1;

    // Second token: target (rX, [rX] or 0xADDRESS)
	token = strtok(NULL, " \t");
    if (!token) return -1;
	if (token[0] == 'r') {
    entry->type = TARGET_REGISTER;
    entry->target.reg_num = strtoul(token + 1, &endptr, 0);
    if (*endptr != '\0') return -1;
	} else if (token[0] == '[' && token[strlen(token) - 1] == ']') {
    // Target is [rX] dereference
    token[strlen(token) - 1] = '\0'; // Remove trailing ']'
    if (token[1] != 'r') {
        fprintf(stderr, "Invalid target deref syntax: %s\n", token);
        return -1;
    }
    entry->type = TARGET_DEREF;
    entry->target.reg_num = strtoul(token + 2, &endptr, 0); // skip [r
    if (*endptr != '\0') return -1;
	} else if (strncmp(token, "0x", 2) == 0) {
    entry->type = TARGET_MEMORY;
    entry->target.addr = strtoul(token, &endptr, 0);
    if (*endptr != '\0') return -1;
	} else {
    fprintf(stderr, "Invalid target: %s\n", token);
    return -1;
	}


    // Third token: value (immediate, register, or dereference)
    token = strtok(NULL, " \t");
    if (!token) return -1;

    if (token[0] == 'r') {
        // Source is a register value
        entry->value_type = VALUE_REGISTER;
        entry->value.reg_num = strtoul(token + 1, &endptr, 0);
        if (*endptr != '\0') return -1;
    } else if (token[0] == '[' && token[strlen(token) - 1] == ']') {
        // Source is [rX] dereference
        token[strlen(token) - 1] = '\0'; // strip trailing ']'
        if (token[1] != 'r') {
            fprintf(stderr, "Invalid dereference syntax: %s\n", token);
            return -1;
        }
        entry->value_type = VALUE_DEREF;
        entry->value.reg_num = strtoul(token + 2, &endptr, 0); // skip [r
        if (*endptr != '\0') return -1;
    } else {
        // Must be an immediate
        entry->value_type = VALUE_IMMEDIATE;
        entry->value.imm = strtoul(token, &endptr, 0);
        if (*endptr != '\0') return -1;
    }

    return 0;
}

// Function to load all updates from a file into the global array
int load_update_entries(const char *filename);
int load_update_entries(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("fopen");
        return 0;
    }

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), f)) {
        // Strip newline
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '\0' || line[0] == '#') continue;

        if (update_entry_count >= MAX_ENTRIES) {
            fprintf(stderr, "Too many entries (limit: %d)\n", MAX_ENTRIES);
            fclose(f);
            return 0;
        }

        if (parse_update_line(line, &update_entries[update_entry_count]) == 0) {
            update_entry_count++;
        } else {
            fprintf(stderr, "Error parsing line: %s\n", line);
        }
    }

    fclose(f);
    return 1;
}

#define MAX_TUPLES 1000

typedef struct {
    uintptr_t anchor;
    uintptr_t target;
} AddressTuple;

static AddressTuple address_tuples[MAX_TUPLES];
static size_t num_tuples = 0;

/* Prototypes */
AddressTuple * is_target_address(uintptr_t addr);
void print_tuples(AddressTuple *tuples, size_t count);
size_t read_tuples_from_file(const char *filename, AddressTuple *tuples, size_t max_tuples);

AddressTuple * is_target_address(uintptr_t addr) {
    for (size_t i = 0; i < num_tuples; ++i) {
        if (address_tuples[i].target == addr) {
            return &address_tuples[i];
        }
    }
    return NULL;
}

size_t read_tuples_from_file(const char *filename, AddressTuple *tuples, size_t max_tuples) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("fopen");
        exit(1);
    }

    size_t count = 0;
    while (count < max_tuples &&
           fscanf(f, "%lx %lx", &tuples[count].anchor, &tuples[count].target) == 2) {
        count++;
    }

    fclose(f);
    return count;
}

void print_tuples(AddressTuple *tuples, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        printf("Tuple %zu: %p -> %p\n", i,
               (void *)tuples[i].anchor,
               (void *)tuples[i].target);
    }
}
/* You can use these functions like this 

int main() {
    AddressTuple tuples[MAX_TUPLES];

    size_t count = read_tuples_from_file("addrs.txt", tuples, MAX_TUPLES);
    print_tuples(tuples, count);

    return 0;
}

*/


#define MAX_BUFFER_SIZE 256

typedef struct {
    uint32_t address;
    char mode; // 'r' or 'w'
    uint32_t length;
    uint8_t buffer[MAX_BUFFER_SIZE];
} MemAccess;


int parse_update_mem_arg(const char *input, MemAccess *out);
int parse_update_mem_arg(const char *input, MemAccess *out) {
    if (!input || !out) return -1;

    // Temporary copy of input string for tokenizing
	char *temp = malloc(strlen(input) + 1);
	if (!temp) return -1;
	strcpy(temp, input);


    char *token = strtok(temp, ":");
    if (!token) { free(temp); return -1;}
    out->address = strtoul(token, NULL, 0); // parse address

    token = strtok(NULL, ":");
    if (!token || (token[0] != 'r' && token[0] != 'w')) return -1;
    out->mode = token[0]; // parse mode

    token = strtok(NULL, ":");
    if (!token) { free(temp); return -1;}
    out->length = strtoul(token, NULL, 0); // parse length
    if (out->length > MAX_BUFFER_SIZE) return -1;

    token = strtok(NULL, ":");
    if (!token) { free(temp); return -1;}

    // Now parse comma-separated bytes
    uint32_t i = 0;
    char *byte_str = strtok(token, ",");
    while (byte_str && i < out->length) {
        out->buffer[i++] = (uint8_t)strtoul(byte_str, NULL, 0);
        byte_str = strtok(NULL, ",");
    }

    if (i != out->length) { printf("Invalid Argument \n"); free(temp); return -1;}

	free(temp);
    return 0; // success
}

unsigned long long* parse_addresses(const char *input, size_t *count);
unsigned long long* parse_addresses(const char *input, size_t *count) {
    // Make a copy of input so we don't modify the original
    char *input_copy = strdup(input);
    if (!input_copy) return NULL;

    size_t capacity = 8;
    *count = 0;
    unsigned long long *addresses = malloc(capacity * sizeof(unsigned long long));
    if (!addresses) {
        free(input_copy);
        return NULL;
    }

    char *token = strtok(input_copy, ",");
    while (token) {
        // Remove leading/trailing whitespace
        while (*token == ' ' || *token == '\t') token++;
        char *endptr;
        unsigned long long addr = strtoull(token, &endptr, 0);
        if (token == endptr) {
            // Invalid conversion
            free(addresses);
            free(input_copy);
            return NULL;
        }

        if (*count >= capacity) {
            capacity *= 2;
            addresses = realloc(addresses, capacity * sizeof(unsigned long long));
            if (!addresses) {
                free(input_copy);
                return NULL;
            }
        }

        addresses[(*count)++] = addr;
        token = strtok(NULL, ",");
    }

    free(input_copy);
    return addresses;
}

// zz: basic block starts
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

    for (int i = 0; i < bb_count; i++) {
        printf("Basic Block %d starts at: 0x%lx\n", i, bb_starts[i]);
    }
}


QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
int counter;

#define HOOK_POINT	(0x106d6)
#define ANCHOR		(0x106cc)


static void raiseirq(unsigned int cpu_index, void *udata);
static void updatepc(unsigned int cpu_index, void *udata);
static void updatereg(unsigned int cpu_index, void *udata);
static void updatemem(unsigned int cpu_index, void *udata);
static void randstate(unsigned int cpu_index, void *udata);
static void randargs(unsigned int cpu_index, void *udata);
static void logrets(unsigned int cpu_index, void *udata);
static void clearpathlogs(unsigned int cpu_index, void *udata);
static void logbbstart(unsigned int cpu_index, void *udata);
static void dumplogger(unsigned int cpu_index, void *udata);
static void dyninst(unsigned int cpu_index, void *udata);
static void dyninst_lib(unsigned int cpu_index, void *udata);

uint32_t qemu_get_register(int reg);
uint32_t qemu_get_register(int reg)
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

cb_entry_t cb_registry[] = {
    { "updatepc", updatepc },
	{ "updatereg", updatereg},
	{ "updatemem", updatemem},
	{ "randstate", randstate},
    { "randargs", randargs },
    { "logrets", logrets},
    { "clearpathlogs", clearpathlogs},
    { "logbbstart", logbbstart},
    { "raiseirq", raiseirq },
	{ "dumplog", dumplogger},
	{ "dyninst", dyninst},
	{ "dyninst_lib", dyninst_lib},
};

#define MAX_FILENAME_LEN 256

typedef struct {
    uint64_t addr;
    char filename[MAX_FILENAME_LEN];  // Fixed-size buffer
} AddrFilePair;

static void dyninst_lib(unsigned int cpu_index, void *udata) {
	qemu_plugin_load_elf((char *) udata);
}


AddrFilePair parse_addr_file(const char *input);
AddrFilePair parse_addr_file(const char *input) {
    AddrFilePair result = {0, {0}};

    const char *colon = strchr(input, ':');
    if (!colon) {
        fprintf(stderr, "Invalid format: no ':' found.\n");
        return result;
    }

    // Parse address part
    char addr_str[32] = {0}; // Enough for 64-bit address string
    size_t addr_len = colon - input;

    if (addr_len >= sizeof(addr_str)) {
        fprintf(stderr, "Address string too long.\n");
        return result;
    }

    strncpy(addr_str, input, addr_len);
    addr_str[addr_len] = '\0';

    result.addr = strtoull(addr_str, NULL, 0); // auto-detect 0x

    // Copy filename part into fixed buffer
    const char *filename = colon + 1;

    if (strlen(filename) >= MAX_FILENAME_LEN) {
        fprintf(stderr, "Filename too long. Truncated.\n");
        strncpy(result.filename, filename, MAX_FILENAME_LEN - 1);
        result.filename[MAX_FILENAME_LEN - 1] = '\0'; // Null-terminate
    } else {
        strcpy(result.filename, filename);
    }

    return result;
}

// Reads entire file into a buffer.
// Returns pointer to buffer and sets *length to file size.
// Returns NULL on error.
void* read_file(const char *filename, size_t *length);
void* read_file(const char *filename, size_t *length) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return NULL;
    }

    // Seek to end to find file size
    if (fseek(file, 0, SEEK_END) != 0) {
        perror("Error seeking file");
        fclose(file);
        return NULL;
    }

    long file_size = ftell(file);
    if (file_size < 0) {
        perror("Error telling file position");
        fclose(file);
        return NULL;
    }
    rewind(file); // Go back to start

    // Allocate buffer
    void *buffer = malloc(file_size);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return NULL;
    }

    // Read entire file into buffer
    size_t read_size = fread(buffer, 1, file_size, file);
    if (read_size != file_size) {
        perror("Error reading file");
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    *length = file_size; // Return size
    return buffer;
}

void dyninst(unsigned int cpu_index, void *udata) {
	AddrFilePair parsed = parse_addr_file((char *)udata);
	
	size_t file_len = 0;
	void *file_buf = read_file(parsed.filename, &file_len);
	if (file_buf) {
		qemu_plugin_write_memory(parsed.addr, file_buf, file_len);
		free(file_buf);
	}
}

#define LOG_BUFFER_SIZE (UINT16_MAX + 1)

const size_t cb_registry_len = sizeof(cb_registry) / sizeof(cb_registry[0]);
void dump_log_buffer_to_file(const AddressList* list, const char* filename);
void dump_log_buffer_to_file(const AddressList* list, const char* filename) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        perror("fopen");
        return;
    }

    // Write the entire buffer
    size_t written = fwrite(list->log_buf.buffer, sizeof(uint32_t), (LOG_BUFFER_SIZE/sizeof(uint32_t)), file);
    if (written != LOG_BUFFER_SIZE) {
        fprintf(stderr, "Warning: Only wrote %zu words out of %u\n", written, LOG_BUFFER_SIZE);
    }

    fclose(file);
}
typedef struct {
    int idx;
    char file_name[256]; // Max file name size (adjust as needed)
} FileEntry;

bool parse_file_entry(const char* line, FileEntry* entry);
bool parse_file_entry(const char* line, FileEntry* entry) {
    char* colonPos = strchr(line, ':');
    if (!colonPos) {
        return false; // No colon found — invalid format
    }

    // Split into index and file_name parts
    size_t idxLen = colonPos - line;
    char idxStr[32]; // Enough for int
    if (idxLen >= sizeof(idxStr)) return false; // Index too big to fit

    strncpy(idxStr, line, idxLen);
    idxStr[idxLen] = '\0';

    // Parse integer index
    entry->idx = atoi(idxStr);

    // Copy file name part
    strncpy(entry->file_name, colonPos + 1, sizeof(entry->file_name) - 1);
    entry->file_name[sizeof(entry->file_name) - 1] = '\0'; // Ensure null-terminated

    return true;
}

static void dumplogger(unsigned int cpu_index, void *udata) {
	FileEntry entry;
	parse_file_entry((const char*) udata, &entry);
	dump_log_buffer_to_file(&addressLists[entry.idx], entry.file_name);
}

static void raiseirq(unsigned int cpu_index, void *udata){
	qemu_plugin_raise_irq(15);
}

static void updatemem(unsigned int cpu_index, void *udata) {
	const char *input = (const char *) udata;
	MemAccess mem;

    if (parse_update_mem_arg(input, &mem) == 0) {
		if (mem.mode == 'r') {
			qemu_plugin_read_memory(mem.address, mem.buffer, mem.length);
		} else {
			qemu_plugin_write_memory(mem.address, mem.buffer, mem.length);
		}
	}
}

#include <stdio.h>
#include <stdlib.h>

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


static void randstate(unsigned int cpu_index, void *udata) {
	const char *input = (const char *) udata;

	size_t count = 0;
	unsigned long long *addrs = parse_addresses(input, &count);
	if (addrs) {
        for (size_t i = 0; i < count; i++) {
			if (addrs[i] < 100) {
				uint32_t val = get_random_word();
				//PC not supported 
				if (addrs[i] != 15) {
					qemu_plugin_set_register((uint8_t *)&val,addrs[i] );
				}
			} else {
				uint8_t val = get_random_byte();
				qemu_plugin_write_memory(addrs[i], &val, 1);
			}
        }
        free(addrs);
    } else {
        printf("Failed to parse addresses.\n");
    }

}

float get_random_float(float min, float max);
float get_random_float(float min, float max) {
    // Generate a random float in the range [min, max]
    unsigned int random_word = get_random_word();
    return min + (random_word / (float)UINT32_MAX) * (max - min);
}

static int cur_iteration = 0;
static void randargs(unsigned int cpu_index, void *udata) {
    // printf("randargs - results for iteration %d:\n", cur_iteration);
    // dump_latest_ret_values();
    if (cur_iteration >= 6) { // run 3 iterations
        printf("randargs iteration %d limit reached, dump values and exit.\n", cur_iteration);
        // dump_ret_values();
        dump_all_path_logs();
        exit(0);
    }
    if (cur_iteration == 0) {
        // clear path logs
        clear_all_path_logs();
    }
    else {
        // log previous iteration values
        record_trace_values(current_path, current_path_len, logged_in_values, logged_out_values);
        // clear
        current_path_len = 0;
    }

    cur_iteration++;
    printf("randargs iteration %d:\n", cur_iteration);
    // iterate arg_settings
    for (size_t i = 0; i < arg_count; i++) {
        ArgSetting *setting = &arg_settings[i];
        // use range to generate random value
        ValueUnion value;
        if (setting->vtype == TYPE_FLOAT) {
            // assert(setting->value_count == 2);
            if (setting->value_count == 1) {
                value.f = setting->value_range[0].f;
            }
            else if (setting->value_count == 2) {
                // Generate a random float in the range
                value.f = get_random_float(setting->value_range[0].f, setting->value_range[1].f);
            } else {
                fprintf(stderr, "Invalid value count for float type in setting '%s'\n", setting->name);
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
            } else {
                fprintf(stderr, "Invalid value count for uint32 type in setting '%s'\n", setting->name);
                perror("randargs");
                exit(EXIT_FAILURE);
            }
        } else {
            fprintf(stderr, "Unsupported value type in setting '%s'\n", setting->name);
            perror("randargs");
            exit(EXIT_FAILURE);
        }

        if (setting->location_type == TYPE_REG) {
            // printf("randargs - setting register %s to value: %u\n", setting->reg, value.u32);
            if (setting->vtype == TYPE_FLOAT) {
                printf("randargs - setting register %s to value: %g\n", setting->reg, value.f);
            } else {
                printf("randargs - setting register %s to value: %u\n", setting->reg, value.u32);
            }
            qemu_plugin_set_register((uint8_t *)&value, get_reg_by_name(setting->reg));
        } else if (setting->location_type == TYPE_ADDR) {
            // printf("randargs - writing value %u to memory address: 0x%lx\n", value.u32, setting->addr);
            if (setting->vtype == TYPE_FLOAT) {
                printf("randargs - writing value %g to memory address: 0x%lx\n", value.f, setting->addr);
            } else {
                printf("randargs - writing value %u to memory address: 0x%lx\n", value.u32, setting->addr);
            }
            qemu_plugin_write_memory(setting->addr, (uint8_t *)&value, 4);
        } else {
            fprintf(stderr, "Unsupported location type in setting '%s'\n", setting->name);
            perror("randargs");
            exit(EXIT_FAILURE);
        }

        // log values
        logged_in_values[i] = value;
    }
}

static void logrets(unsigned int cpu_index, void *udata) {
    // This function is called when the magic instruction is executed
    // It will dump the latest return values to the log buffer
    printf("logrets called, dumping latest return values.\n");
    for (size_t i = 0; i < ret_count; i++) {
        RetSetting *setting = &ret_settings[i];
        ValueUnion value;
        if (setting->location_type == TYPE_REG) {
            // Log register value
            value.u32 = qemu_get_register(get_reg_by_name(setting->reg));
            if (setting->vtype == TYPE_FLOAT) {
                // value.f = qemu_get_register(get_reg_by_name(setting->reg));
                printf("logrets - register %s: %g\n", setting->reg, value.f);
            } else {
                // value.u32 = qemu_get_register(get_reg_by_name(setting->reg));
                printf("logrets - register %s: %u\n", setting->reg, value.u32);
            }
        } else if (setting->location_type == TYPE_ADDR) {
            // Log memory value
            qemu_plugin_read_memory(setting->addr, (uint8_t *)&value, 4);
            if (setting->vtype == TYPE_FLOAT) {
                printf("logrets - memory address 0x%lx: %g\n", setting->addr, value.f);
            } else {
                printf("logrets - memory address 0x%lx: %u\n", setting->addr, value.u32);
            }
        } else {
            fprintf(stderr, "Unsupported location type in setting '%s'\n", setting->name);
            perror("logrets");
            exit(EXIT_FAILURE);
        }

        // log out values
        logged_out_values[i] = value;
    }
}

static void clearpathlogs(unsigned int cpu_index, void *udata) {
    // Clear all path logs
    clear_all_path_logs();
}

static void logbbstart(unsigned int cpu_index, void *udata) {
    // get pc vlue
    uint32_t pc = qemu_get_register(15); // Assuming 15 is the
    current_path[current_path_len++] = (uint64_t)pc;
}

static void updatepc(unsigned int cpu_index, void *udata)
{
	// BUGON: This wont' work anymore
	uint32_t val = 0xdeadbeef;
	val = (0x106cc | 1);
	qemu_plugin_set_register((uint8_t *)&val, 15);
}

static void updatereg(unsigned int cpu_index, void *udata)
{
    ValueUnion vn;
    vn.f = 6.28;
    qemu_plugin_set_register((uint8_t *)&vn, 26); //  26 is s0
}



// Finds all update entries targeting the given memory address.
// `matches` is an output array to be filled with pointers to matching entries.
// `max_matches` limits how many results to return.
// Returns the number of matches found.
size_t find_updates_for_address(unsigned long addr,
                                UpdateEntry **matches,
                                size_t max_matches);
size_t find_updates_for_address(unsigned long addr,
                                UpdateEntry **matches,
                                size_t max_matches)
{
    size_t count = 0;
    for (size_t i = 0; i < update_entry_count && count < max_matches; ++i) {
        if (update_entries[i].update_point == addr)
        {
            matches[count++] = &update_entries[i];
        }
    }
    return count;
}

int inline_ins = 0;
#define MAX_MATCHES 10


typedef struct {
    AddressList* list;
    LoggerEntry* entry;
} LookupResult;

// Find an address in any list and return both the list and entry pointers
LookupResult lookup_addr(uintptr_t addr);
LookupResult lookup_addr(uintptr_t addr) {
    LookupResult result = {0};

    for (size_t i = 0; i < listCount; i++) {
        AddressList* list = &addressLists[i];
        for (size_t j = 0; j < list->count; j++) {
            if (list->entries[j].address == addr) {
                result.list = list;
                result.entry = &list->entries[j];
                return result; // First match returned
            }
        }
    }

    // Not found
    result.list = NULL;
    result.entry = NULL;
    return result;
}
static int init = 0;
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
	if (runtime && !init) {
			qemu_plugin_load_elf((char *)runtime);
			init = 1;
	}
    size_t n = qemu_plugin_tb_n_insns(tb);
    size_t i;
	UpdateEntry *matches[MAX_MATCHES];

	printf("->Virtual Clock: %llu \n", (unsigned long long)qemu_plugin_get_virtual_timer());

    for (i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

		if (qemu_plugin_insn_vaddr(insn) == 0x20800050) {
				//Magic instruction
				qemu_plugin_u64 entry_tmp;
                // In TCG frontend it is already set, if you want to modify it you will have to
                // change CPSR.
                entry_tmp.data = NULL;
				qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_UPDATE_REG, entry_tmp, -1);
				return;
		}


		//Highest priority: Logger
		LookupResult ret = lookup_addr(qemu_plugin_insn_vaddr(insn));
		if (ret.list) {
			qemu_plugin_u64 entry_tmp;
			if (!ret.list->log_buf.buffer) {
					ret.list->log_buf.buffer = malloc(UINT16_MAX + 1);
			}
			entry_tmp.offset = (size_t)&ret.list->log_buf;
			qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_LOG_REG, entry_tmp, ret.entry->reg);
		}

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

		//Middle prioirity is Virtual instructions 
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


		//Second to Highest priority: Modifier (zz: move modifier after vi)
		//void * handle= qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn,  QEMU_PLUGIN_CB_GEN_LABEL, NULL, 0);
		size_t count = find_updates_for_address(qemu_plugin_insn_vaddr(insn), matches, MAX_MATCHES);
		if (count > 0) {
		for (size_t match_idx = 0; match_idx < count; ++match_idx) {
			UpdateEntry *e = matches[match_idx];

			printf("  Update Point: 0x%lx, ", e->update_point);
	        if (e->type == TARGET_REGISTER || e->type == TARGET_DEREF) {
    	        printf("Target: r%d, ", e->target.reg_num);
				qemu_plugin_u64 entry;
                // In TCG frontend it is already set, if you want to modify it you will have to
                // change CPSR.
                entry.offset = (size_t)(e->value.imm);
				entry.data = (void *)e;
                qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_UPDATE_REG, entry, e->target.reg_num);
	        } else if (e->type == TARGET_MEMORY) {
				printf("Target: r%d, ", e->target.reg_num);
                qemu_plugin_u64 entry;
                // In TCG frontend it is already set, if you want to modify it you will have to
                // change CPSR.
                entry.offset = (size_t)(e->value.imm);
                qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn, QEMU_PLUGIN_INLINE_UPDATE_MEM, entry, e->target.addr);
    	        printf("Target: 0x%lx, ", e->target.addr);
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

static cb_func_t lookup_callback(const char *name) {
    for (size_t i = 0; i < cb_registry_len; i++) {
        if (strcmp(cb_registry[i].name, name) == 0)
            return cb_registry[i].func;
    }
    return NULL;
}


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

void parse_json_args(const char *filename);
void parse_json_args(const char *filename)
{
    char *json = read_json_file(filename);
    if (!json) {
        perror("read_json_file failed");
        return;
    }

    parse_arg_settings(json);

    free(json);

    dump_arg_settings();
}

void parse_json_outs(const char *filename);
void parse_json_outs(const char *filename)
{
    char *json = read_json_file(filename);
    if (!json) {
        perror("read_json_file failed");
        return;
    }

    parse_ret_settings(json);

    free(json);

    dump_ret_settings();
}

#if 0
static void print_rules(void) {
    printf("Parsed %zu rules:\n", rules_count);
    for (size_t i = 0; i < rules_count; i++) {
        printf("Rule %zu: Addr=0x%llx, Func=%p, Args='%s'\n",
               i, rules[i].address, (void *)rules[i].func, rules[i].args);
    }
}
#endif

uint64_t my_unimp_read(void *opaque, hwaddr offset, unsigned size);
uint64_t my_unimp_read(void *opaque, hwaddr offset, unsigned size) {
    printf("Read at offset 0x%" PRIx64 "\n", offset);
    return 0x0;
}

void my_unimp_write(void *opaque, hwaddr offset, uint64_t value, unsigned size);
void my_unimp_write(void *opaque, hwaddr offset, uint64_t value, unsigned size) {
    printf("Write at offset 0x%" PRIx64 " value 0x%" PRIx64 "\n", offset, value);
}

DEV_XPORTER importer = {.read = my_unimp_read,
        .write = my_unimp_write};


QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
	if (argc < 1) {
        fprintf(stderr, "Usage: plugin.so <address_file.txt>\n");
        return -1;
    }

	const char *filename= get_arg("detour", argc, argv);
    num_tuples = read_tuples_from_file(filename, address_tuples, MAX_TUPLES);

	filename= get_arg("modifier", argc, argv);
	load_update_entries(filename);

	filename = get_arg("virtual", argc, argv);
	parse_rules_file(filename);

    filename = get_arg("args", argc, argv);
    parse_json_args(filename);

    filename = get_arg("outs", argc, argv);
    parse_json_outs(filename);

    filename = get_arg("basicblocks", argc, argv);
    parse_basic_block_file(filename);

	filename = get_arg("logger", argc, argv);
	load_logger_config(filename);

	filename = get_arg("monitor", argc, argv);
	runtime = filename; // Lazy Init


	qemu_plugin_unimp_export_device((void *)&importer);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
